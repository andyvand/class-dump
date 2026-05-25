// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDDyldCache.h"
#import <mach/vm_prot.h>

// Minimal subset of dyld_cache_header. The real struct (defined in
// dyld/include/mach-o/dyld_cache_format.h in Apple's open-source dyld) has
// added many fields over the years; we only read the prefix that has been
// stable since the cache format was introduced.
struct cd_dsc_header_min {
    char     magic[16];          // 0x00 e.g. "dyld_v1   arm64e\0"
    uint32_t mappingOffset;      // 0x10
    uint32_t mappingCount;       // 0x14
    uint32_t imagesOffsetOld;    // 0x18 (legacy table; 0 in modern caches)
    uint32_t imagesCountOld;     // 0x1c
    uint64_t dyldBaseAddress;    // 0x20
};

// Header field offsets that are stable across the cache versions we care
// about. Matches `struct dyld_cache_header` in Apple's dyld source.
enum {
    kDscOffLocalSymbolsOffset   = 0x48,
    kDscOffLocalSymbolsSize     = 0x50,
    kDscOffCacheType            = 0x68,
    kDscOffUUID                 = 0x58,
    kDscOffSharedRegionStart    = 0xe0,
    kDscOffMappingWithSlideOff  = 0x138,
    kDscOffMappingWithSlideCnt  = 0x13c,
    kDscOffSubCacheArrayOffset  = 0x188,
    kDscOffSubCacheArrayCount   = 0x18c,
    kDscOffSymbolFileUUID       = 0x190,
    kDscOffCacheSubType         = 0x1c8,
};

// dyld_subcache_entry uses the wider (with fileSuffix) layout when the
// header's mappingOffset extends past `cacheSubType`. Older caches (mapping
// offset <= 0x1cc) use the 24-byte `dyld_subcache_entry_v1`. We mirror this
// gating logic to stay compatible with both.
static const NSUInteger kSubcacheEntrySizeV1  = 16 + 8;        // uuid + cacheVMOffset
static const NSUInteger kSubcacheEntrySizeNew = 16 + 8 + 32;   // + fileSuffix[32]

// In modern caches (post ~macOS 12), the per-cache imagesOffset/imagesCount
// fields appear later in the header. Their absolute offset depends on the
// header version; the value is layered behind a lot of intervening fields.
// We probe a small set of known offsets and verify the result lies within
// the header (i.e. before mappingOffset).
static const NSUInteger kProbeImagesOffsets[] = {
    0x1c0, // some 12.x caches
    0x1c8, // 13.x
    0x1d0, // 14.x
    0x1d8, // 15.x+
    0x1e0,
};

struct cd_dsc_image_info {
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
};

struct cd_dsc_mapping_info {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
};

struct cd_dsc_mapping_and_slide_info {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint64_t slideInfoFileOffset;
    uint64_t slideInfoFileSize;
    uint64_t flags;
    uint32_t maxProt;
    uint32_t initProt;
};

// Flag bits — must match dyld's `enum` in dyld_cache_format.h.
enum {
    CD_DYLD_CACHE_MAPPING_AUTH_DATA       = 1u << 0,
    CD_DYLD_CACHE_MAPPING_DIRTY_DATA      = 1u << 1,
    CD_DYLD_CACHE_MAPPING_CONST_DATA      = 1u << 2,
    CD_DYLD_CACHE_MAPPING_TEXT_STUBS      = 1u << 3,
    CD_DYLD_CACHE_DYNAMIC_CONFIG_DATA     = 1u << 4,
    CD_DYLD_CACHE_READ_ONLY_DATA          = 1u << 5,
    CD_DYLD_CACHE_MAPPING_CONST_TPRO_DATA = 1u << 6,
};

// Mirror of dyld's DyldSharedCache::mappingName() — gives readable names to
// the mapping-name slot in CDDyldCacheMappingInfo. We use the same VM_PROT
// bits and DYLD_CACHE_MAPPING_* flags so the output matches what dyld
// itself prints when running on the same cache.
static NSString *CDDscMappingName(uint32_t maxProt, uint64_t flags)
{
    if (maxProt & VM_PROT_EXECUTE) {
        if (flags & CD_DYLD_CACHE_MAPPING_TEXT_STUBS) return @"__TEXT_STUBS";
        return @"__TEXT";
    }
    if (maxProt & VM_PROT_WRITE) {
        if (flags & CD_DYLD_CACHE_DYNAMIC_CONFIG_DATA)     return @"__DATA_CONFIG";
        if (flags & CD_DYLD_CACHE_MAPPING_AUTH_DATA)       return @"__AUTH";
        if (flags & CD_DYLD_CACHE_MAPPING_DIRTY_DATA)      return @"__DATA_DIRTY";
        if (flags & CD_DYLD_CACHE_MAPPING_CONST_TPRO_DATA) return @"__TPRO_CONST";
        if (flags & CD_DYLD_CACHE_MAPPING_CONST_DATA)      return @"__DATA_CONST";
        return @"__DATA";
    }
    if (maxProt & VM_PROT_READ) {
        if (flags & CD_DYLD_CACHE_READ_ONLY_DATA) return @"__READ_ONLY";
        return @"__LINKEDIT";
    }
    return @"*unknown*";
}

static NSString *CDDscUUIDString(const uint8_t uuid[16])
{
    return [NSString stringWithFormat:
            @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            uuid[0],  uuid[1],  uuid[2],  uuid[3],
            uuid[4],  uuid[5],  uuid[6],  uuid[7],
            uuid[8],  uuid[9],
            uuid[10], uuid[11],
            uuid[12], uuid[13], uuid[14], uuid[15]];
}

@implementation CDDyldCacheImageInfo
- (instancetype)initWithAddress:(uint64_t)address path:(NSString *)path {
    if ((self = [super init])) { _address = address; _path = path; }
    return self;
}
@end

@implementation CDDyldCacheMappingInfo
- (instancetype)initWithAddress:(uint64_t)address
                           size:(uint64_t)size
                     fileOffset:(uint64_t)fileOffset
                        maxProt:(uint32_t)maxProt
                       initProt:(uint32_t)initProt
                          flags:(uint64_t)flags
{
    if ((self = [super init])) {
        _address = address;
        _size = size;
        _fileOffset = fileOffset;
        _maxProt = maxProt;
        _initProt = initProt;
        _flags = flags;
        _name = CDDscMappingName(maxProt, flags);
    }
    return self;
}
@end

@implementation CDDyldCacheSubcacheInfo
- (instancetype)initWithPath:(NSString *)path
                      suffix:(NSString *)suffix
                        uuid:(NSString *)uuid
                    vmOffset:(uint64_t)vmOffset
                    fileSize:(uint64_t)fileSize
                    mappings:(NSArray<CDDyldCacheMappingInfo *> *)mappings
{
    if ((self = [super init])) {
        _path = path ?: @"";
        _suffix = suffix ?: @"";
        _uuid = uuid ?: @"";
        _vmOffset = vmOffset;
        _fileSize = fileSize;
        _mappings = [mappings copy] ?: @[];
    }
    return self;
}
@end

// One subcache slice. The main cache file is also represented as one of
// these; its `data` is the file content and its mappings cover the main
// region (typically the header + a small slab).
@interface CDDyldCacheSlice : NSObject
@property (nonatomic, strong) NSData *data;
@property (nonatomic, strong) NSArray *mappings; // boxed cd_dsc_mapping_info entries (vmaddr lookup)
@property (nonatomic, strong) CDDyldCacheSubcacheInfo *info;
@end
@implementation CDDyldCacheSlice @end

@implementation CDDyldCache
{
    NSData *_data;
    struct cd_dsc_header_min _hdr;
    NSArray<CDDyldCacheImageInfo *> *_images;
    NSArray *_mappings; // boxed cd_dsc_mapping_info entries (main cache only)
    uint32_t _platform;
    BOOL _legacy;
    NSString *_uuid;
    uint64_t _cacheType;

    // All slices (main + subcaches), each carrying its own data + mappings.
    // Lookups walk this array so addresses that resolve into a subcache file
    // (where the actual __TEXT and __DATA pages live in split caches) hit the
    // right backing store.
    NSArray<CDDyldCacheSlice *> *_slices;
}

- (instancetype)initWithData:(NSData *)data
{
    if ((self = [super init]) == nil) return nil;
    if ([data length] < sizeof(_hdr)) return nil;
    memcpy(&_hdr, [data bytes], sizeof(_hdr));
    if (strncmp(_hdr.magic, "dyld_v1", 7) != 0) return nil;
    _data = data;

    [self loadImages];
    [self loadMappings];
    [self _readMainHeaderExtras];
    // Single-file mode: only the main cache contributes mappings. _slices
    // mirrors _mappings so the lookup paths can use one code path.
    NSArray<CDDyldCacheMappingInfo *> *mainInfos = [self _mappingInfosForData:_data
                                                              mappingOffset:_hdr.mappingOffset
                                                               mappingCount:_hdr.mappingCount];
    CDDyldCacheSlice *mainSlice = [CDDyldCacheSlice new];
    mainSlice.data = _data;
    mainSlice.mappings = _mappings;
    mainSlice.info = [[CDDyldCacheSubcacheInfo alloc] initWithPath:@""
                                                            suffix:@""
                                                              uuid:_uuid ?: @""
                                                          vmOffset:0
                                                          fileSize:[_data length]
                                                          mappings:mainInfos];
    _slices = @[mainSlice];
    [self probePlatform];
    return self;
}

- (instancetype)initWithPath:(NSString *)path
{
    if (path == nil) return nil;
    NSData *mainData = [NSData dataWithContentsOfFile:path
                                              options:NSDataReadingMappedAlways
                                                error:NULL];
    if (mainData == nil) return nil;
    self = [self initWithData:mainData];
    if (self == nil) return nil;
    // Replace the placeholder main slice with one that carries the resolved
    // path so --dsc-info can show the on-disk file.
    if (_slices.count >= 1) {
        CDDyldCacheSlice *main = _slices[0];
        main.info = [[CDDyldCacheSubcacheInfo alloc] initWithPath:path
                                                           suffix:@""
                                                             uuid:_uuid ?: @""
                                                         vmOffset:0
                                                         fileSize:[_data length]
                                                         mappings:main.info.mappings];
    }
    [self _loadSubcachesFromBasePath:path];
    return self;
}

- (void)_readMainHeaderExtras
{
    const uint8_t *bytes = (const uint8_t *)[_data bytes];
    NSUInteger len = [_data length];
    if (len >= kDscOffCacheType + 8) {
        memcpy(&_cacheType, bytes + kDscOffCacheType, 8);
    }
    if (len >= kDscOffUUID + 16) {
        _uuid = CDDscUUIDString(bytes + kDscOffUUID);
    } else {
        _uuid = @"";
    }
}

- (void)_loadSubcachesFromBasePath:(NSString *)basePath
{
    // Apple's modern dyld_cache_header layout: subCacheArrayOffset/Count
    // live at file offsets 0x188/0x18c. Validate the values before trusting
    // them: a sensible offset is < mappingOffset (the header end) and the
    // count is bounded (we've seen up to ~13 subcaches in shipping caches).
    if ((NSUInteger)_hdr.mappingOffset <= kDscOffSubCacheArrayCount + 4) return;
    const uint8_t *bytes = (const uint8_t *)[_data bytes];
    NSUInteger fileLen = [_data length];
    if (fileLen < kDscOffSubCacheArrayCount + 4) return;
    uint32_t subOff = 0, subCnt = 0;
    memcpy(&subOff, bytes + kDscOffSubCacheArrayOffset, 4);
    memcpy(&subCnt, bytes + kDscOffSubCacheArrayCount, 4);
    if (subOff == 0 || subCnt == 0) return;
    if (subCnt > 64) return;

    // Pick the entry layout the same way dyld does: if `mappingOffset`
    // extends past `cacheSubType` (the field that was added together with
    // the 32-byte fileSuffix), this is a v2 entry. Otherwise v1.
    NSUInteger entrySize = (_hdr.mappingOffset > kDscOffCacheSubType + 4)
        ? kSubcacheEntrySizeNew : kSubcacheEntrySizeV1;
    if ((NSUInteger)subOff + (NSUInteger)subCnt * entrySize > fileLen) {
        // Fall back to the other layout if the table doesn't fit. Some
        // intermediate cache revisions briefly mixed these up.
        entrySize = (entrySize == kSubcacheEntrySizeNew) ? kSubcacheEntrySizeV1 : kSubcacheEntrySizeNew;
        if ((NSUInteger)subOff + (NSUInteger)subCnt * entrySize > fileLen) return;
    }

    // For universal caches (cacheType == 2), the .development variant uses
    // a `<base>.development` name; subcache siblings are named off the
    // canonical base — i.e. strip the trailing ".development" when building
    // subcache paths.
    NSString *suffixBase = basePath;
    if (_cacheType == 2 /* kDyldSharedCacheTypeUniversal */) {
        if ([suffixBase hasSuffix:@".development"]) {
            suffixBase = [suffixBase substringToIndex:[suffixBase length] - [@".development" length]];
        }
    }

    NSMutableArray *slices = [NSMutableArray arrayWithArray:_slices];
    for (uint32_t i = 0; i < subCnt; i++) {
        const uint8_t *p = bytes + subOff + i * entrySize;
        uint8_t subUUID[16] = {0};
        memcpy(subUUID, p, 16);
        uint64_t vmOff = 0;
        memcpy(&vmOff, p + 16, 8);
        NSString *suffix = nil;
        if (entrySize == kSubcacheEntrySizeNew) {
            const char *sfx = (const char *)(p + 16 + 8);
            size_t maxLen = entrySize - (16 + 8);
            size_t actual = strnlen(sfx, maxLen);
            suffix = [[NSString alloc] initWithBytes:sfx length:actual encoding:NSUTF8StringEncoding];
            if (suffix.length == 0) {
                // Older cache revision that uses v2 entries with an empty
                // suffix string: fall back to ".N" naming.
                suffix = [NSString stringWithFormat:@".%u", i + 1];
            }
        } else {
            suffix = [NSString stringWithFormat:@".%u", i + 1];
        }

        NSString *subPath = [suffixBase stringByAppendingString:suffix];
        NSData *subData = [NSData dataWithContentsOfFile:subPath
                                                 options:NSDataReadingMappedAlways
                                                   error:NULL];
        if (subData == nil) {
            fprintf(stderr,
                    "class-dump: warning: subcache %u (%s) not readable, skipping\n",
                    i + 1, [subPath UTF8String]);
            continue;
        }
        // Each subcache file is itself a "mini" dyld cache: same magic, its
        // own mappingOffset/mappingCount. Parse them and add as a slice.
        if ([subData length] < sizeof(struct cd_dsc_header_min)) continue;
        struct cd_dsc_header_min subHdr;
        memcpy(&subHdr, [subData bytes], sizeof(subHdr));
        if (strncmp(subHdr.magic, "dyld_v1", 7) != 0) continue;
        NSArray *subMappings = [self _parseMappingsFromData:subData
                                              mappingOffset:subHdr.mappingOffset
                                               mappingCount:subHdr.mappingCount];
        if (subMappings.count == 0) continue;

        // Optional sanity check: subcache UUIDs should match the entry's
        // expected UUID. Warn on mismatch — this catches stale subcaches
        // left over from a partial OS update.
        NSString *subUUIDString = @"";
        if ([subData length] >= kDscOffUUID + 16) {
            uint8_t fileUUID[16] = {0};
            memcpy(fileUUID, (const uint8_t *)[subData bytes] + kDscOffUUID, 16);
            subUUIDString = CDDscUUIDString(fileUUID);
            if (memcmp(fileUUID, subUUID, 16) != 0) {
                fprintf(stderr,
                        "class-dump: warning: subcache %s UUID mismatch (expected %s, got %s)\n",
                        [suffix UTF8String],
                        [CDDscUUIDString(subUUID) UTF8String],
                        [subUUIDString UTF8String]);
            }
        }

        NSArray<CDDyldCacheMappingInfo *> *infos =
            [self _mappingInfosForData:subData
                         mappingOffset:subHdr.mappingOffset
                          mappingCount:subHdr.mappingCount];

        CDDyldCacheSlice *s = [CDDyldCacheSlice new];
        s.data = subData;
        s.mappings = subMappings;
        s.info = [[CDDyldCacheSubcacheInfo alloc] initWithPath:subPath
                                                        suffix:suffix
                                                          uuid:subUUIDString
                                                      vmOffset:vmOff
                                                      fileSize:[subData length]
                                                      mappings:infos];
        [slices addObject:s];
    }

    // .symbols sidecar: when the main header's `symbolFileUUID` is non-zero
    // there's a separate `<base>.symbols` file containing the unmapped local
    // symbol nlist table. We don't *use* it for class-dump output, but we
    // attach it as a slice when present so callers can still see it via
    // -subcaches (and so any cached path walker that expects it doesn't
    // print a misleading "missing" warning). The file has no vm mappings
    // that resolve into the rest of the cache, so it doesn't affect the
    // lookup hot path.
    if (fileLen >= kDscOffSymbolFileUUID + 16) {
        uint8_t symUUID[16] = {0};
        memcpy(symUUID, bytes + kDscOffSymbolFileUUID, 16);
        BOOL hasSymbols = NO;
        for (int i = 0; i < 16; i++) if (symUUID[i]) { hasSymbols = YES; break; }
        if (hasSymbols) {
            NSString *symPath = [suffixBase stringByAppendingString:@".symbols"];
            NSData *symData = [NSData dataWithContentsOfFile:symPath
                                                     options:NSDataReadingMappedAlways
                                                       error:NULL];
            if (symData != nil) {
                CDDyldCacheSlice *s = [CDDyldCacheSlice new];
                s.data = symData;
                s.mappings = @[];
                s.info = [[CDDyldCacheSubcacheInfo alloc]
                          initWithPath:symPath
                                suffix:@".symbols"
                                  uuid:CDDscUUIDString(symUUID)
                              vmOffset:0
                              fileSize:[symData length]
                              mappings:@[]];
                [slices addObject:s];
            }
        }
    }

    _slices = [slices copy];
}

- (NSArray *)_parseMappingsFromData:(NSData *)data
                      mappingOffset:(uint32_t)mappingOffset
                       mappingCount:(uint32_t)mappingCount
{
    NSMutableArray *m = [NSMutableArray array];
    NSUInteger entrySize = sizeof(struct cd_dsc_mapping_info);
    if ((NSUInteger)mappingOffset + (NSUInteger)mappingCount * entrySize > [data length]) {
        return @[];
    }
    const uint8_t *base = (const uint8_t *)[data bytes];
    for (uint32_t i = 0; i < mappingCount; i++) {
        NSData *entry = [[NSData alloc] initWithBytes:base + mappingOffset + i * entrySize length:entrySize];
        [m addObject:entry];
    }
    return [m copy];
}

// Produce CDDyldCacheMappingInfo[] for a slice. When the cache exposes the
// richer `mappingWithSlideOffset` table (modern caches), parse those so the
// `flags` field can label __LINKEDIT vs __READ_ONLY, __DATA_CONST, etc.
// Otherwise fall back to the legacy `mapping_info` layout with flags=0.
- (NSArray<CDDyldCacheMappingInfo *> *)_mappingInfosForData:(NSData *)data
                                              mappingOffset:(uint32_t)mappingOffset
                                               mappingCount:(uint32_t)mappingCount
{
    if (data == nil || mappingCount == 0) return @[];

    const uint8_t *bytes = (const uint8_t *)[data bytes];
    NSUInteger len = [data length];

    // Look up the cache's own mappingWithSlideOffset (in this slice's
    // header). Subcaches duplicate the same prefix layout as the main
    // cache, so the field is at the same fixed offset.
    BOOL useSlideTable = NO;
    uint32_t slideOff = 0, slideCnt = 0;
    if (len >= kDscOffMappingWithSlideCnt + 4 && mappingOffset > kDscOffMappingWithSlideOff) {
        memcpy(&slideOff, bytes + kDscOffMappingWithSlideOff, 4);
        memcpy(&slideCnt, bytes + kDscOffMappingWithSlideCnt, 4);
        if (slideOff != 0 && slideCnt == mappingCount &&
            (NSUInteger)slideOff + (NSUInteger)slideCnt * sizeof(struct cd_dsc_mapping_and_slide_info) <= len) {
            useSlideTable = YES;
        }
    }

    NSMutableArray<CDDyldCacheMappingInfo *> *out = [NSMutableArray arrayWithCapacity:mappingCount];
    if (useSlideTable) {
        for (uint32_t i = 0; i < slideCnt; i++) {
            struct cd_dsc_mapping_and_slide_info mi;
            memcpy(&mi, bytes + slideOff + i * sizeof(mi), sizeof(mi));
            [out addObject:[[CDDyldCacheMappingInfo alloc]
                            initWithAddress:mi.address
                                       size:mi.size
                                 fileOffset:mi.fileOffset
                                    maxProt:mi.maxProt
                                   initProt:mi.initProt
                                      flags:mi.flags]];
        }
    } else {
        if ((NSUInteger)mappingOffset + (NSUInteger)mappingCount * sizeof(struct cd_dsc_mapping_info) > len) {
            return @[];
        }
        for (uint32_t i = 0; i < mappingCount; i++) {
            struct cd_dsc_mapping_info mi;
            memcpy(&mi, bytes + mappingOffset + i * sizeof(mi), sizeof(mi));
            [out addObject:[[CDDyldCacheMappingInfo alloc]
                            initWithAddress:mi.address
                                       size:mi.size
                                 fileOffset:mi.fileOffset
                                    maxProt:mi.maxProt
                                   initProt:mi.initProt
                                      flags:0]];
        }
    }
    return [out copy];
}

- (void)loadMappings;
{
    _mappings = [self _parseMappingsFromData:_data
                               mappingOffset:_hdr.mappingOffset
                                mappingCount:_hdr.mappingCount];
}

- (BOOL)_fileOffsetForVMAddr:(uint64_t)vmAddr outFileOff:(uint64_t *)outOff outRemaining:(uint64_t *)outRem;
{
    // Single-cache path (back-compat): only the main file's mappings.
    for (NSData *e in _mappings) {
        struct cd_dsc_mapping_info mi;
        memcpy(&mi, [e bytes], sizeof(mi));
        if (vmAddr >= mi.address && vmAddr < mi.address + mi.size) {
            uint64_t delta = vmAddr - mi.address;
            if (outOff) *outOff = mi.fileOffset + delta;
            if (outRem) *outRem = mi.size - delta;
            return YES;
        }
    }
    return NO;
}

// Locate `vmAddr` in any slice and return the matching data + file offset.
- (BOOL)_locate:(uint64_t)vmAddr outData:(NSData **)outData outFileOff:(uint64_t *)outOff outRemaining:(uint64_t *)outRem;
{
    for (CDDyldCacheSlice *s in _slices) {
        for (NSData *e in s.mappings) {
            struct cd_dsc_mapping_info mi;
            memcpy(&mi, [e bytes], sizeof(mi));
            if (vmAddr >= mi.address && vmAddr < mi.address + mi.size) {
                uint64_t delta = vmAddr - mi.address;
                if (outData) *outData = s.data;
                if (outOff)  *outOff  = mi.fileOffset + delta;
                if (outRem)  *outRem  = mi.size - delta;
                return YES;
            }
        }
    }
    return NO;
}

- (NSString *)stringAtAddress:(uint64_t)address;
{
    NSData *sliceData = nil;
    uint64_t off = 0, rem = 0;
    if (![self _locate:address outData:&sliceData outFileOff:&off outRemaining:&rem]) return nil;
    if (off >= [sliceData length]) return nil;
    NSUInteger maxLen = (NSUInteger)MIN(rem, (uint64_t)([sliceData length] - off));
    const char *p = (const char *)[sliceData bytes] + off;
    size_t n = strnlen(p, maxLen);
    return [[NSString alloc] initWithBytes:p length:n encoding:NSUTF8StringEncoding];
}

- (NSData *)bytesAtAddress:(uint64_t)address length:(NSUInteger)length;
{
    NSData *sliceData = nil;
    uint64_t off = 0, rem = 0;
    if (![self _locate:address outData:&sliceData outFileOff:&off outRemaining:&rem]) return nil;
    NSUInteger maxLen = (NSUInteger)MIN((uint64_t)length, MIN(rem, (uint64_t)([sliceData length] - off)));
    if (maxLen == 0) return nil;
    return [NSData dataWithBytes:(const uint8_t *)[sliceData bytes] + off length:maxLen];
}

- (BOOL)readPointerAtAddress:(uint64_t)address into:(uint64_t *)outValue;
{
    NSData *sliceData = nil;
    uint64_t off = 0, rem = 0;
    if (![self _locate:address outData:&sliceData outFileOff:&off outRemaining:&rem]) return NO;
    if (rem < 8 || off + 8 > [sliceData length]) return NO;
    uint64_t v;
    memcpy(&v, (const uint8_t *)[sliceData bytes] + off, 8);
    if (outValue) *outValue = v;
    return YES;
}

- (BOOL)containsAddress:(uint64_t)address;
{
    return [self _locate:address outData:NULL outFileOff:NULL outRemaining:NULL];
}

- (uint64_t)cacheBaseAddress;
{
    // sharedRegionStart from the main cache header. This is the value that
    // DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE runtimeOffsets are computed
    // against, and it can be lower than any one mapping's vmaddr if the
    // header itself isn't mapped to vmaddr 0 of the region — so reading it
    // from the header is more reliable than taking the min of mappings.
    if ([_data length] >= kDscOffSharedRegionStart + 8) {
        uint64_t srs = 0;
        memcpy(&srs, (const uint8_t *)[_data bytes] + kDscOffSharedRegionStart, 8);
        if (srs != 0) return srs;
    }
    uint64_t base = UINT64_MAX;
    for (CDDyldCacheSlice *s in _slices) {
        for (NSData *e in s.mappings) {
            struct cd_dsc_mapping_info mi;
            memcpy(&mi, [e bytes], sizeof(mi));
            if (mi.address < base) base = mi.address;
        }
    }
    return base == UINT64_MAX ? 0 : base;
}

- (BOOL)readResolvedPointerAtAddress:(uint64_t)address into:(uint64_t *)outValue;
{
    uint64_t raw = 0;
    if (![self readPointerAtAddress:address into:&raw]) return NO;
    if (raw == 0) {
        if (outValue) *outValue = 0;
        return YES;
    }
    uint64_t base = [self cacheBaseAddress];
    // If the top 16 bits are clear, the slot is either already-applied (rare
    // when reading a cache file from disk, but possible for caches that have
    // been pre-processed) or simply a small constant. Decide by checking
    // whether the raw value already lies inside a cache mapping.
    if ((raw >> 48) == 0 && [self containsAddress:raw]) {
        if (outValue) *outValue = raw;
        return YES;
    }
    // Decode as DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE (format 13). For both the
    // auth and non-auth shapes, bits 0..33 hold runtimeOffset. Other bits
    // (high8 / diversity / addrDiv / keyIsData / next / auth) are runtime
    // hints we don't need to follow the pointer.
    uint64_t target = base + (raw & 0x3FFFFFFFFULL);
    if (![self containsAddress:target]) return NO;
    if (outValue) *outValue = target;
    return YES;
}

- (NSString *)magic
{
    char buf[17] = {0};
    memcpy(buf, _hdr.magic, 16);
    return [NSString stringWithUTF8String:buf];
}

- (uint32_t)mappingCount  { return _hdr.mappingCount; }
- (uint32_t)mappingOffset { return _hdr.mappingOffset; }
- (BOOL)usesLegacyImageTable { return _legacy; }
- (NSArray<CDDyldCacheImageInfo *> *)images { return _images ?: @[]; }
- (uint32_t)platform { return _platform; }
- (NSString *)uuid { return _uuid ?: @""; }
- (uint64_t)cacheType { return _cacheType; }

- (NSArray<CDDyldCacheSubcacheInfo *> *)subcaches
{
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:_slices.count];
    for (CDDyldCacheSlice *s in _slices) {
        if (s.info) [out addObject:s.info];
    }
    return [out copy];
}

- (void)loadImages
{
    NSMutableArray *imgs = [NSMutableArray array];
    uint32_t imagesOffset = 0;
    uint32_t imagesCount = 0;

    if (_hdr.imagesOffsetOld != 0 && _hdr.imagesCountOld != 0) {
        imagesOffset = _hdr.imagesOffsetOld;
        imagesCount = _hdr.imagesCountOld;
        _legacy = YES;
    } else {
        for (size_t i = 0; i < sizeof(kProbeImagesOffsets)/sizeof(kProbeImagesOffsets[0]); i++) {
            NSUInteger probe = kProbeImagesOffsets[i];
            if (probe + 8 > _hdr.mappingOffset) continue; // probe must be inside the header
            if (probe + 8 > [_data length]) continue;
            uint32_t off, cnt;
            memcpy(&off, (const uint8_t *)[_data bytes] + probe,     4);
            memcpy(&cnt, (const uint8_t *)[_data bytes] + probe + 4, 4);
            if (off > _hdr.mappingOffset && cnt > 0 && cnt < 0x10000 &&
                (NSUInteger)off + (NSUInteger)cnt * sizeof(struct cd_dsc_image_info) <= [_data length]) {
                imagesOffset = off;
                imagesCount = cnt;
                break;
            }
        }
    }

    if (imagesOffset == 0 || imagesCount == 0) {
        _images = @[];
        return;
    }

    NSUInteger entrySize = sizeof(struct cd_dsc_image_info);
    if ((NSUInteger)imagesOffset + (NSUInteger)imagesCount * entrySize > [_data length]) {
        _images = @[];
        return;
    }

    const uint8_t *base = (const uint8_t *)[_data bytes];
    for (uint32_t i = 0; i < imagesCount; i++) {
        struct cd_dsc_image_info ii;
        memcpy(&ii, base + imagesOffset + i * entrySize, entrySize);
        const char *path = (const char *)(base + ii.pathFileOffset);
        if ((NSUInteger)ii.pathFileOffset >= [_data length]) continue;
        size_t maxLen = [_data length] - ii.pathFileOffset;
        size_t actual = strnlen(path, maxLen);
        NSString *s = [[NSString alloc] initWithBytes:path length:actual encoding:NSUTF8StringEncoding];
        [imgs addObject:[[CDDyldCacheImageInfo alloc] initWithAddress:ii.address path:s ?: @""]];
    }

    _images = [imgs copy];
}

// MARK: - Unmapped local symbols
//
// Modern caches keep the local-symbol nlist+strings table out of the mapped
// pages (so they don't bloat the in-memory shared region) and stash it in a
// sibling `<cache>.symbols` file. Legacy caches embedded the same data inside
// the main cache file. dsc_extractor strips most of these out of the
// extracted dylib's LC_SYMTAB, so for class-dump we need to crack the table
// ourselves whenever we want to label every routine.

// Pick the slice that backs the unmapped local symbols. Returns the
// .symbols sidecar for modern caches, the main slice for legacy caches,
// or nil if no slice carries a non-zero `localSymbolsOffset` header field.
- (CDDyldCacheSlice *)_sliceHoldingLocalSymbols
{
    for (CDDyldCacheSlice *s in _slices) {
        if (s.info && [s.info.suffix isEqualToString:@".symbols"]) return s;
    }
    // Fallback: legacy single-file caches keep the locals inside the main file.
    if (_slices.count > 0) return _slices[0];
    return nil;
}

// Read a uint64_t from `data` at `offset`. Returns 0 on out-of-bounds.
static uint64_t CDReadU64(NSData *data, NSUInteger offset)
{
    if (offset + 8 > [data length]) return 0;
    uint64_t v = 0;
    memcpy(&v, (const uint8_t *)[data bytes] + offset, 8);
    return v;
}

- (NSDictionary<NSNumber *, NSString *> *)localSymbolsForImageAtAddress:(uint64_t)imageUnslidVMAddr
{
    CDDyldCacheSlice *symSlice = [self _sliceHoldingLocalSymbols];
    if (symSlice == nil) return nil;
    NSData *data = symSlice.data;
    if (data == nil) return nil;

    uint64_t locOff  = CDReadU64(data, kDscOffLocalSymbolsOffset);
    uint64_t locSize = CDReadU64(data, kDscOffLocalSymbolsSize);
    if (locOff == 0 || locSize == 0) return nil;
    if (locOff + locSize > [data length]) return nil;

    // dyld_cache_local_symbols_info header at `locOff`.
    if (locOff + 24 > [data length]) return nil;
    const uint8_t *info = (const uint8_t *)[data bytes] + locOff;
    uint32_t nlistOffset   = 0, nlistCount   = 0;
    uint32_t stringsOffset = 0, stringsSize  = 0;
    uint32_t entriesOffset = 0, entriesCount = 0;
    memcpy(&nlistOffset,   info +  0, 4);
    memcpy(&nlistCount,    info +  4, 4);
    memcpy(&stringsOffset, info +  8, 4);
    memcpy(&stringsSize,   info + 12, 4);
    memcpy(&entriesOffset, info + 16, 4);
    memcpy(&entriesCount,  info + 20, 4);

    // The offsets inside the info header are relative to the info header
    // itself, so anchor against `info` rather than the slice base.
    if ((NSUInteger)nlistOffset + (NSUInteger)nlistCount * 16 > locSize) return nil;
    if ((NSUInteger)stringsOffset + (NSUInteger)stringsSize > locSize) return nil;

    // Layout test: modern caches (with symbolFileUUID in the header) use the
    // 16-byte `dyld_cache_local_symbols_entry_64`; legacy caches use the
    // 12-byte `dyld_cache_local_symbols_entry`. The test matches dyld's
    // `forEachLocalSymbolEntry` gate.
    BOOL modern = (_hdr.mappingOffset >= kDscOffSymbolFileUUID);
    NSUInteger entrySize = modern ? 16 : 12;
    if ((NSUInteger)entriesOffset + (NSUInteger)entriesCount * entrySize > locSize) return nil;

    uint64_t cacheBase = [self cacheBaseAddress];
    if (cacheBase == 0) return nil;
    uint64_t targetOffset = imageUnslidVMAddr - cacheBase; // VM offset from cache base

    // Find the entry covering this image.
    uint32_t startIdx = 0, count = 0;
    BOOL found = NO;
    for (uint32_t i = 0; i < entriesCount; i++) {
        const uint8_t *eBase = info + entriesOffset + i * entrySize;
        uint64_t dylibOff = 0;
        uint32_t nStart = 0, nCount = 0;
        if (modern) {
            memcpy(&dylibOff, eBase + 0, 8);
            memcpy(&nStart,   eBase + 8, 4);
            memcpy(&nCount,   eBase + 12, 4);
        } else {
            uint32_t dylibOff32 = 0;
            memcpy(&dylibOff32, eBase + 0, 4);
            memcpy(&nStart,     eBase + 4, 4);
            memcpy(&nCount,     eBase + 8, 4);
            dylibOff = dylibOff32;
        }
        if (dylibOff == targetOffset) {
            startIdx = nStart;
            count = nCount;
            found = YES;
            break;
        }
    }
    if (!found || count == 0) return nil;

    // Walk the nlist_64 slab for this image. We assume nlist_64 (16 bytes)
    // because every shipping macOS / iOS cache for the last several years
    // is 64-bit; 32-bit caches don't run dsc-class-dump in practice.
    NSMutableDictionary<NSNumber *, NSString *> *out = [NSMutableDictionary dictionary];
    if ((NSUInteger)startIdx + (NSUInteger)count > nlistCount) return nil;

    const uint8_t *nlistBase = info + nlistOffset + (NSUInteger)startIdx * 16;
    const uint8_t *strBase   = info + stringsOffset;
    NSUInteger strMax = stringsSize;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = nlistBase + (NSUInteger)i * 16;
        uint32_t strx;   memcpy(&strx,   e + 0,  4);
        uint8_t  ntype  = e[4];
        // uint8_t nsect = e[5];  uint16_t ndesc = read16(e+6);
        uint64_t value;  memcpy(&value,  e + 8,  8);
        if (value == 0) continue;
        if (strx >= strMax) continue;

        // Skip stab/debug records we don't care about (no useful name for a
        // function start). N_STAB (0xe0) bits being set means it's a debug
        // symbol; allow N_FUN (0x24) entries because dsc-builder sometimes
        // emits N_FUN locals.
        BOOL isStab = (ntype & 0xe0) != 0;
        BOOL isFun  = (ntype == 0x24);
        if (isStab && !isFun) continue;

        const char *cstr = (const char *)(strBase + strx);
        size_t maxLen = strMax - strx;
        size_t actual = strnlen(cstr, maxLen);
        if (actual == 0) continue;
        NSString *name = [[NSString alloc] initWithBytes:cstr length:actual encoding:NSUTF8StringEncoding];
        if (name == nil) continue;

        NSNumber *key = @(value);
        // Earlier symbols win (dyld writes globals before private locals).
        if (out[key] == nil) out[key] = name;
    }

    return out.count > 0 ? [out copy] : nil;
}

- (void)probePlatform
{
    // Best-effort probe: the platform field's offset has migrated across cache
    // versions. We probe a small window after the dyldBaseAddress field.
    static const NSUInteger probes[] = { 0xa8, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0, 0xd8 };
    for (size_t i = 0; i < sizeof(probes)/sizeof(probes[0]); i++) {
        NSUInteger p = probes[i];
        if (p + 4 > [_data length]) continue;
        uint32_t v;
        memcpy(&v, (const uint8_t *)[_data bytes] + p, 4);
        if (v >= 1 && v <= 24) {
            _platform = v;
            return;
        }
    }
}

@end
