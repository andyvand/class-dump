// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDDyldCache.h"

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

@implementation CDDyldCacheImageInfo
- (instancetype)initWithAddress:(uint64_t)address path:(NSString *)path {
    if ((self = [super init])) { _address = address; _path = path; }
    return self;
}
@end

// One subcache slice. The main cache file is also represented as one of
// these; its `data` is the file content and its mappings cover the main
// region (typically the header + a small slab).
@interface CDDyldCacheSlice : NSObject
@property (nonatomic, strong) NSData *data;
@property (nonatomic, strong) NSArray *mappings; // boxed cd_dsc_mapping_info entries
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
    // Single-file mode: only the main cache contributes mappings. _slices
    // mirrors _mappings so the lookup paths can use one code path.
    CDDyldCacheSlice *mainSlice = [CDDyldCacheSlice new];
    mainSlice.data = _data;
    mainSlice.mappings = _mappings;
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
    [self _loadSubcachesFromBasePath:path];
    return self;
}

- (void)_loadSubcachesFromBasePath:(NSString *)basePath
{
    // Apple's modern dyld_cache_header layout: subCacheArrayOffset/Count
    // live at file offsets 0x188/0x18c. Validate the values before trusting
    // them: a sensible offset is < mappingOffset (the header end) and the
    // count is bounded (we've seen up to ~13 subcaches in shipping caches).
    if ((NSUInteger)_hdr.mappingOffset < 0x190) return;
    const uint8_t *bytes = (const uint8_t *)[_data bytes];
    if ((NSUInteger)0x190 > [_data length]) return;
    uint32_t subOff = 0, subCnt = 0;
    memcpy(&subOff, bytes + 0x188, 4);
    memcpy(&subCnt, bytes + 0x18c, 4);
    if (subOff == 0 || subCnt == 0) return;
    if (subCnt > 64) return;

    // Subcache entry layout in current caches (~iOS 16 / macOS 13 onwards):
    //   uuid[16], cacheVMOffset(uint64), fileSuffix[32]  (= 56 bytes)
    // Older caches used a 24-byte entry without the file-suffix field; for
    // those we synthesise the suffix as ".N".
    const size_t kEntryNew = 16 + 8 + 32;
    const size_t kEntryOld = 16 + 8;
    size_t entrySize = kEntryNew;
    // Sanity: the new layout must fit in the file.
    if ((NSUInteger)subOff + (NSUInteger)subCnt * entrySize > [_data length]) {
        entrySize = kEntryOld;
        if ((NSUInteger)subOff + (NSUInteger)subCnt * entrySize > [_data length]) return;
    }

    NSMutableArray *slices = [NSMutableArray arrayWithArray:_slices];
    for (uint32_t i = 0; i < subCnt; i++) {
        const uint8_t *p = bytes + subOff + i * entrySize;
        NSString *suffix = nil;
        if (entrySize == kEntryNew) {
            const char *sfx = (const char *)(p + 16 + 8);
            size_t maxLen = entrySize - (16 + 8);
            size_t actual = strnlen(sfx, maxLen);
            suffix = [[NSString alloc] initWithBytes:sfx length:actual encoding:NSUTF8StringEncoding];
        } else {
            suffix = [NSString stringWithFormat:@".%u", i + 1];
        }
        if (suffix.length == 0) continue;

        NSString *subPath = [basePath stringByAppendingString:suffix];
        NSData *subData = [NSData dataWithContentsOfFile:subPath
                                                 options:NSDataReadingMappedAlways
                                                   error:NULL];
        if (subData == nil) continue;
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
        CDDyldCacheSlice *s = [CDDyldCacheSlice new];
        s.data = subData;
        s.mappings = subMappings;
        [slices addObject:s];
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
    if ([_data length] >= 0xe8) {
        uint64_t srs = 0;
        memcpy(&srs, (const uint8_t *)[_data bytes] + 0xe0, 8);
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

- (void)probePlatform
{
    // Best-effort probe: the platform field's offset has migrated across cache
    // versions. We probe a small window after the dyldBaseAddress field.
    static const NSUInteger probes[] = { 0xa8, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0 };
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
