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

@implementation CDDyldCache
{
    NSData *_data;
    struct cd_dsc_header_min _hdr;
    NSArray<CDDyldCacheImageInfo *> *_images;
    NSArray *_mappings; // boxed cd_dsc_mapping_info entries
    uint32_t _platform;
    BOOL _legacy;
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
    [self probePlatform];
    return self;
}

- (void)loadMappings;
{
    NSMutableArray *m = [NSMutableArray array];
    NSUInteger entrySize = sizeof(struct cd_dsc_mapping_info);
    if ((NSUInteger)_hdr.mappingOffset + (NSUInteger)_hdr.mappingCount * entrySize > [_data length]) {
        _mappings = @[];
        return;
    }
    const uint8_t *base = (const uint8_t *)[_data bytes];
    for (uint32_t i = 0; i < _hdr.mappingCount; i++) {
        NSData *entry = [[NSData alloc] initWithBytes:base + _hdr.mappingOffset + i * entrySize length:entrySize];
        [m addObject:entry];
    }
    _mappings = [m copy];
}

- (BOOL)_fileOffsetForVMAddr:(uint64_t)vmAddr outFileOff:(uint64_t *)outOff outRemaining:(uint64_t *)outRem;
{
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

- (NSString *)stringAtAddress:(uint64_t)address;
{
    uint64_t off = 0, rem = 0;
    if (![self _fileOffsetForVMAddr:address outFileOff:&off outRemaining:&rem]) return nil;
    if (off >= [_data length]) return nil;
    NSUInteger maxLen = (NSUInteger)MIN(rem, (uint64_t)([_data length] - off));
    const char *p = (const char *)[_data bytes] + off;
    size_t n = strnlen(p, maxLen);
    return [[NSString alloc] initWithBytes:p length:n encoding:NSUTF8StringEncoding];
}

- (BOOL)readPointerAtAddress:(uint64_t)address into:(uint64_t *)outValue;
{
    uint64_t off = 0, rem = 0;
    if (![self _fileOffsetForVMAddr:address outFileOff:&off outRemaining:&rem]) return NO;
    if (rem < 8 || off + 8 > [_data length]) return NO;
    uint64_t v;
    memcpy(&v, (const uint8_t *)[_data bytes] + off, 8);
    if (outValue) *outValue = v;
    return YES;
}

- (BOOL)containsAddress:(uint64_t)address;
{
    uint64_t off = 0, rem = 0;
    return [self _fileOffsetForVMAddr:address outFileOff:&off outRemaining:&rem];
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
