// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCChainedFixups.h"

#import "CDMachOFile.h"
#import "CDLCSegment.h"

#import <mach-o/fixup-chains.h>

static NSString *PointerFormatName(uint16_t fmt)
{
    switch (fmt) {
        case DYLD_CHAINED_PTR_ARM64E:                          return @"ARM64E";
        case DYLD_CHAINED_PTR_64:                              return @"64";
        case DYLD_CHAINED_PTR_32:                              return @"32";
        case DYLD_CHAINED_PTR_32_CACHE:                        return @"32_CACHE";
        case DYLD_CHAINED_PTR_32_FIRMWARE:                     return @"32_FIRMWARE";
        case DYLD_CHAINED_PTR_64_OFFSET:                       return @"64_OFFSET";
        case DYLD_CHAINED_PTR_ARM64E_KERNEL:                   return @"ARM64E_KERNEL";
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE:                 return @"64_KERNEL_CACHE";
        case DYLD_CHAINED_PTR_ARM64E_USERLAND:                 return @"ARM64E_USERLAND";
        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:                 return @"ARM64E_FIRMWARE";
        case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:             return @"X86_64_KERNEL_CACHE";
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24:               return @"ARM64E_USERLAND24";
#ifdef DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
        case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:             return @"ARM64E_SHARED_CACHE";
#endif
#ifdef DYLD_CHAINED_PTR_ARM64E_SEGMENTED
        case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:                return @"ARM64E_SEGMENTED";
#endif
#ifdef DYLD_CHAINED_PTR_ARM64E_AUTH_SEGMENTED
        case DYLD_CHAINED_PTR_ARM64E_AUTH_SEGMENTED:           return @"ARM64E_AUTH_SEGMENTED";
#endif
        default: return [NSString stringWithFormat:@"unknown(0x%x)", fmt];
    }
}

static NSString *ImportsFormatName(uint32_t fmt)
{
    switch (fmt) {
        case DYLD_CHAINED_IMPORT:           return @"IMPORT";
        case DYLD_CHAINED_IMPORT_ADDEND:    return @"IMPORT_ADDEND";
        case DYLD_CHAINED_IMPORT_ADDEND64:  return @"IMPORT_ADDEND64";
        default: return [NSString stringWithFormat:@"unknown(%u)", fmt];
    }
}

@implementation CDLCChainedFixups
{
    NSArray<NSString *> *_importNames;
    BOOL _parsed;
    struct dyld_chained_fixups_header _header;
    // VM address (uint64_t boxed as NSNumber) → import symbol name (NSString).
    // Populated lazily during -applyToMutableData:imageBase:.
    NSMutableDictionary<NSNumber *, NSString *> *_bindNameByAddress;
}

- (uint32_t)fixupsVersion { [self ensureParsed]; return _header.fixups_version; }
- (uint32_t)startsOffset  { [self ensureParsed]; return _header.starts_offset; }
- (uint32_t)importsOffset { [self ensureParsed]; return _header.imports_offset; }
- (uint32_t)symbolsOffset { [self ensureParsed]; return _header.symbols_offset; }
- (uint32_t)importsCount  { [self ensureParsed]; return _header.imports_count; }
- (uint32_t)importsFormat { [self ensureParsed]; return _header.imports_format; }
- (uint32_t)symbolsFormat { [self ensureParsed]; return _header.symbols_format; }

- (NSArray<NSString *> *)importNames { [self ensureParsed]; return _importNames; }

- (void)ensureParsed
{
    if (_parsed) return;
    _parsed = YES;

    NSData *blob = [self linkeditData];
    const uint8_t *base = (const uint8_t *)[blob bytes];
    NSUInteger total = [blob length];
    if (total < sizeof(_header)) return;

    memcpy(&_header, base, sizeof(_header));

    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:_header.imports_count];

    if (_header.imports_offset == 0 || _header.symbols_offset == 0) {
        _importNames = [names copy];
        return;
    }

    const char *symbols = (const char *)(base + _header.symbols_offset);
    const uint8_t *importsBase = base + _header.imports_offset;

    NSUInteger entrySize = 0;
    switch (_header.imports_format) {
        case DYLD_CHAINED_IMPORT:          entrySize = sizeof(struct dyld_chained_import); break;
        case DYLD_CHAINED_IMPORT_ADDEND:   entrySize = sizeof(struct dyld_chained_import_addend); break;
        case DYLD_CHAINED_IMPORT_ADDEND64: entrySize = sizeof(struct dyld_chained_import_addend64); break;
        default:                           _importNames = [names copy]; return;
    }

    for (uint32_t i = 0; i < _header.imports_count; i++) {
        const uint8_t *p = importsBase + i * entrySize;
        if (p + entrySize > base + total) break;

        uint32_t nameOffset = 0;
        if (_header.imports_format == DYLD_CHAINED_IMPORT) {
            struct dyld_chained_import e;
            memcpy(&e, p, sizeof(e));
            nameOffset = e.name_offset;
        } else if (_header.imports_format == DYLD_CHAINED_IMPORT_ADDEND) {
            struct dyld_chained_import_addend e;
            memcpy(&e, p, sizeof(e));
            nameOffset = e.name_offset;
        } else {
            struct dyld_chained_import_addend64 e;
            memcpy(&e, p, sizeof(e));
            nameOffset = e.name_offset;
        }

        const char *s = symbols + nameOffset;
        if ((const uint8_t *)s >= base + total) {
            [names addObject:@""];
        } else {
            [names addObject:[NSString stringWithUTF8String:s] ?: @""];
        }
    }

    _importNames = [names copy];
}

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];

    [self ensureParsed];

    NSData *blob = [self linkeditData];
    if ([blob length] < sizeof(_header)) {
        [resultString appendString:@"  (chained fixups payload too small)\n"];
        return;
    }

    [resultString appendFormat:@"   fixups_version %u\n",  _header.fixups_version];
    [resultString appendFormat:@"     starts_offset %u\n", _header.starts_offset];
    [resultString appendFormat:@"    imports_offset %u\n", _header.imports_offset];
    [resultString appendFormat:@"    symbols_offset %u\n", _header.symbols_offset];
    [resultString appendFormat:@"     imports_count %u\n", _header.imports_count];
    [resultString appendFormat:@"    imports_format %u (%@)\n", _header.imports_format, ImportsFormatName(_header.imports_format)];
    [resultString appendFormat:@"    symbols_format %u (%@)\n", _header.symbols_format, _header.symbols_format == 0 ? @"uncompressed" : @"zlib"];

    if (!isVerbose) return;

    const uint8_t *base = (const uint8_t *)[blob bytes];
    NSUInteger total = [blob length];

    if (_header.starts_offset > 0 && _header.starts_offset + sizeof(struct dyld_chained_starts_in_image) <= total) {
        const struct dyld_chained_starts_in_image *image = (const struct dyld_chained_starts_in_image *)(base + _header.starts_offset);
        [resultString appendFormat:@"\n  starts_in_image:\n    seg_count %u\n", image->seg_count];

        for (uint32_t s = 0; s < image->seg_count; s++) {
            uint32_t segInfoOffset = image->seg_info_offset[s];
            if (segInfoOffset == 0) {
                [resultString appendFormat:@"    seg %u: (no fixups)\n", s];
                continue;
            }
            NSUInteger segOff = (NSUInteger)_header.starts_offset + segInfoOffset;
            if (segOff + sizeof(struct dyld_chained_starts_in_segment) > total) {
                [resultString appendFormat:@"    seg %u: (out of bounds)\n", s];
                continue;
            }
            const struct dyld_chained_starts_in_segment *seg = (const struct dyld_chained_starts_in_segment *)(base + segOff);
            [resultString appendFormat:@"    seg %u:\n", s];
            [resultString appendFormat:@"      size %u  page_size 0x%x\n", seg->size, seg->page_size];
            [resultString appendFormat:@"      pointer_format %u (%@)\n", seg->pointer_format, PointerFormatName(seg->pointer_format)];
            [resultString appendFormat:@"      segment_offset 0x%llx  max_valid_pointer 0x%x\n", seg->segment_offset, seg->max_valid_pointer];
            [resultString appendFormat:@"      page_count %u\n", seg->page_count];
            for (uint16_t p = 0; p < seg->page_count; p++) {
                uint16_t startVal = seg->page_start[p];
                if (startVal == DYLD_CHAINED_PTR_START_NONE) {
                    [resultString appendFormat:@"        page[%u] none\n", p];
                } else {
                    [resultString appendFormat:@"        page[%u] 0x%04x\n", p, startVal];
                }
            }
        }
    }

    if ([_importNames count] > 0) {
        [resultString appendFormat:@"\n  imports (%lu):\n", (unsigned long)[_importNames count]];
        NSUInteger i = 0;
        for (NSString *name in _importNames) {
            [resultString appendFormat:@"    [%lu] %@\n", (unsigned long)i++, name];
        }
    }
}

#pragma mark - Chain walking

// Resolve a raw 64-bit chain entry into (resolvedAddress, nextStrideUnits, isBind, ordinal).
// `outOrdinal` is set to the import-table ordinal for binds, 0 for rebases.
// `cacheBase` is the dyld_shared_cache base VM address (only used for the
// SHARED_CACHE pointer formats whose target is cache-relative). 0 disables
// SHARED_CACHE decoding.
// Returns YES if the slot represents a valid entry; NO to stop the chain
// (e.g. corrupt/unsupported).
static BOOL CDDecodeChainEntry(uint64_t raw, uint16_t format, uint64_t imageBase,
                               uint64_t cacheBase,
                               uint64_t *outResolved, uint32_t *outNextStrideUnits,
                               BOOL *outIsBind, uint32_t *outStrideBytes,
                               uint32_t *outOrdinal)
{
    uint64_t resolved = 0;
    uint32_t next = 0;
    BOOL isBind = NO;
    uint32_t stride = 4; // default for arm64e family
    uint32_t ordinal = 0;

    switch (format) {
        case DYLD_CHAINED_PTR_ARM64E:
        case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND:
        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24: {
            BOOL auth = (raw >> 63) & 1;
            isBind    = (raw >> 62) & 1;
            next      = (uint32_t)((raw >> 51) & 0x7FF);
            // Per dyld's fixup-chains.h: stride is 8 for ARM64E / USERLAND /
            // USERLAND24, and 4 for KERNEL / FIRMWARE.
            switch (format) {
                case DYLD_CHAINED_PTR_ARM64E:
                case DYLD_CHAINED_PTR_ARM64E_USERLAND:
                case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
                    stride = 8; break;
                default:
                    stride = 4; break;
            }
            if (isBind) {
                // USERLAND24 / auth_bind24 use a 24-bit ordinal; the other
                // ARM64E variants use 16 bits.
                if (format == DYLD_CHAINED_PTR_ARM64E_USERLAND24)
                    ordinal = (uint32_t)(raw & 0xFFFFFFULL);
                else
                    ordinal = (uint32_t)(raw & 0xFFFFULL);
                resolved = 0;
            } else if (auth) {
                // auth_rebase: target is 32-bit runtimeOffset (image-relative)
                uint64_t runtimeOffset = raw & 0xFFFFFFFFULL;
                resolved = imageBase + runtimeOffset;
            } else {
                uint64_t target = raw & 0x7FFFFFFFFFFULL; // 43 bits
                uint64_t high8  = (raw >> 43) & 0xFFULL;
                if (format == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                    format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 ||
                    format == DYLD_CHAINED_PTR_ARM64E_KERNEL) {
                    resolved = imageBase + target;
                } else {
                    resolved = target | (high8 << 56);
                }
            }
            break;
        }
        case DYLD_CHAINED_PTR_64: {
            isBind = (raw >> 63) & 1;
            next   = (uint32_t)((raw >> 51) & 0xFFF);
            stride = 4;
            if (isBind) {
                ordinal = (uint32_t)(raw & 0xFFFFFFULL); // 24-bit ordinal
                resolved = 0;
            } else {
                uint64_t target = raw & 0xFFFFFFFFFULL; // 36 bits in modern _64? Actually 43 in classic _64.
                // Be permissive: take 43 bits.
                target = raw & 0x7FFFFFFFFFFULL;
                uint64_t high8 = (raw >> 43) & 0xFFULL;
                resolved = target | (high8 << 56);
            }
            break;
        }
        case DYLD_CHAINED_PTR_64_OFFSET: {
            isBind = (raw >> 63) & 1;
            next   = (uint32_t)((raw >> 51) & 0xFFF);
            stride = 4;
            if (isBind) {
                ordinal = (uint32_t)(raw & 0xFFFFFFULL); // 24-bit ordinal
                resolved = 0;
            } else {
                uint64_t target = raw & 0xFFFFFFFFFULL; // 36 bits
                resolved = imageBase + target;
            }
            break;
        }
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
        case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: {
            // cache_rebase: target=30, cache=2, diversity=16, addrDiv=1, key=2, next=12, isAuth=1
            isBind = NO;
            next   = (uint32_t)((raw >> 51) & 0xFFF);
            stride = 4;
            uint64_t target = raw & 0x3FFFFFFFULL; // 30 bits
            resolved = imageBase + target;
            break;
        }
        case DYLD_CHAINED_PTR_32:
        case DYLD_CHAINED_PTR_32_FIRMWARE: {
            // 32-bit pointers: full slot is 4 bytes. Caller must handle.
            // Bits: bind:1, next:5, target:26 (or similar). Skip for now.
            return NO;
        }
        case 13 /* DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE */: {
            // dyld_chained_ptr_arm64e_shared_cache_rebase:
            //   runtimeOffset:34, high8:8, unused:10, next:11, auth:1
            // dyld_chained_ptr_arm64e_shared_cache_auth_rebase:
            //   runtimeOffset:34, diversity:16, addrDiv:1, keyIsData:1, next:11, auth:1
            // No bind variant for this format — every slot is a rebase whose
            // target is cache-relative.
            if (cacheBase == 0) {
                // Caller didn't (or couldn't) supply a cache base. Refuse to
                // decode rather than zero out the slot, which would corrupt
                // data the caller may still want to inspect raw.
                return NO;
            }
            isBind = NO;
            next   = (uint32_t)((raw >> 52) & 0x7FF);
            stride = 8;
            uint64_t runtimeOffset = raw & 0x3FFFFFFFFULL; // 34 bits
            BOOL auth = (raw >> 63) & 1;
            if (auth) {
                resolved = cacheBase + runtimeOffset;
            } else {
                uint64_t high8 = (raw >> 34) & 0xFFULL;
                resolved = (cacheBase + runtimeOffset) | (high8 << 56);
            }
            break;
        }
        default:
            return NO;
    }

    if (outResolved) *outResolved = resolved;
    if (outNextStrideUnits) *outNextStrideUnits = next;
    if (outIsBind) *outIsBind = isBind;
    if (outStrideBytes) *outStrideBytes = stride;
    if (outOrdinal) *outOrdinal = ordinal;
    return YES;
}

- (void)applyToMutableData:(NSMutableData *)data imageBase:(uint64_t)imageBase
{
    [self ensureParsed];
    NSData *blob = [self linkeditData];
    NSUInteger blobLen = [blob length];
    if (blobLen < sizeof(_header)) return;
    if (_header.starts_offset == 0) return;
    if ((NSUInteger)_header.starts_offset + sizeof(struct dyld_chained_starts_in_image) > blobLen) return;

    const uint8_t *blobBase = (const uint8_t *)[blob bytes];
    const struct dyld_chained_starts_in_image *image =
        (const struct dyld_chained_starts_in_image *)(blobBase + _header.starts_offset);

    NSUInteger fileLen = [data length];
    uint8_t *fileBytes = (uint8_t *)[data mutableBytes];

    // Snapshot of segments for file-offset → VM-address translation. We can't
    // ask self.machOFile.segments inside the inner loop because that triggers
    // weak-reference loads on every bind slot; cache once up front.
    NSArray<CDLCSegment *> *machoSegments = [self.machOFile segments];

    // For DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE, the rebase target is encoded
    // as a 34-bit offset from the shared cache's base VM. We don't have an
    // explicit cache-base field in the chained-fixups payload; derive it by
    // rounding the image's __TEXT vmaddr down to a 2 GB boundary (modern
    // shared caches load at fixed 2 GB-aligned bases — 0x180000000 on macOS
    // arm64). Without this, format-13 slots would be left raw and downstream
    // readers would report "unresolved adopted protocol" notes for every
    // cache-resident protocol the image references.
    uint64_t cacheBase = imageBase & 0xFFFFFFFF80000000ULL;

    if (_bindNameByAddress == nil)
        _bindNameByAddress = [[NSMutableDictionary alloc] init];

    for (uint32_t s = 0; s < image->seg_count; s++) {
        uint32_t segInfoOff = image->seg_info_offset[s];
        if (segInfoOff == 0) continue;
        NSUInteger segOff = (NSUInteger)_header.starts_offset + segInfoOff;
        if (segOff + sizeof(struct dyld_chained_starts_in_segment) > blobLen) continue;
        const struct dyld_chained_starts_in_segment *seg =
            (const struct dyld_chained_starts_in_segment *)(blobBase + segOff);

        uint16_t fmt = seg->pointer_format;
        uint64_t segOffset = seg->segment_offset;
        uint32_t pageSize = seg->page_size ?: 0x4000;

        for (uint16_t p = 0; p < seg->page_count; p++) {
            uint16_t startVal = seg->page_start[p];
            if (startVal == DYLD_CHAINED_PTR_START_NONE) continue;
            // Multi-chain pages (high bit set) point to a list of starts; skip
            // for simplicity — they're rare in extracted dylibs.
            if (startVal & DYLD_CHAINED_PTR_START_MULTI) continue;

            uint64_t pageStartFileOff = segOffset + (uint64_t)p * pageSize + startVal;
            if (pageStartFileOff + 8 > fileLen) continue;

            uint32_t strideBytes = 4;
            uint64_t cursor = pageStartFileOff;
            for (;;) {
                if (cursor + 8 > fileLen) break;
                uint64_t raw;
                memcpy(&raw, fileBytes + cursor, 8);

                uint64_t resolved = 0;
                uint32_t nextUnits = 0;
                BOOL isBind = NO;
                uint32_t ordinal = 0;
                if (!CDDecodeChainEntry(raw, fmt, imageBase, cacheBase, &resolved, &nextUnits, &isBind, &strideBytes, &ordinal)) {
                    break;
                }

                // For binds, record VM address → import symbol name BEFORE
                // we overwrite the slot. CDObjectiveC2Processor later asks
                // for an external class name at this VM address.
                if (isBind && ordinal < [_importNames count]) {
                    NSString *importName = [_importNames objectAtIndex:ordinal];
                    if ([importName length] > 0) {
                        uint64_t vmAddr = 0;
                        for (CDLCSegment *cdSeg in machoSegments) {
                            NSUInteger fo = cdSeg.fileoff;
                            NSUInteger sz = cdSeg.filesize;
                            if (cursor >= fo && cursor < fo + sz) {
                                vmAddr = (uint64_t)cdSeg.vmaddr + (cursor - (uint64_t)fo);
                                break;
                            }
                        }
                        if (vmAddr != 0) {
                            _bindNameByAddress[@(vmAddr)] = importName;
                        }
                    }
                }

                memcpy(fileBytes + cursor, &resolved, 8);

                if (nextUnits == 0) break;
                cursor += (uint64_t)nextUnits * strideBytes;
                // Don't run off the page (chains are page-local).
                uint64_t pageEnd = segOffset + (uint64_t)(p + 1) * pageSize;
                if (cursor >= pageEnd) break;
            }
        }
    }
}

- (NSString *)bindNameForAddress:(uint64_t)address;
{
    return _bindNameByAddress[@(address)];
}

@end
