// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCChainedFixups.h"

#import "CDMachOFile.h"

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

// Resolve a raw 64-bit chain entry into (resolvedAddress, nextStrideUnits, isBind).
// Returns YES if the slot represents a valid entry; NO to stop the chain
// (e.g. corrupt/unsupported).
static BOOL CDDecodeChainEntry(uint64_t raw, uint16_t format, uint64_t imageBase,
                               uint64_t *outResolved, uint32_t *outNextStrideUnits,
                               BOOL *outIsBind, uint32_t *outStrideBytes)
{
    uint64_t resolved = 0;
    uint32_t next = 0;
    BOOL isBind = NO;
    uint32_t stride = 4; // default for arm64e family

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
        default:
            return NO;
    }

    if (outResolved) *outResolved = resolved;
    if (outNextStrideUnits) *outNextStrideUnits = next;
    if (outIsBind) *outIsBind = isBind;
    if (outStrideBytes) *outStrideBytes = stride;
    return YES;
}

- (void)applyToMutableData:(NSMutableData *)data imageBase:(uint64_t)imageBase
{
    [self ensureParsed];
    NSData *blob = [self linkeditData];
    NSUInteger blobLen = [blob length];
    if (blobLen < sizeof(_header)) { NSLog(@"chain: blob too small %lu < %lu", (unsigned long)blobLen, sizeof(_header)); return; }
    if (_header.starts_offset == 0) { NSLog(@"chain: starts_offset is 0"); return; }
    if ((NSUInteger)_header.starts_offset + sizeof(struct dyld_chained_starts_in_image) > blobLen) { NSLog(@"chain: starts out of bounds"); return; }
    NSLog(@"chain: starts_offset=%u, blobLen=%lu, dataLen=%lu, imageBase=0x%llx",
          _header.starts_offset, (unsigned long)blobLen, (unsigned long)[data length], imageBase);
    NSUInteger chainCount = 0;

    const uint8_t *blobBase = (const uint8_t *)[blob bytes];
    const struct dyld_chained_starts_in_image *image =
        (const struct dyld_chained_starts_in_image *)(blobBase + _header.starts_offset);

    NSUInteger fileLen = [data length];
    uint8_t *fileBytes = (uint8_t *)[data mutableBytes];

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
                if (!CDDecodeChainEntry(raw, fmt, imageBase, &resolved, &nextUnits, &isBind, &strideBytes)) {
                    break;
                }

                memcpy(fileBytes + cursor, &resolved, 8);
                chainCount++;

                if (nextUnits == 0) break;
                cursor += (uint64_t)nextUnits * strideBytes;
                // Don't run off the page (chains are page-local).
                uint64_t pageEnd = segOffset + (uint64_t)(p + 1) * pageSize;
                if (cursor >= pageEnd) break;
            }
        }
    }
    NSLog(@"chain: rewrote %lu slots", (unsigned long)chainCount);
}

@end
