// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDFilesetExtractor.h"
#import "CDLCFilesetEntry.h"

#include <mach-o/loader.h>
#include <string.h>

NSString * const CDFilesetExtractorErrorDomain = @"CDFilesetExtractorErrorDomain";

// Mach-O LC numbers that may post-date the SDK we're building against.
#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE   (0x33 | LC_REQ_DYLD)
#endif
#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS (0x34 | LC_REQ_DYLD)
#endif
#ifndef LC_FILESET_ENTRY
#define LC_FILESET_ENTRY       (0x35 | LC_REQ_DYLD)
#endif

// Per-segment record built during planning; consumed when we copy bytes and
// rewrite LC_SEGMENT_64.fileoff / section_64.offset.
typedef struct {
    uint64_t origFileoff;   // segment fileoff in the source cache
    uint64_t newFileoff;    // segment fileoff in the extracted file
    uint64_t fileSize;      // bytes to copy (==filesize in source)
    NSUInteger lcOffset;    // byte offset of this LC_SEGMENT_64 inside the LC region
    BOOL isLinkedit;        // SEG_LINKEDIT?
} CDFilesetSegMap;

static inline uint64_t CDAlignUp64(uint64_t v, uint64_t a)
{
    return (v + a - 1) & ~(a - 1);
}

static NSError *CDMakeError(NSInteger code, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static NSError *CDMakeError(NSInteger code, NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    return [NSError errorWithDomain:CDFilesetExtractorErrorDomain
                               code:code
                           userInfo:@{ NSLocalizedFailureReasonErrorKey: m }];
}

@implementation CDFilesetExtractor

+ (BOOL)extractEntry:(CDLCFilesetEntry *)entry
           fromCache:(NSData *)cacheData
              toPath:(NSString *)outPath
               error:(NSError **)error
{
    if (entry == nil || cacheData == nil || outPath == nil) {
        if (error) *error = CDMakeError(1, @"nil argument");
        return NO;
    }

    const uint8_t *cacheBytes = (const uint8_t *)[cacheData bytes];
    const NSUInteger cacheLen = [cacheData length];
    const uint64_t headerOff = entry.fileoff;

    if (headerOff + sizeof(struct mach_header_64) > cacheLen) {
        if (error) *error = CDMakeError(2, @"fileset entry header at 0x%llx is out of bounds", headerOff);
        return NO;
    }

    struct mach_header_64 mh;
    memcpy(&mh, cacheBytes + headerOff, sizeof(mh));
    if (mh.magic != MH_MAGIC_64) {
        if (error) *error = CDMakeError(3, @"unsupported Mach-O magic 0x%08x at 0x%llx (only 64-bit little-endian fileset entries are supported)",
                                        mh.magic, headerOff);
        return NO;
    }

    const NSUInteger lcRegionSize = (NSUInteger)mh.sizeofcmds;
    const NSUInteger headerRegion = sizeof(mh) + lcRegionSize;
    if (mh.ncmds == 0 || lcRegionSize == 0 || headerOff + headerRegion > cacheLen) {
        if (error) *error = CDMakeError(4, @"malformed Mach-O header at 0x%llx (ncmds=%u sizeofcmds=%u)",
                                        headerOff, mh.ncmds, mh.sizeofcmds);
        return NO;
    }

    // -- Pass 1: find the kext's __LINKEDIT slice in the source cache, so we
    // can later rebase linkedit-resident command offsets onto its new home.
    const uint8_t *lcBase = cacheBytes + headerOff + sizeof(mh);
    uint64_t le_orig = 0, le_size = 0;
    {
        NSUInteger off = 0;
        for (uint32_t i = 0; i < mh.ncmds; i++) {
            if (off + sizeof(struct load_command) > lcRegionSize) break;
            struct load_command lc;
            memcpy(&lc, lcBase + off, sizeof(lc));
            if (lc.cmdsize < sizeof(lc) || off + lc.cmdsize > lcRegionSize) break;
            if (lc.cmd == LC_SEGMENT_64 && lc.cmdsize >= sizeof(struct segment_command_64)) {
                struct segment_command_64 sc;
                memcpy(&sc, lcBase + off, sizeof(sc));
                if (strncmp(sc.segname, SEG_LINKEDIT, sizeof(sc.segname)) == 0) {
                    le_orig = sc.fileoff;
                    le_size = sc.filesize;
                    break;
                }
            }
            off += lc.cmdsize;
        }
    }

    // -- Pass 2: plan a new file layout. __TEXT (which contains the header +
    // load commands) goes at offset 0; the remaining segments are placed
    // sequentially, page-aligned. The original load commands say where each
    // segment lives in the source cache; we record (orig, new) pairs and
    // grow the output buffer to fit.
    NSMutableData *plans = [NSMutableData data];
    uint64_t cursor = 0;
    uint64_t newLEoff = 0;
    BOOL haveLE = NO;
    BOOL haveText = NO;

    {
        NSUInteger off = 0;
        for (uint32_t i = 0; i < mh.ncmds; i++) {
            if (off + sizeof(struct load_command) > lcRegionSize) break;
            struct load_command lc;
            memcpy(&lc, lcBase + off, sizeof(lc));
            if (lc.cmdsize < sizeof(lc) || off + lc.cmdsize > lcRegionSize) break;

            if (lc.cmd == LC_SEGMENT_64 && lc.cmdsize >= sizeof(struct segment_command_64)) {
                struct segment_command_64 sc;
                memcpy(&sc, lcBase + off, sizeof(sc));

                BOOL isLE   = (strncmp(sc.segname, SEG_LINKEDIT, sizeof(sc.segname)) == 0);
                BOOL isText = (strncmp(sc.segname, SEG_TEXT,     sizeof(sc.segname)) == 0);

                uint64_t newFileoff = 0;
                if (sc.filesize > 0) {
                    if (isText && sc.fileoff == headerOff) {
                        // Place __TEXT at offset 0: copying its bytes wholesale
                        // preserves the mach header + load commands we'll later
                        // edit in place.
                        newFileoff = 0;
                        haveText = YES;
                    } else {
                        cursor = CDAlignUp64(cursor, 0x4000);
                        newFileoff = cursor;
                    }
                    uint64_t end = newFileoff + sc.filesize;
                    if (end > cursor) cursor = end;
                }

                CDFilesetSegMap m = {
                    .origFileoff = sc.fileoff,
                    .newFileoff  = newFileoff,
                    .fileSize    = sc.filesize,
                    .lcOffset    = off,
                    .isLinkedit  = isLE,
                };
                [plans appendBytes:&m length:sizeof(m)];
                if (isLE) { newLEoff = newFileoff; haveLE = YES; }
            }

            off += lc.cmdsize;
        }
    }

    if (!haveText) {
        if (error) *error = CDMakeError(5, @"fileset entry at 0x%llx has no __TEXT segment co-located with the header (entry-relative __TEXT extraction is not supported)",
                                        headerOff);
        return NO;
    }

    // Make sure the output is at least big enough to hold the header + load
    // commands (handles tiny synthetic test inputs with no segment data).
    if (cursor < headerRegion) cursor = headerRegion;

    NSMutableData *out = [NSMutableData dataWithLength:(NSUInteger)cursor];
    uint8_t *outBuf = (uint8_t *)[out mutableBytes];

    // -- Pass 3: copy segment bytes from the cache into the new layout.
    const CDFilesetSegMap *plan = (const CDFilesetSegMap *)[plans bytes];
    const NSUInteger nPlans = [plans length] / sizeof(CDFilesetSegMap);
    for (NSUInteger i = 0; i < nPlans; i++) {
        if (plan[i].fileSize == 0) continue;
        uint64_t src = plan[i].origFileoff;
        uint64_t sz  = plan[i].fileSize;
        if (src >= cacheLen) continue;
        if (src + sz > cacheLen) sz = cacheLen - src;
        if (sz > 0) {
            memcpy(outBuf + plan[i].newFileoff, cacheBytes + src, (size_t)sz);
        }
    }

    // After the __TEXT copy above, the original header + load commands now
    // live at the start of outBuf — we can edit them in place.

    // -- Pass 4: rewrite each LC_SEGMENT_64.fileoff and its section_64.offset
    // values to point inside the new layout.
    for (NSUInteger i = 0; i < nPlans; i++) {
        NSUInteger scOff = sizeof(mh) + plan[i].lcOffset;
        if (scOff + sizeof(struct segment_command_64) > sizeof(mh) + lcRegionSize) continue;

        struct segment_command_64 sc;
        memcpy(&sc, outBuf + scOff, sizeof(sc));
        uint64_t orig = sc.fileoff;
        sc.fileoff = plan[i].newFileoff;
        memcpy(outBuf + scOff, &sc, sizeof(sc));

        // Sections come immediately after the segment_command_64.
        uint64_t segEnd = orig + plan[i].fileSize;
        for (uint32_t s = 0; s < sc.nsects; s++) {
            NSUInteger secOff = scOff + sizeof(sc) + (NSUInteger)s * sizeof(struct section_64);
            if (secOff + sizeof(struct section_64) > sizeof(mh) + lcRegionSize) break;
            struct section_64 sect;
            memcpy(&sect, outBuf + secOff, sizeof(sect));
            if (sect.offset != 0 && (uint64_t)sect.offset >= orig && (uint64_t)sect.offset < segEnd) {
                uint64_t rebase = (uint64_t)sect.offset - orig + plan[i].newFileoff;
                if (rebase <= UINT32_MAX) {
                    sect.offset = (uint32_t)rebase;
                    memcpy(outBuf + secOff, &sect, sizeof(sect));
                }
            }
            // sect.reloff is generally 0 in fileset kexts; leave it alone.
        }
    }

    // -- Pass 5: rewrite linkedit-resident command offsets. Anything pointing
    // inside the kext's original __LINKEDIT slice gets rebased onto its new
    // home; anything pointing outside (rare — typically only happens when a
    // kernel cache shares a string pool across kexts) is zeroed out so the
    // loaded image stays valid even if it loses that one piece of metadata.
    if (haveLE && le_size > 0) {
        NSUInteger off = 0;
        for (uint32_t i = 0; i < mh.ncmds; i++) {
            if (off + sizeof(struct load_command) > lcRegionSize) break;
            struct load_command lc;
            memcpy(&lc, outBuf + sizeof(mh) + off, sizeof(lc));
            if (lc.cmdsize < sizeof(lc) || off + lc.cmdsize > lcRegionSize) break;

            NSUInteger cmdOff = sizeof(mh) + off;

#define CD_REBASE_OFF(field, sizeField) do { \
    if (c.field != 0) { \
        uint64_t v = (uint64_t)c.field; \
        if (v >= le_orig && v < le_orig + le_size) { \
            uint64_t r = v - le_orig + newLEoff; \
            if (r <= UINT32_MAX) c.field = (uint32_t)r; \
        } else { \
            c.field = 0; c.sizeField = 0; \
        } \
    } \
} while (0)

            switch (lc.cmd) {
                case LC_SYMTAB: {
                    if (lc.cmdsize < sizeof(struct symtab_command)) break;
                    struct symtab_command c;
                    memcpy(&c, outBuf + cmdOff, sizeof(c));
                    CD_REBASE_OFF(symoff, nsyms);
                    CD_REBASE_OFF(stroff, strsize);
                    memcpy(outBuf + cmdOff, &c, sizeof(c));
                    break;
                }
                case LC_DYSYMTAB: {
                    if (lc.cmdsize < sizeof(struct dysymtab_command)) break;
                    struct dysymtab_command c;
                    memcpy(&c, outBuf + cmdOff, sizeof(c));
                    CD_REBASE_OFF(tocoff,        ntoc);
                    CD_REBASE_OFF(modtaboff,     nmodtab);
                    CD_REBASE_OFF(extrefsymoff,  nextrefsyms);
                    CD_REBASE_OFF(indirectsymoff,nindirectsyms);
                    CD_REBASE_OFF(extreloff,     nextrel);
                    CD_REBASE_OFF(locreloff,     nlocrel);
                    memcpy(outBuf + cmdOff, &c, sizeof(c));
                    break;
                }
                case LC_FUNCTION_STARTS:
                case LC_DATA_IN_CODE:
                case LC_DYLD_CHAINED_FIXUPS:
                case LC_DYLD_EXPORTS_TRIE:
                case LC_CODE_SIGNATURE:
                case LC_SEGMENT_SPLIT_INFO:
                case LC_LINKER_OPTIMIZATION_HINT: {
                    if (lc.cmdsize < sizeof(struct linkedit_data_command)) break;
                    struct linkedit_data_command c;
                    memcpy(&c, outBuf + cmdOff, sizeof(c));
                    CD_REBASE_OFF(dataoff, datasize);
                    memcpy(outBuf + cmdOff, &c, sizeof(c));
                    break;
                }
                case LC_DYLD_INFO:
                case LC_DYLD_INFO_ONLY: {
                    if (lc.cmdsize < sizeof(struct dyld_info_command)) break;
                    struct dyld_info_command c;
                    memcpy(&c, outBuf + cmdOff, sizeof(c));
                    CD_REBASE_OFF(rebase_off,    rebase_size);
                    CD_REBASE_OFF(bind_off,      bind_size);
                    CD_REBASE_OFF(weak_bind_off, weak_bind_size);
                    CD_REBASE_OFF(lazy_bind_off, lazy_bind_size);
                    CD_REBASE_OFF(export_off,    export_size);
                    memcpy(outBuf + cmdOff, &c, sizeof(c));
                    break;
                }
                default:
                    break;
            }

#undef CD_REBASE_OFF

            off += lc.cmdsize;
        }
    }

    NSError *werr = nil;
    if (![out writeToFile:outPath options:NSDataWritingAtomic error:&werr]) {
        if (error) *error = werr ?: CDMakeError(6, @"writing %@ failed", outPath);
        return NO;
    }
    return YES;
}

@end
