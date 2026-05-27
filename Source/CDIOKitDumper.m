// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDIOKitDumper.h"

#import "CDMachOFile.h"
#import "CDLCFilesetEntry.h"
#import "CDLCSegment.h"
#import "CDSection.h"
#import "CDSearchPathState.h"

@implementation CDIOKitMetaClass
@end

// One file-backed VM range from the top-level fileset Mach-O.
typedef struct {
    uint64_t vmaddr;
    uint64_t filesize;
    uint64_t fileoff;
    BOOL     exec;       // mapped from an executable/text segment
} CDIOKitSeg;

@implementation CDIOKitDumper
{
    NSData         *_cacheData;
    const uint8_t  *_bytes;
    NSUInteger      _length;
    CDMachOFile    *_topLevel;

    CDIOKitSeg     *_segs;
    NSUInteger      _segCount;
    uint64_t        _base;

    // metaClassAddress(NSNumber) -> CDIOKitMetaClass
    NSMutableDictionary<NSNumber *, CDIOKitMetaClass *> *_meta;

    // Candidate vtables discovered in __const: parallel arrays.
    NSMutableArray<NSNumber *> *_vtableAddrs;          // start address
    NSMutableArray<NSArray<NSNumber *> *> *_vtableSlots; // resolved exec slot addresses
}

- (instancetype)initWithCacheData:(NSData *)cacheData topLevel:(CDMachOFile *)topLevel;
{
    if ((self = [super init])) {
        _cacheData = cacheData;
        _bytes     = (const uint8_t *)[cacheData bytes];
        _length    = [cacheData length];
        _topLevel  = topLevel;
        _meta        = [NSMutableDictionary dictionary];
        _vtableAddrs = [NSMutableArray array];
        _vtableSlots = [NSMutableArray array];
        [self buildSegmentMap];
    }
    return self;
}

- (NSUInteger)metaClassCount { return [_meta count]; }

#pragma mark - Address translation

- (void)buildSegmentMap;
{
    NSArray *segments = _topLevel.segments;
    _segCount = [segments count];
    _segs = calloc(_segCount ?: 1, sizeof(CDIOKitSeg));
    uint64_t base = UINT64_MAX;
    NSUInteger i = 0;
    for (CDLCSegment *seg in segments) {
        _segs[i].vmaddr   = (uint64_t)seg.vmaddr;
        _segs[i].filesize = (uint64_t)seg.filesize;
        _segs[i].fileoff  = (uint64_t)seg.fileoff;
        NSString *n = seg.name;
        _segs[i].exec = ([n isEqualToString:@"__TEXT_EXEC"] ||
                         [n isEqualToString:@"__TEXT_BOOT_EXEC"] ||
                         [n isEqualToString:@"__TEXT"]);
        if (_segs[i].vmaddr < base) base = _segs[i].vmaddr;
        i++;
    }
    _base = (base == UINT64_MAX) ? 0 : base;
}

// VM address -> file offset, or NSNotFound. Only addresses with file backing
// resolve (the cache maps each segment's filesize bytes).
- (NSUInteger)offsetForAddress:(uint64_t)addr;
{
    for (NSUInteger i = 0; i < _segCount; i++) {
        if (addr >= _segs[i].vmaddr && (addr - _segs[i].vmaddr) < _segs[i].filesize) {
            return (NSUInteger)(_segs[i].fileoff + (addr - _segs[i].vmaddr));
        }
    }
    return NSNotFound;
}

- (BOOL)addressInExec:(uint64_t)addr;
{
    for (NSUInteger i = 0; i < _segCount; i++) {
        if (_segs[i].exec && addr >= _segs[i].vmaddr && (addr - _segs[i].vmaddr) < _segs[i].filesize)
            return YES;
    }
    return NO;
}

// Resolve a raw (possibly chained-fixup) 64-bit slot to a VM address. The
// arm64e kernelcache pointer formats encode the target as a low-bit offset from
// the cache base; we accept the value as-is when it already lands in a segment,
// otherwise probe the common offset widths.
- (uint64_t)resolvePointer:(uint64_t)raw;
{
    if (raw == 0) return 0;
    if ([self offsetForAddress:raw] != NSNotFound) return raw;
    const uint64_t masks[3] = { 0x3FFFFFFFULL, 0x7FFFFFFFFULL, 0xFFFFFFFFFULL };
    for (int i = 0; i < 3; i++) {
        uint64_t cand = _base + (raw & masks[i]);
        if ([self offsetForAddress:cand] != NSNotFound) return cand;
    }
    return 0;
}

- (uint64_t)pointerAtAddress:(uint64_t)addr;
{
    NSUInteger off = [self offsetForAddress:addr];
    if (off == NSNotFound || off + 8 > _length) return 0;
    uint64_t raw;
    memcpy(&raw, _bytes + off, 8);
    return [self resolvePointer:raw];
}

- (NSString *)stringAtAddress:(uint64_t)addr;
{
    NSUInteger off = [self offsetForAddress:addr];
    if (off == NSNotFound) return nil;
    NSUInteger end = off;
    while (end < _length && _bytes[end] != 0) end++;
    if (end == off || end >= _length) return nil;
    NSUInteger len = end - off;
    for (NSUInteger i = off; i < end; i++) {
        uint8_t c = _bytes[i];
        if (c < 0x20 || c >= 0x7f) return nil; // printable ASCII only
    }
    return [[NSString alloc] initWithBytes:_bytes + off length:len encoding:NSASCIIStringEncoding];
}

static BOOL CDIsClassNameChar(unichar c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '_' || c == ':' || c == '<' || c == '>' || c == ',' || c == ' ' ||
            c == '*' || c == '&' || c == '$' || c == '~';
}

static BOOL CDIsLikelyClassName(NSString *s)
{
    NSUInteger len = [s length];
    if (len == 0 || len > 200) return NO;
    unichar first = [s characterAtIndex:0];
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_')) return NO;
    for (NSUInteger i = 0; i < len; i++) {
        if (!CDIsClassNameChar([s characterAtIndex:i])) return NO;
    }
    return YES;
}

#pragma mark - ARM64 mini-emulation

// Emulate a straight-line prologue tracking x0..x30 through the constant-
// materialising instructions (ADRP, ADD imm, MOVZ/MOVK, LDR uimm). Stops at the
// first BL (the OSMetaClass::OSMetaClass call) and returns x0..x3 in out[0..3],
// or returns NO on RET / instruction budget exhaustion before any BL.
- (BOOL)emulateConstructorAt:(uint64_t)funcAddr out:(uint64_t[4])out;
{
    NSUInteger off = [self offsetForAddress:funcAddr];
    if (off == NSNotFound) return NO;
    uint64_t reg[32] = {0};
    const NSUInteger kMax = 240;
    for (NSUInteger i = 0; i < kMax; i++) {
        NSUInteger io = off + i * 4;
        if (io + 4 > _length) break;
        uint32_t ins;
        memcpy(&ins, _bytes + io, 4);
        uint64_t pc = funcAddr + i * 4;

        if ((ins & 0x9F000000) == 0x90000000) {            // ADRP
            uint32_t rd = ins & 0x1F;
            uint64_t immlo = (ins >> 29) & 3;
            uint64_t immhi = (ins >> 5) & 0x7FFFF;
            int64_t imm = (int64_t)((immhi << 2) | immlo);
            if (imm & (1 << 20)) imm -= (1 << 21);
            reg[rd] = (pc & ~0xFFFULL) + ((uint64_t)imm << 12);
        } else if ((ins & 0xFF000000) == 0x91000000) {     // ADD (immediate, 64-bit)
            uint32_t rd = ins & 0x1F, rn = (ins >> 5) & 0x1F;
            uint64_t imm = (ins >> 10) & 0xFFF;
            if ((ins >> 22) & 1) imm <<= 12;
            reg[rd] = reg[rn] + imm;
        } else if ((ins & 0x7F800000) == 0x52800000) {     // MOVZ (32/64)
            uint32_t rd = ins & 0x1F;
            uint64_t imm16 = (ins >> 5) & 0xFFFF;
            uint32_t hw = ((ins >> 21) & 3) * 16;
            reg[rd] = imm16 << hw;
        } else if ((ins & 0x7F800000) == 0x72800000) {     // MOVK
            uint32_t rd = ins & 0x1F;
            uint64_t imm16 = (ins >> 5) & 0xFFFF;
            uint32_t hw = ((ins >> 21) & 3) * 16;
            reg[rd] = (reg[rd] & ~(0xFFFFULL << hw)) | (imm16 << hw);
        } else if ((ins & 0xFFC00000) == 0xF9400000) {     // LDR (immediate, unsigned offset, 64-bit)
            uint32_t rt = ins & 0x1F, rn = (ins >> 5) & 0x1F;
            uint64_t a = reg[rn] + ((uint64_t)((ins >> 10) & 0xFFF) * 8);
            reg[rt] = [self pointerAtAddress:a];
        } else if ((ins & 0xFC000000) == 0x94000000) {     // BL
            out[0] = reg[0]; out[1] = reg[1]; out[2] = reg[2]; out[3] = reg[3];
            return YES;
        } else if (ins == 0xD65F03C0) {                    // RET
            break;
        }
    }
    return NO;
}

// Emulate a tiny getMetaClass()-style thunk: returns the address loaded into x0
// by the time RET executes (the metaclass address). Returns 0 if it branches
// away before returning.
- (uint64_t)emulateMetaClassThunkAt:(uint64_t)funcAddr;
{
    NSUInteger off = [self offsetForAddress:funcAddr];
    if (off == NSNotFound) return 0;
    uint64_t reg[32] = {0};
    for (NSUInteger i = 0; i < 8; i++) {
        NSUInteger io = off + i * 4;
        if (io + 4 > _length) break;
        uint32_t ins;
        memcpy(&ins, _bytes + io, 4);
        uint64_t pc = funcAddr + i * 4;
        if ((ins & 0x9F000000) == 0x90000000) {            // ADRP
            uint32_t rd = ins & 0x1F;
            uint64_t immlo = (ins >> 29) & 3;
            uint64_t immhi = (ins >> 5) & 0x7FFFF;
            int64_t imm = (int64_t)((immhi << 2) | immlo);
            if (imm & (1 << 20)) imm -= (1 << 21);
            reg[rd] = (pc & ~0xFFFULL) + ((uint64_t)imm << 12);
        } else if ((ins & 0xFF000000) == 0x91000000) {     // ADD imm
            uint32_t rd = ins & 0x1F, rn = (ins >> 5) & 0x1F;
            uint64_t imm = (ins >> 10) & 0xFFF;
            if ((ins >> 22) & 1) imm <<= 12;
            reg[rd] = reg[rn] + imm;
        } else if ((ins & 0xFFC00000) == 0xF9400000) {     // LDR uimm
            uint32_t rt = ins & 0x1F, rn = (ins >> 5) & 0x1F;
            uint64_t a = reg[rn] + ((uint64_t)((ins >> 10) & 0xFFF) * 8);
            reg[rt] = [self pointerAtAddress:a];
        } else if (ins == 0xD65F03C0) {                    // RET
            return reg[0];
        } else if ((ins & 0xFC000000) == 0x94000000) {     // BL -> not a simple thunk
            break;
        }
    }
    return 0;
}

#pragma mark - Scanning

- (void)scanFilesetEntries:(NSArray<CDLCFilesetEntry *> *)entries;
{
    CDSearchPathState *sp = [[CDSearchPathState alloc] init];
    NSMutableArray<NSValue *> *constSections = [NSMutableArray array]; // NSRange{addr,size}

    // Pass 1: recover metaclasses from every kext's constructors.
    for (CDLCFilesetEntry *e in entries) {
        if ((NSUInteger)e.fileoff >= _length) continue;
        @autoreleasepool {
            CDMachOFile *entry = [[CDMachOFile alloc] initWithData:_cacheData
                                                      headerOffset:(NSUInteger)e.fileoff
                                                          filename:e.entryID ?: @"?"
                                                   searchPathState:sp];
            if (entry == nil) continue;
            NSString *kextID = e.entryID ?: [NSString stringWithFormat:@"entry_%llx", e.fileoff];

            for (CDLCSegment *seg in entry.segments) {
                for (CDSection *sect in seg.sections) {
                    NSString *sn = sect.sectionName;
                    NSString *sg = sect.segmentName;
                    if ([sn isEqualToString:@"__mod_init_func"] || [sn isEqualToString:@"__init"]) {
                        [self scanInitSection:sect kextID:kextID];
                    } else if ([sn isEqualToString:@"__const"] &&
                               ([sg isEqualToString:@"__DATA_CONST"] ||
                                [sg isEqualToString:@"__DATA"] ||
                                [sg isEqualToString:@"__KLDDATA"])) {
                        [constSections addObject:[NSValue valueWithRange:NSMakeRange((NSUInteger)sect.addr, (NSUInteger)sect.size)]];
                    }
                }
            }
        }
    }

    // Resolve cross-kext superclass edges that go through a GOT indirection:
    // when a super metaclass address isn't itself a known metaclass, try
    // dereferencing it once (the constructor loaded a GOT slot pointing at the
    // real metaclass).
    for (CDIOKitMetaClass *mc in [_meta allValues]) {
        if (mc.superMetaClassAddress == 0) continue;
        if (_meta[@(mc.superMetaClassAddress)] != nil) continue;
        uint64_t deref = [self pointerAtAddress:mc.superMetaClassAddress];
        if (deref != 0 && _meta[@(deref)] != nil) mc.superMetaClassAddress = deref;
    }

    // Pass 2: recover vtables.
    [self recoverVtablesFromConstSections:constSections];
}

- (void)scanInitSection:(CDSection *)sect kextID:(NSString *)kextID;
{
    uint64_t addr = (uint64_t)sect.addr;
    NSUInteger size = (NSUInteger)sect.size;
    for (NSUInteger k = 0; k + 8 <= size; k += 8) {
        uint64_t fn = [self pointerAtAddress:addr + k];
        if (fn == 0 || ![self addressInExec:fn]) continue;
        uint64_t r[4];
        if (![self emulateConstructorAt:fn out:r]) continue;
        uint64_t metaAddr = r[0], nameAddr = r[1], superAddr = r[2];
        uint32_t size32 = (uint32_t)r[3];
        if ([self offsetForAddress:metaAddr] == NSNotFound) continue;
        if (size32 == 0 || size32 > 0x200000) continue;
        NSString *name = [self stringAtAddress:nameAddr];
        if (![name length] || !CDIsLikelyClassName(name)) continue;

        NSNumber *key = @(metaAddr);
        if (_meta[key] != nil) continue; // first definition wins
        CDIOKitMetaClass *mc = [[CDIOKitMetaClass alloc] init];
        mc.metaClassAddress      = metaAddr;
        mc.superMetaClassAddress = superAddr;
        mc.name                  = name;
        mc.instanceSize          = size32;
        mc.kextID                = kextID;
        _meta[key] = mc;
    }
}

- (void)recoverVtablesFromConstSections:(NSArray<NSValue *> *)constSections;
{
    // Gather candidate vtables: runs of >= 8 consecutive pointers that all
    // target executable code.
    for (NSValue *v in constSections) {
        NSRange r = [v rangeValue];
        uint64_t addr = r.location;
        NSUInteger count = r.length / 8;
        NSUInteger i = 0;
        while (i < count) {
            uint64_t p = [self pointerAtAddress:addr + i * 8];
            if (p != 0 && [self addressInExec:p]) {
                NSUInteger j = i;
                NSMutableArray<NSNumber *> *slots = [NSMutableArray array];
                while (j < count) {
                    uint64_t q = [self pointerAtAddress:addr + j * 8];
                    if (q != 0 && [self addressInExec:q]) { [slots addObject:@(q)]; j++; }
                    else break;
                }
                if ([slots count] >= 8) {
                    [_vtableAddrs addObject:@(addr + i * 8)];
                    [_vtableSlots addObject:slots];
                }
                i = j;
            } else {
                i++;
            }
        }
    }

    // Detect the getMetaClass() slot: the slot index whose thunk most often
    // returns a known metaclass address across all candidate vtables.
    NSInteger bestSlot = -1; NSUInteger bestHits = 0;
    NSUInteger n = [_vtableAddrs count];
    for (NSUInteger s = 0; s < 30; s++) {
        NSUInteger hits = 0;
        for (NSUInteger vi = 0; vi < n; vi++) {
            NSArray<NSNumber *> *slots = _vtableSlots[vi];
            if (s >= [slots count]) continue;
            uint64_t m = [self emulateMetaClassThunkAt:[slots[s] unsignedLongLongValue]];
            if (m != 0 && _meta[@(m)] != nil) hits++;
        }
        if (hits > bestHits) { bestHits = hits; bestSlot = (NSInteger)s; }
    }
    if (bestSlot < 0) return;

    // Assign each vtable to its class (first vtable wins per metaclass).
    for (NSUInteger vi = 0; vi < n; vi++) {
        NSArray<NSNumber *> *slots = _vtableSlots[vi];
        if ((NSUInteger)bestSlot >= [slots count]) continue;
        uint64_t m = [self emulateMetaClassThunkAt:[slots[(NSUInteger)bestSlot] unsignedLongLongValue]];
        CDIOKitMetaClass *mc = _meta[@(m)];
        if (mc == nil || mc.vtableAddress != 0) continue;
        mc.vtableAddress = [_vtableAddrs[vi] unsignedLongLongValue];
        mc.vtableSlots   = slots;
    }
}

#pragma mark - Output

- (NSString *)nameForMetaClassAddress:(uint64_t)addr;
{
    CDIOKitMetaClass *mc = _meta[@(addr)];
    return mc.name;
}

- (BOOL)writeHeadersForKext:(NSString *)kextID toDirectory:(NSString *)outDir error:(NSError **)error;
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:outDir]) {
        if (![fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    }

    NSMutableArray<CDIOKitMetaClass *> *classes = [NSMutableArray array];
    for (CDIOKitMetaClass *mc in [_meta allValues]) {
        if ([mc.kextID isEqualToString:kextID]) [classes addObject:mc];
    }
    if ([classes count] == 0) return YES;

    [classes sortUsingComparator:^NSComparisonResult(CDIOKitMetaClass *a, CDIOKitMetaClass *b) {
        return [a.name compare:b.name];
    }];

    for (CDIOKitMetaClass *mc in classes) {
        NSString *superName = [self nameForMetaClassAddress:mc.superMetaClassAddress];
        NSMutableString *s = [NSMutableString string];
        [s appendString:@"//\n//     Generated by class-dump 3.5 (64 bit) — IOKit OSMetaClass-derived view.\n"];
        [s appendFormat:@"//     Recovered from a stripped kernelcache; method names are unavailable.\n//\n\n"];
        [s appendFormat:@"// kext: %@\n", mc.kextID];
        [s appendFormat:@"// metaclass: 0x%llx", mc.metaClassAddress];
        if (mc.vtableAddress) [s appendFormat:@"   vtable: 0x%llx (%lu slots)", mc.vtableAddress, (unsigned long)[mc.vtableSlots count]];
        [s appendString:@"\n"];

        if (superName) {
            [s appendFormat:@"class %@ : %@ {\n", mc.name, superName];
        } else if (mc.superMetaClassAddress != 0) {
            [s appendFormat:@"class %@ /* : metaclass 0x%llx (unresolved) */ {\n", mc.name, mc.superMetaClassAddress];
        } else {
            [s appendFormat:@"class %@ {\n", mc.name];
        }
        [s appendFormat:@"    // instance size 0x%x (%u bytes)\n", mc.instanceSize, mc.instanceSize];

        if ([mc.vtableSlots count] > 0) {
            [s appendFormat:@"\n    // vtable (%lu slots; unnamed — cache is stripped):\n", (unsigned long)[mc.vtableSlots count]];
            NSUInteger idx = 0;
            for (NSNumber *slot in mc.vtableSlots) {
                [s appendFormat:@"    //   [%3lu] 0x%llx\n", (unsigned long)idx, [slot unsignedLongLongValue]];
                idx++;
            }
        }
        [s appendString:@"};\n"];

        NSString *fileName = [[mc.name stringByReplacingOccurrencesOfString:@"::" withString:@"_"]
                                       stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        fileName = [[fileName stringByReplacingOccurrencesOfString:@"<" withString:@"_"]
                              stringByReplacingOccurrencesOfString:@">" withString:@"_"];
        if ([fileName length] == 0) continue;
        NSString *path = [[outDir stringByAppendingPathComponent:fileName] stringByAppendingPathExtension:@"h"];
        if (![s writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:error]) return NO;
    }
    return YES;
}

@end
