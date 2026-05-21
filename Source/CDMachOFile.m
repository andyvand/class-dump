// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDMachOFile.h"

#import <objc/runtime.h>

#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#import "CDMachOFileDataCursor.h"
#import "CDFatFile.h"
#import "CDLoadCommand.h"
#import "CDLCDyldInfo.h"
#import "CDLCDylib.h"
#import "CDLCDynamicSymbolTable.h"
#import "CDLCEncryptionInfo.h"
#import "CDLCRunPath.h"
#import "CDLCSegment.h"
#import "CDLCSymbolTable.h"
#import "CDLCUUID.h"
#import "CDLCVersionMinimum.h"
#import "CDObjectiveC1Processor.h"
#import "CDObjectiveC2Processor.h"
#import "CDSection.h"
#import "CDSymbol.h"
#import "CDRelocationInfo.h"
#import "CDSearchPathState.h"
#import "CDLCSourceVersion.h"
#import "CDLCBuildVersion.h"
#import "CDLCChainedFixups.h"
#import "CDDyldCache.h"

static NSString *CDMachOFileMagicNumberDescription(uint32_t magic)
{
    switch (magic) {
        case MH_MAGIC:    return @"MH_MAGIC";
        case MH_CIGAM:    return @"MH_CIGAM";
        case MH_MAGIC_64: return @"MH_MAGIC_64";
        case MH_CIGAM_64: return @"MH_CIGAM_64";
    }

    return [NSString stringWithFormat:@"0x%08x", magic];
}

@implementation CDMachOFile
{
    CDByteOrder _byteOrder;

    NSArray *_loadCommands;
    NSArray *_dylibLoadCommands;
    NSArray *_segments;
    const void *_header;
    CDLCSymbolTable *_symbolTable;
    CDLCDynamicSymbolTable *_dynamicSymbolTable;
    CDLCDyldInfo *_dyldInfo;
    CDLCDylib *_dylibIdentifier;
    CDLCVersionMinimum *_minVersionMacOSX;
    CDLCVersionMinimum *_minVersionIOS;
    CDLCVersionMinimum *_minVersionTVOS;
    CDLCVersionMinimum *_minVersionWatchOS;
    CDLCSourceVersion *_sourceVersion;
    CDLCBuildVersion *_buildVersion;
    NSArray *_runPaths;
    NSArray *_runPathCommands;
    NSArray *_dyldEnvironment;
    NSArray *_reExportedDylibs;

    // Non-zero when this image's mach_header lives at an offset inside its
    // backing NSData (used for LC_FILESET_ENTRY kernelcaches). Segment
    // fileoff/symoff/stroff values are still parent-absolute, so we keep
    // self.data pointing at the whole parent file and only shift the cursor
    // used to read the mach header + load commands.
    NSUInteger _sliceHeaderOffset;

    // The parts of struct mach_header_64 pulled out so that our property accessors can be synthesized.
	uint32_t _magic;
	cpu_type_t _cputype;
	cpu_subtype_t _cpusubtype;
	uint32_t _filetype;
	uint32_t _ncmds;
	uint32_t _sizeofcmds;
	uint32_t _flags;
	uint32_t _reserved;
    
    BOOL _uses64BitABI;
}

- (id)init;
{
    if ((self = [super init])) {
        _byteOrder = CDByteOrder_LittleEndian;
    }
    
    return self;
}

- (id)initWithData:(NSData *)data filename:(NSString *)filename searchPathState:(CDSearchPathState *)searchPathState;
{
    return [self initWithData:data headerOffset:0 filename:filename searchPathState:searchPathState];
}

- (id)initWithData:(NSData *)data
       headerOffset:(NSUInteger)headerOffset
           filename:(NSString *)filename
    searchPathState:(CDSearchPathState *)searchPathState;
{
    if ((self = [super initWithData:data filename:filename searchPathState:searchPathState])) {
        _byteOrder = CDByteOrder_LittleEndian;
        _sliceHeaderOffset = headerOffset;

        if (headerOffset >= [data length]) return nil;
        CDDataCursor *cursor = [[CDDataCursor alloc] initWithData:data];
        [cursor setOffset:headerOffset];
        _header = (const uint8_t *)[data bytes] + headerOffset;
        _magic = [cursor readBigInt32];
        if (_magic == MH_MAGIC || _magic == MH_MAGIC_64) {
            _byteOrder = CDByteOrder_BigEndian;
        } else if (_magic == MH_CIGAM || _magic == MH_CIGAM_64) {
            _byteOrder = CDByteOrder_LittleEndian;
        } else {
            return nil;
        }
        
        _uses64BitABI = (_magic == MH_MAGIC_64) || (_magic == MH_CIGAM_64);
        
        if (_byteOrder == CDByteOrder_LittleEndian) {
            _cputype    = [cursor readLittleInt32];
            _cpusubtype = [cursor readLittleInt32];
            _filetype   = [cursor readLittleInt32];
            _ncmds      = [cursor readLittleInt32];
            _sizeofcmds = [cursor readLittleInt32];
            _flags      = [cursor readLittleInt32];
            if (_uses64BitABI) {
                _reserved = [cursor readLittleInt32];
            }
        } else {
            _cputype    = [cursor readBigInt32];
            _cpusubtype = [cursor readBigInt32];
            _filetype   = [cursor readBigInt32];
            _ncmds      = [cursor readBigInt32];
            _sizeofcmds = [cursor readBigInt32];
            _flags      = [cursor readBigInt32];
            if (_uses64BitABI) {
                _reserved = [cursor readBigInt32];
            }
        }

        NSAssert(_uses64BitABI == CDArchUses64BitABI((CDArch){ .cputype = _cputype, .cpusubtype = _cpusubtype }), @"Header magic should match cpu arch", nil);
        
        NSUInteger headerSize = _uses64BitABI ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
        CDMachOFileDataCursor *fileCursor = [[CDMachOFileDataCursor alloc] initWithFile:self offset:_sliceHeaderOffset + headerSize];
        [self _readLoadCommands:fileCursor count:_ncmds];
    }

    return self;
}

- (void)_readLoadCommands:(CDMachOFileDataCursor *)cursor count:(uint32_t)count;
{
    NSMutableArray *loadCommands      = [[NSMutableArray alloc] init];
    NSMutableArray *dylibLoadCommands = [[NSMutableArray alloc] init];
    NSMutableArray *segments          = [[NSMutableArray alloc] init];
    NSMutableArray *runPaths          = [[NSMutableArray alloc] init];
    NSMutableArray *runPathCommands   = [[NSMutableArray alloc] init];
    NSMutableArray *dyldEnvironment   = [[NSMutableArray alloc] init];
    NSMutableArray *reExportedDylibs  = [[NSMutableArray alloc] init];
    
    for (uint32_t index = 0; index < count; index++) {
        CDLoadCommand *loadCommand = [CDLoadCommand loadCommandWithDataCursor:cursor];
        if (loadCommand != nil) {
            [loadCommands addObject:loadCommand];

            if (loadCommand.cmd == LC_VERSION_MIN_MACOSX)                        self.minVersionMacOSX = (CDLCVersionMinimum *)loadCommand;
            if (loadCommand.cmd == LC_VERSION_MIN_IPHONEOS)                      self.minVersionIOS = (CDLCVersionMinimum *)loadCommand;
            if (loadCommand.cmd == LC_VERSION_MIN_TVOS)
                self.minVersionTVOS = (CDLCVersionMinimum *)loadCommand;
            if (loadCommand.cmd == LC_VERSION_MIN_WATCHOS)
                self.minVersionWatchOS = (CDLCVersionMinimum *)loadCommand;
            if (loadCommand.cmd == LC_DYLD_ENVIRONMENT)                          [dyldEnvironment addObject:loadCommand];
            if (loadCommand.cmd == LC_REEXPORT_DYLIB)                            [reExportedDylibs addObject:loadCommand];
            if (loadCommand.cmd == LC_ID_DYLIB)                                  self.dylibIdentifier = (CDLCDylib *)loadCommand;

            if ([loadCommand isKindOfClass:[CDLCSourceVersion class]])           self.sourceVersion = (CDLCSourceVersion *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCBuildVersion class]])       self.buildVersion = (CDLCBuildVersion *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCDylib class]])              [dylibLoadCommands addObject:loadCommand];
            else if ([loadCommand isKindOfClass:[CDLCSegment class]])            [segments addObject:loadCommand];
            else if ([loadCommand isKindOfClass:[CDLCSymbolTable class]])        self.symbolTable = (CDLCSymbolTable *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCDynamicSymbolTable class]]) self.dynamicSymbolTable = (CDLCDynamicSymbolTable *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCDyldInfo class]])           self.dyldInfo = (CDLCDyldInfo *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCRunPath class]]) {
                [runPaths addObject:[(CDLCRunPath *)loadCommand resolvedRunPath]];
                [runPathCommands addObject:loadCommand];
            }
        }
        //NSLog(@"loadCommand: %@", loadCommand);
    }
    _loadCommands      = [loadCommands copy];
    _dylibLoadCommands = [dylibLoadCommands copy];
    _segments          = [segments copy];
    _runPaths          = [runPaths copy];
    _runPathCommands   = [runPathCommands copy];
    _dyldEnvironment   = [dyldEnvironment copy];
    _reExportedDylibs  = [reExportedDylibs copy];

    for (CDLoadCommand *loadCommand in _loadCommands) {
        [loadCommand machOFileDidReadLoadCommands:self];
    }

    [self applyChainedFixupsIfAny];
}

- (void)applyChainedFixupsIfAny;
{
    // When we're a sub-image embedded in a kernelcache (LC_FILESET_ENTRY), we
    // share the parent file's data and the parent owns any chained-fixup
    // table. Rewriting it per entry would both mutate state we don't own and
    // re-apply fixups already applied for the cache as a whole.
    if (_sliceHeaderOffset != 0) return;

    CDLCChainedFixups *cf = nil;
    for (CDLoadCommand *lc in _loadCommands) {
        if ([lc isKindOfClass:[CDLCChainedFixups class]]) { cf = (CDLCChainedFixups *)lc; break; }
    }

    uint64_t imageBase = 0;
    for (CDLCSegment *seg in _segments) {
        if ([seg.name isEqualToString:@"__TEXT"]) { imageBase = (uint64_t)seg.vmaddr; break; }
    }

    if (cf != nil) {
        NSMutableData *mutable = [self.data mutableCopy];
        if (mutable == nil) return;
        [cf applyToMutableData:mutable imageBase:imageBase];
        [self setResolvedData:[mutable copy]];
        return;
    }

    // No LC_DYLD_CHAINED_FIXUPS — but the data may still contain raw chain
    // bits if this image was extracted from a dyld_shared_cache by
    // `dsc_extractor.bundle` (which strips the LC). Detect that by sniffing a
    // few __DATA* slots; if any look chain-encoded, do a brute-force rewrite.
    if ([self _looksLikeUnappliedChainData]) {
        NSMutableData *mutable = [self.data mutableCopy];
        if (mutable == nil) return;
        [self _heuristicallyRewriteChainSlotsIn:mutable imageBase:imageBase];
        [self setResolvedData:[mutable copy]];
    }
}

- (BOOL)_looksLikeUnappliedChainData;
{
    // Sample the first 8-byte slot of every __DATA*/__AUTH* segment. If any
    // contains a value with the upper 16 bits non-zero AND the value is not
    // itself a valid VM address inside the image, treat the image as having
    // unresolved chain bits.
    const uint8_t *bytes = (const uint8_t *)[self.data bytes];
    NSUInteger len = [self.data length];
    for (CDLCSegment *seg in _segments) {
        NSString *n = seg.name;
        if (![n isEqualToString:@"__DATA"]
            && ![n isEqualToString:@"__DATA_CONST"]
            && ![n isEqualToString:@"__DATA_DIRTY"]
            && ![n isEqualToString:@"__AUTH"]
            && ![n isEqualToString:@"__AUTH_CONST"]) continue;
        NSUInteger off = seg.fileoff;
        NSUInteger end = off + MIN(seg.filesize, (NSUInteger)0x100);
        if (end > len) end = len;
        for (NSUInteger i = off; i + 8 <= end; i += 8) {
            uint64_t v;
            memcpy(&v, bytes + i, 8);
            if (v == 0) continue;
            if ((v >> 48) == 0) continue; // top 16 clear → not chain-encoded
            if ([self segmentContainingAddress:(NSUInteger)v]) continue;
            return YES;
        }
    }
    return NO;
}

- (uint64_t)_resolveChainSlot:(uint64_t)raw imageBase:(uint64_t)imageBase cacheBase:(uint64_t)cacheBase;
{
    // Apply the same candidate-address probing as dataOffsetForAddress:'s
    // fallback. Returns the resolved VM address (which lies inside one of our
    // segments OR inside the backing dyld_shared_cache) or 0 if we can't
    // decode this slot.
    const uint64_t kTarget30 = 0x3FFFFFFFULL;        // arm64e SHARED_CACHE
    const uint64_t kTarget32 = 0xFFFFFFFFULL;        // arm64e auth_rebase
    const uint64_t kTarget36 = 0xFFFFFFFFFULL;       // _64 / _64_OFFSET
    const uint64_t kTarget43 = 0x7FFFFFFFFFFULL;     // arm64e USERLAND
    const uint64_t kAddr47   = 0x7FFFFFFFFFFFULL;    // PAC-stripped canonical

    uint64_t candidates[10] = {
        // Try most-restrictive masks first (modern caches use small targets);
        // wider masks would otherwise produce a "near-miss" address that lands
        // on a neighbouring string and looks plausible.
        cacheBase + (raw & kTarget30),
        imageBase + (raw & kTarget30),
        cacheBase + (raw & kTarget32),
        imageBase + (raw & kTarget32),
        cacheBase + (raw & kTarget36),
        imageBase + (raw & kTarget36),
        cacheBase + (raw & kTarget43),
        imageBase + (raw & kTarget43),
        raw & kAddr47,
        raw & 0x0000FFFFFFFFFFFFULL,
    };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        if (candidates[i] == 0 || candidates[i] == raw) continue;
        if ([self segmentContainingAddress:(NSUInteger)candidates[i]]) {
            return candidates[i];
        }
        if (self.backingCache && [self.backingCache containsAddress:candidates[i]]) {
            return candidates[i];
        }
    }
    return 0;
}

- (void)_heuristicallyRewriteChainSlotsIn:(NSMutableData *)mutable imageBase:(uint64_t)imageBase;
{
    uint64_t cacheBase = imageBase & 0xFFFFFFFF80000000ULL;
    uint8_t *bytes = (uint8_t *)[mutable mutableBytes];
    NSUInteger len = [mutable length];
    NSUInteger rewroteToImage = 0, rewroteToCache = 0;

    for (CDLCSegment *seg in _segments) {
        NSString *n = seg.name;
        if (![n isEqualToString:@"__DATA"]
            && ![n isEqualToString:@"__DATA_CONST"]
            && ![n isEqualToString:@"__DATA_DIRTY"]
            && ![n isEqualToString:@"__AUTH"]
            && ![n isEqualToString:@"__AUTH_CONST"]) continue;

        NSUInteger off = seg.fileoff;
        NSUInteger end = off + seg.filesize;
        if (end > len) end = len;
        for (NSUInteger i = off; i + 8 <= end; i += 8) {
            uint64_t v;
            memcpy(&v, bytes + i, 8);
            if (v == 0) continue;
            if ((v >> 48) == 0) {
                // Already looks like a clean VM address — leave alone.
                continue;
            }
            uint64_t resolved = [self _resolveChainSlot:v imageBase:imageBase cacheBase:cacheBase];
            if (resolved == 0) continue;
            memcpy(bytes + i, &resolved, 8);
            if ([self segmentContainingAddress:(NSUInteger)resolved]) rewroteToImage++;
            else rewroteToCache++;
        }
    }
    NSLog(@"chain-heuristic: rewrote %lu slots to image, %lu to cache",
          (unsigned long)rewroteToImage, (unsigned long)rewroteToCache);
}

- (void)setBackingCache:(CDDyldCache *)cache;
{
    Ivar ivar = class_getInstanceVariable([CDMachOFile class], "_backingCache");
    if (ivar) object_setIvar(self, ivar, cache);
    // Re-run chain resolution now that more candidate-address pools exist.
    if (cache) {
        NSLog(@"CDMachOFile: re-running chain fixups with cache backing");
        [self applyChainedFixupsIfAny];
    }
}

- (void)setResolvedData:(NSData *)data;
{
    // _data is declared in CDFile's @implementation block (@protected). Use
    // the runtime to set it without exposing a public setter.
    Ivar dataIvar = class_getInstanceVariable([CDFile class], "_data");
    if (dataIvar) object_setIvar(self, dataIvar, data);
}

#pragma mark - Debugging

- (NSString *)description;
{
    return [NSString stringWithFormat:@"<%@:%p> magic: 0x%08x, cputype: %x, cpusubtype: %x, filetype: %d, ncmds: %ld, sizeofcmds: %d, flags: 0x%x, uses64BitABI? %d, filename: %@, data: %p",
            NSStringFromClass([self class]), self,
            [self magic], [self cputype], [self cpusubtype], [self filetype], [_loadCommands count], 0, [self flags], self.uses64BitABI,
            self.filename, self.data];
}

#pragma mark -

- (CDMachOFile *)machOFileWithArch:(CDArch)arch;
{
    if (self.cputype == arch.cputype && self.maskedCPUSubtype == (arch.cpusubtype & ~CPU_SUBTYPE_MASK))
        return self;

    return nil;
}

#pragma mark -

- (cpu_type_t)maskedCPUType;
{
    return self.cputype & ~CPU_ARCH_MASK;
}

- (cpu_subtype_t)maskedCPUSubtype;
{
    return self.cpusubtype & ~CPU_SUBTYPE_MASK;
}

- (NSUInteger)ptrSize;
{
    return self.uses64BitABI ? sizeof(uint64_t) : sizeof(uint32_t);
}
             
// We only have one architecture, so it is by default the best match.  
- (BOOL)bestMatchForArch:(CDArch *)ioArchPtr;
{
    if (ioArchPtr != NULL) {
        ioArchPtr->cputype    = self.cputype;
        ioArchPtr->cpusubtype = self.cpusubtype;
    }

    return YES;
}

- (NSString *)filetypeDescription;
{
    switch ([self filetype]) {
        case MH_OBJECT:      return @"OBJECT";
        case MH_EXECUTE:     return @"EXECUTE";
        case MH_FVMLIB:      return @"FVMLIB";
        case MH_CORE:        return @"CORE";
        case MH_PRELOAD:     return @"PRELOAD";
        case MH_DYLIB:       return @"DYLIB";
        case MH_DYLINKER:    return @"DYLINKER";
        case MH_BUNDLE:      return @"BUNDLE";
        case MH_DYLIB_STUB:  return @"DYLIB_STUB";
        case MH_DSYM:        return @"DSYM";
        case MH_KEXT_BUNDLE: return @"KEXT_BUNDLE";
        default:
            break;
    }

    return nil;
}

- (NSString *)flagDescription;
{
    NSMutableArray *setFlags = [NSMutableArray array];
    uint32_t flags = [self flags];
    if (flags & MH_NOUNDEFS)                [setFlags addObject:@"NOUNDEFS"];
    if (flags & MH_INCRLINK)                [setFlags addObject:@"INCRLINK"];
    if (flags & MH_DYLDLINK)                [setFlags addObject:@"DYLDLINK"];
    if (flags & MH_BINDATLOAD)              [setFlags addObject:@"BINDATLOAD"];
    if (flags & MH_PREBOUND)                [setFlags addObject:@"PREBOUND"];
    if (flags & MH_SPLIT_SEGS)              [setFlags addObject:@"SPLIT_SEGS"];
    if (flags & MH_LAZY_INIT)               [setFlags addObject:@"LAZY_INIT"];
    if (flags & MH_TWOLEVEL)                [setFlags addObject:@"TWOLEVEL"];
    if (flags & MH_FORCE_FLAT)              [setFlags addObject:@"FORCE_FLAT"];
    if (flags & MH_NOMULTIDEFS)             [setFlags addObject:@"NOMULTIDEFS"];
    if (flags & MH_NOFIXPREBINDING)         [setFlags addObject:@"NOFIXPREBINDING"];
    if (flags & MH_PREBINDABLE)             [setFlags addObject:@"PREBINDABLE"];
    if (flags & MH_ALLMODSBOUND)            [setFlags addObject:@"ALLMODSBOUND"];
    if (flags & MH_SUBSECTIONS_VIA_SYMBOLS) [setFlags addObject:@"SUBSECTIONS_VIA_SYMBOLS"];
    if (flags & MH_CANONICAL)               [setFlags addObject:@"CANONICAL"];
    if (flags & MH_WEAK_DEFINES)            [setFlags addObject:@"WEAK_DEFINES"];
    if (flags & MH_BINDS_TO_WEAK)           [setFlags addObject:@"BINDS_TO_WEAK"];
    if (flags & MH_ALLOW_STACK_EXECUTION)   [setFlags addObject:@"ALLOW_STACK_EXECUTION"];
    if (flags & MH_ROOT_SAFE)               [setFlags addObject:@"ROOT_SAFE"];
    if (flags & MH_SETUID_SAFE)             [setFlags addObject:@"SETUID_SAFE"];
    if (flags & MH_NO_REEXPORTED_DYLIBS)    [setFlags addObject:@"NO_REEXPORTED_DYLIBS"];
    if (flags & MH_PIE)                     [setFlags addObject:@"PIE"];

    return [setFlags componentsJoinedByString:@" "];
}

#pragma mark -

- (CDLCSegment *)dataConstSegment
{
    // macho objects from iOS 9 appear to store various sections
    // in __DATA_CONST that were previously found in __DATA
    CDLCSegment *seg = [self segmentWithName:@"__DATA_CONST"];

    // Fall back on __DATA if it is not found for earlier behavior
    if (!seg) {
        seg = [self segmentWithName:@"__DATA"];
    }
    return seg;
}

- (CDLCSegment *)segmentWithName:(NSString *)segmentName;
{
    for (id loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [[loadCommand name] isEqual:segmentName]) {
            return loadCommand;
        }
    }

    return nil;
}

- (CDLCSegment *)segmentContainingAddress:(NSUInteger)address;
{
    for (id loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [loadCommand containsAddress:address]) {
            return loadCommand;
        }
    }

    return nil;
}

- (void)showWarning:(NSString *)warning;
{
    NSLog(@"Warning: %@", warning);
}

- (uint64_t)pointerAtAddress:(uint64_t)address;
{
    if (address == 0) return 0;
    NSUInteger off = [self dataOffsetForAddress:(NSUInteger)address];
    if (off != 0 && off + 8 <= [self.data length]) {
        uint64_t v;
        memcpy(&v, (const uint8_t *)[self.data bytes] + off, 8);
        static int n = 0; if (n < 5) { NSLog(@"pointerAtAddress(0x%llx) [self] -> 0x%llx", address, v); n++; }
        return v;
    }
    if (self.backingCache) {
        uint64_t v = 0;
        if ([self.backingCache readPointerAtAddress:address into:&v]) {
            static int n = 0; if (n < 5) { NSLog(@"pointerAtAddress(0x%llx) [cache] -> 0x%llx", address, v); n++; }
            return v;
        }
    }
    return 0;
}

- (NSString *)stringAtAddress:(NSUInteger)address;
{
    const void *ptr;

    if (address == 0)
        return nil;

    CDLCSegment *segment = [self segmentContainingAddress:address];
    if (segment == nil) {
        // Resolve via the same chain-pointer heuristics used in
        // dataOffsetForAddress: (cache-base + 36/43-bit target, etc.).
        NSUInteger resolved = [self dataOffsetForAddress:address];
        if (resolved == 0) {
            // Last resort: ask the backing dyld_shared_cache. Selectors and
            // type strings for cache-extracted dylibs frequently live in the
            // cache's shared selector pool.
            if (self.backingCache) {
                NSString *s = [self.backingCache stringAtAddress:(uint64_t)address];
                if (s) return s;
            }
            return nil;
        }
        const uint8_t *p = (const uint8_t *)[self.data bytes] + resolved;
        return [[NSString alloc] initWithBytes:p length:strlen((const char *)p) encoding:NSASCIIStringEncoding];
    }

    if ([segment isProtected]) {
        NSData *d2 = [segment decryptedData];
        NSUInteger d2Offset = [segment segmentOffsetForAddress:address];
        if (d2Offset == 0)
            return nil;

        ptr = (uint8_t *)[d2 bytes] + d2Offset;
        return [[NSString alloc] initWithBytes:ptr length:strlen(ptr) encoding:NSASCIIStringEncoding];
    }

    NSUInteger offset = [self dataOffsetForAddress:address];
    if (offset == 0)
        return nil;

    ptr = (uint8_t *)[self.data bytes] + offset;

    return [[NSString alloc] initWithBytes:ptr length:strlen(ptr) encoding:NSASCIIStringEncoding];
}

- (NSUInteger)dataOffsetForAddress:(NSUInteger)address;
{
    if (address == 0)
        return 0;

    CDLCSegment *segment = [self segmentContainingAddress:address];
    if (segment == nil) {
        // dsc_extractor leaves raw arm64e USERLAND chained-fixup bits in
        // __DATA* without preserving an LC_DYLD_CHAINED_FIXUPS to describe
        // them. The pointer formats use a 36- or 43-bit target encoded against
        // a base address (image __TEXT vmaddr or shared-cache base). Probe a
        // small set of likely interpretations; first hit that lands in a
        // segment wins.
        uint64_t imageBase = 0;
        for (CDLCSegment *seg in self.segments) {
            if ([seg.name isEqualToString:@"__TEXT"]) { imageBase = (uint64_t)seg.vmaddr; break; }
        }
        // Round __TEXT vmaddr down to a 2 GB boundary — modern shared caches
        // are loaded at fixed 2 GB-aligned bases, e.g. 0x180000000 on arm64
        // macOS. Each cached image's __TEXT lives within `cacheBase + 2 GB`.
        uint64_t cacheBase = imageBase & 0xFFFFFFFF80000000ULL;

        const uint64_t kTarget30 = 0x3FFFFFFFULL;
        const uint64_t kTarget32 = 0xFFFFFFFFULL;
        const uint64_t kTarget36 = 0xFFFFFFFFFULL;
        const uint64_t kTarget43 = 0x7FFFFFFFFFFULL;
        const uint64_t kAddr47   = 0x7FFFFFFFFFFFULL;

        NSUInteger candidates[10];
        candidates[0] = (NSUInteger)(cacheBase + (address & kTarget30));
        candidates[1] = (NSUInteger)(imageBase + (address & kTarget30));
        candidates[2] = (NSUInteger)(cacheBase + (address & kTarget32));
        candidates[3] = (NSUInteger)(imageBase + (address & kTarget32));
        candidates[4] = (NSUInteger)(cacheBase + (address & kTarget36));
        candidates[5] = (NSUInteger)(imageBase + (address & kTarget36));
        candidates[6] = (NSUInteger)(cacheBase + (address & kTarget43));
        candidates[7] = (NSUInteger)(imageBase + (address & kTarget43));
        candidates[8] = (NSUInteger)(address & kAddr47);
        candidates[9] = (NSUInteger)(address & 0x0000FFFFFFFFFFFFULL);

        for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
            if (candidates[i] == 0 || candidates[i] == address) continue;
            CDLCSegment *cand = [self segmentContainingAddress:candidates[i]];
            if (cand) { segment = cand; address = candidates[i]; goto found; }
        }
        // Hush — the printed error before exit was making valid invocations
        // look broken. Callers handle a 0 return gracefully.
        return 0;
    }
found:

//    if ([segment isProtected]) {
//        NSLog(@"Error: Segment is protected.");
//        exit(5);
//    }

#if 0
    NSLog(@"---------->");
    NSLog(@"segment is: %@", segment);
    NSLog(@"address: 0x%08x", address);
    NSLog(@"CDFile offset:    0x%08x", offset);
    NSLog(@"file off for address: 0x%08x", [segment fileOffsetForAddress:address]);
    NSLog(@"data offset:      0x%08x", offset + [segment fileOffsetForAddress:address]);
    NSLog(@"<----------");
#endif
    return [segment fileOffsetForAddress:address];
}

- (const void *)bytes;
{
    return [self.data bytes];
}

- (const void *)bytesAtOffset:(NSUInteger)offset;
{
    return (uint8_t *)[self.data bytes] + offset;
}

- (NSString *)importBaseName;
{
    if ([self filetype] == MH_DYLIB) {
        return CDImportNameForPath(self.filename);
    }

    return nil;
}

#pragma mark -

- (BOOL)isEncrypted;
{
    for (CDLoadCommand *loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCEncryptionInfo class]] && [(CDLCEncryptionInfo *)loadCommand isEncrypted]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)hasProtectedSegments;
{
    for (CDLoadCommand *loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [(CDLCSegment *)loadCommand isProtected])
            return YES;
    }

    return NO;
}

- (BOOL)canDecryptAllSegments;
{
    for (CDLoadCommand *loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [(CDLCSegment *)loadCommand canDecrypt] == NO)
            return NO;
    }

    return YES;
}

- (NSString *)loadCommandString:(BOOL)isVerbose;
{
    NSMutableString *resultString = [NSMutableString string];
    NSUInteger count = [_loadCommands count];
    for (NSUInteger index = 0; index < count; index++) {
        [resultString appendFormat:@"Load command %lu\n", index];
        CDLoadCommand *loadCommand = _loadCommands[index];
        [loadCommand appendToString:resultString verbose:isVerbose];
        [resultString appendString:@"\n"];
    }

    return resultString;
}

- (NSString *)headerString:(BOOL)isVerbose;
{
    NSMutableString *resultString = [NSMutableString string];
    [resultString appendString:@"Mach header\n"];
    [resultString appendString:@"      magic cputype cpusubtype   filetype ncmds sizeofcmds      flags\n"];
    // Grr, %11@ doesn't work.
    if (isVerbose)
        [resultString appendFormat:@"%11@ %7@ %10u   %8@ %5lu %10u %@\n",
                      CDMachOFileMagicNumberDescription([self magic]), [self archName], [self cpusubtype],
                      [self filetypeDescription], [_loadCommands count], 0, [self flagDescription]];
    else
        [resultString appendFormat:@" 0x%08x %7u %10u   %8u %5lu %10u 0x%08x\n",
                      [self magic], [self cputype], [self cpusubtype], [self filetype], [_loadCommands count], 0, [self flags]];
    [resultString appendString:@"\n"];

    return resultString;
}

- (NSUUID *)UUID;
{
    for (CDLoadCommand *loadCommand in _loadCommands)
        if ([loadCommand isKindOfClass:[CDLCUUID class]])
            return [(CDLCUUID *)loadCommand UUID];

    return nil;
}

// Must not return nil.
- (NSString *)archName;
{
    return CDNameForCPUType([self cputype], [self cpusubtype]);
}

- (void)logInfoForAddress:(NSUInteger)address;
{
    if (address != 0) {
        CDLCSegment *segment = [self segmentContainingAddress:address];
        if (segment == nil) {
            NSLog(@"No segment contains address: %016lx", address);
        } else {
            //NSLog(@"Found address %016lx in segment, sections= %@", address, [segment sections]);
            CDSection *section = [segment sectionContainingAddress:address];
            if (section == nil) {
                NSLog(@"Found address %016lx in segment %@, but not in a section", address, [segment name]);
            } else {
                NSLog(@"Found address %016lx in segment %@, section %@", address, [segment name], [section sectionName]);
            }
        }

        NSString *str = [self stringAtAddress:address];
        NSLog(@"      address %016lx as a string: '%@' (length %lu)", address, str, [str length]);
        NSLog(@"      address %016lx data offset: %lu", address, [self dataOffsetForAddress:address]);
    }
}

- (NSString *)externalClassNameForAddress:(NSUInteger)address;
{
    // Not for NSCFArray (NSMutableArray), NSSimpleAttributeDictionaryEnumerator (NSEnumerator), NSSimpleAttributeDictionary (NSDictionary), etc.
    // It turns out NSMutableArray is in /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation, so...
    // ... it's an undefined symbol, need to look it up.
    CDRelocationInfo *rinfo = [self.dynamicSymbolTable relocationEntryWithOffset:address - [self.symbolTable baseAddress]];
    //NSLog(@"rinfo: %@", rinfo);
    if (rinfo != nil) {
        CDSymbol *symbol = [[self.symbolTable symbols] objectAtIndex:rinfo.symbolnum];
        //NSLog(@"symbol: %@", symbol);

        // Now we could use GET_LIBRARY_ORDINAL(), look up the the appropriate mach-o file (being sure to have loaded them even without -r),
        // look up the symbol in that mach-o file, get the address, look up the class based on that address, and finally get the class name
        // from that.

        // Or, we could be lazy and take advantage of the fact that the class name we're after is in the symbol name:
        NSString *str = [symbol name];
        if ([str hasPrefix:ObjCClassSymbolPrefix]) {
            return [str substringFromIndex:[ObjCClassSymbolPrefix length]];
        } else {
            NSLog(@"Warning: Unknown prefix on symbol name... %@ (addr %lx)", str, address);
            return str;
        }
    }

    // This is fine, they might really be root objects.  NSObject, NSProxy.
    return nil;
}

- (BOOL)hasRelocationEntryForAddress:(NSUInteger)address;
{
    CDRelocationInfo *rinfo = [self.dynamicSymbolTable relocationEntryWithOffset:address - [self.symbolTable baseAddress]];
    //NSLog(@"%s, rinfo= %@", __cmd, rinfo);
    return rinfo != nil;
}

- (BOOL)hasRelocationEntryForAddress2:(NSUInteger)address;
{
    return [self.dyldInfo symbolNameForAddress:address] != nil;
}

- (NSString *)externalClassNameForAddress2:(NSUInteger)address;
{
    NSString *str = [self.dyldInfo symbolNameForAddress:address];

    if (str != nil) {
        if ([str hasPrefix:ObjCClassSymbolPrefix]) {
            return [str substringFromIndex:[ObjCClassSymbolPrefix length]];
        } else {
            NSLog(@"Warning: Unknown prefix on symbol name... %@ (addr %lx)", str, address);
            return str;
        }
    }

    return nil;
}

- (BOOL)hasObjectiveC1Data;
{
    return [self segmentWithName:@"__OBJC"] != nil;
}

- (BOOL)hasObjectiveC2Data;
{
    // http://twitter.com/gparker/status/17962955683
    // Oxced: What's the best way to determine the ObjC ABI version of a file?  otool tests if cputype is ARM, but that's not accurate with iOS 4 simulator
    // gparker: @0xced Old ABI has an __OBJC segment. New ABI has a __DATA,__objc_info section.
    // 0xced: @gparker I was hoping for a flag, but that will do it, thanks.
    // 0xced: @gparker Did you mean __DATA,__objc_imageinfo instead of __DATA,__objc_info ?
    // gparker: @0xced Yes, it's __DATA,__objc_imageinfo.
    return [[self dataConstSegment] sectionWithName:@"__objc_imageinfo"] != nil;
}

- (Class)processorClass;
{
    if ([self hasObjectiveC2Data])
        return [CDObjectiveC2Processor class];
    
    return [CDObjectiveC1Processor class];
}

- (CDLCDylib *)dylibLoadCommandForLibraryOrdinal:(NSUInteger)libraryOrdinal;
{
    if (libraryOrdinal == SELF_LIBRARY_ORDINAL || libraryOrdinal >= MAX_LIBRARY_ORDINAL)
        return nil;
    
    NSArray *loadCommands = _dylibLoadCommands;
    if (_dylibIdentifier != nil) {
        // Remove our own ID (LC_ID_DYLIB) so that we calculate the correct offset
        NSMutableArray *remainingLoadCommands = [loadCommands mutableCopy];
        [remainingLoadCommands removeObject:_dylibIdentifier];
        loadCommands = remainingLoadCommands;
    }
    
    if (libraryOrdinal - 1 < [loadCommands count]) // Ordinals start from 1
        return loadCommands[libraryOrdinal - 1];
    else
        return nil;
}

- (NSString *)architectureNameDescription;
{
    return self.archName;
}

@end
