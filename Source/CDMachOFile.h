// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDFile.h"

#include <mach/machine.h> // For cpu_type_t, cpu_subtype_t
#include <mach-o/loader.h>

typedef enum : NSUInteger {
    CDByteOrder_LittleEndian = 0,
    CDByteOrder_BigEndian = 1,
} CDByteOrder;

@class CDLCSegment;
@class CDLCBuildVersion, CDLCDyldInfo, CDLCDylib, CDMachOFile, CDLCSymbolTable, CDLCDynamicSymbolTable, CDLCVersionMinimum, CDLCSourceVersion;
@class CDDyldCache;

@interface CDMachOFile : CDFile

// Backing cache used to resolve addresses that fall outside this image's
// segments. Set when the image was extracted from a dyld_shared_cache so
// that selrefs / class refs / type strings that point into the cache's
// shared selector or class pools can still be read.
@property (strong) CDDyldCache *backingCache;

// Parses the mach-O image embedded at `headerOffset` bytes into `data`. Used
// for LC_FILESET_ENTRY kernelcaches where each contained image's mach_header
// sits at a known offset inside the parent file and the image's load
// commands carry parent-absolute file offsets (segment fileoff, symoff,
// stroff, …). Passing 0 is equivalent to the regular initializer.
- (id)initWithData:(NSData *)data
       headerOffset:(NSUInteger)headerOffset
           filename:(NSString *)filename
    searchPathState:(CDSearchPathState *)searchPathState;

@property (readonly) CDByteOrder byteOrder;

@property (readonly) const void *header;

@property (readonly) uint32_t magic;
@property (assign) cpu_type_t cputype;
@property (assign) cpu_subtype_t cpusubtype;
@property (readonly) uint32_t filetype;
@property (readonly) uint32_t flags;

@property (nonatomic, readonly) cpu_type_t maskedCPUType;
@property (nonatomic, readonly) cpu_subtype_t maskedCPUSubtype;

@property (readonly) NSArray *loadCommands;
@property (readonly) NSArray *dylibLoadCommands;
@property (readonly) NSArray *segments;
@property (readonly) NSArray *runPaths;
@property (readonly) NSArray *runPathCommands;
@property (readonly) NSArray *dyldEnvironment;
@property (readonly) NSArray *reExportedDylibs;

@property (strong) CDLCSymbolTable *symbolTable;
@property (strong) CDLCDynamicSymbolTable *dynamicSymbolTable;
@property (strong) CDLCDyldInfo *dyldInfo;
@property (strong) CDLCDylib *dylibIdentifier;
@property (strong) CDLCVersionMinimum *minVersionMacOSX;
@property (strong) CDLCVersionMinimum *minVersionIOS;
@property (strong) CDLCVersionMinimum *minVersionTVOS;
@property (strong) CDLCVersionMinimum *minVersionWatchOS;
@property (strong) CDLCSourceVersion *sourceVersion;
@property (strong) CDLCBuildVersion *buildVersion;

@property (readonly) BOOL uses64BitABI;
- (NSUInteger)ptrSize;

- (NSString *)filetypeDescription;
- (NSString *)flagDescription;

- (CDLCSegment *)dataConstSegment;
- (CDLCSegment *)segmentWithName:(NSString *)segmentName;
- (CDLCSegment *)segmentContainingAddress:(NSUInteger)address;
- (NSString *)stringAtAddress:(NSUInteger)address;

// Read a 64-bit value at a VM address, consulting the backing
// dyld_shared_cache if the address is outside this image's segments.
// Returns 0 if the address can't be resolved.
- (uint64_t)pointerAtAddress:(uint64_t)address;

// If `raw` already lies inside one of this image's segments or inside the
// backing dyld_shared_cache, returns it unchanged. Otherwise tries to decode
// it as a chained-fixup pointer encoding (the chain pass may have missed it —
// e.g. multi-chain start pages, or LC_DYLD_CHAINED_FIXUPS stripped by
// dsc_extractor) and returns the recovered VM address, or 0 if no plausible
// interpretation lands in a known segment / mapping.
- (uint64_t)resolvedAddressForRawValue:(uint64_t)raw;

- (NSUInteger)dataOffsetForAddress:(NSUInteger)address;

// Returns YES when `name` was read at `address` but doesn't appear to be the
// start of a complete selector — e.g. it's nil/empty, or `address` is in the
// middle of a printable C string whose true start is a few bytes earlier.
// Used by the small-method-list path in cache-extracted dylibs, where the
// stored relative offset can point a few bytes past the actual selector.
- (BOOL)nameLooksTruncated:(NSString *)name address:(uint64_t)address;

// Walk backward up to `maxBack` bytes from `address` looking for a NUL byte,
// then read a NUL-terminated string starting at the next position. Returns
// nil if `address` isn't inside a section/mapping that holds C strings, or
// if the bytes immediately before `address` aren't a plausible selector tail.
- (NSString *)selectorBySearchingBackwardFrom:(uint64_t)address maxBack:(NSUInteger)maxBack;

- (const void *)bytes;
- (const void *)bytesAtOffset:(NSUInteger)offset;

@property (nonatomic, readonly) NSString *importBaseName;

@property (nonatomic, readonly) BOOL isEncrypted;
@property (nonatomic, readonly) BOOL hasProtectedSegments;
@property (nonatomic, readonly) BOOL canDecryptAllSegments;

- (NSString *)loadCommandString:(BOOL)isVerbose;
- (NSString *)headerString:(BOOL)isVerbose;

@property (nonatomic, readonly) NSUUID *UUID;
@property (nonatomic, readonly) NSString *archName;

- (Class)processorClass;
- (void)logInfoForAddress:(NSUInteger)address;

- (NSString *)externalClassNameForAddress:(NSUInteger)address;
- (BOOL)hasRelocationEntryForAddress:(NSUInteger)address;

// Checks compressed dyld info on 10.6 or later.
- (BOOL)hasRelocationEntryForAddress2:(NSUInteger)address;
- (NSString *)externalClassNameForAddress2:(NSUInteger)address;

- (CDLCDylib *)dylibLoadCommandForLibraryOrdinal:(NSUInteger)ordinal;

@property (nonatomic, readonly) BOOL hasObjectiveC1Data;
@property (nonatomic, readonly) BOOL hasObjectiveC2Data;
@property (nonatomic, readonly) Class processorClass;

@end
