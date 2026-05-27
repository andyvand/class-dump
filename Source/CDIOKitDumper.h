// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@class CDMachOFile;
@class CDLCFilesetEntry;

// Recovers the IOKit / libkern C++ class hierarchy from an MH_FILESET
// kernelcache that has been stripped of its nlist symbol table.
//
// Modern release kernelcaches carry no LC_SYMTAB symbols, so the symbol-based
// C++ dumper (CDCPlusPlusDumper) has nothing to read. The class hierarchy is
// however still discoverable from the OSMetaClass runtime metadata: every
// libkern class registers itself by invoking
//
//     OSMetaClass::OSMetaClass(const char *className,
//                              const OSMetaClass *superClass,
//                              unsigned int classSize)
//
// from a static constructor listed in the kext's __mod_init_func. By
// disassembling each constructor we recover (metaClass, className, superClass,
// instanceSize); linking metaClass -> superClass by address reconstructs the
// inheritance graph, including cross-kext edges (e.g. a driver deriving from
// IOService in the kernel). Class vtables are then located in __DATA*.__const
// by matching each candidate vtable's getMetaClass() slot back to a known
// metaclass.
//
// The recovered information is class name, superclass, instance size and the
// vtable slot count/addresses. Method names cannot be recovered from a stripped
// cache (no symbols), so vtable slots are emitted as unnamed addresses.
@interface CDIOKitMetaClass : NSObject
@property (nonatomic, assign) uint64_t metaClassAddress;
@property (nonatomic, assign) uint64_t superMetaClassAddress;
@property (nonatomic, copy)   NSString *name;
@property (nonatomic, assign) uint32_t  instanceSize;
@property (nonatomic, copy)   NSString *kextID;
@property (nonatomic, assign) uint64_t  vtableAddress;     // 0 when not found
@property (nonatomic, strong) NSArray<NSNumber *> *vtableSlots; // function addresses
@end

@interface CDIOKitDumper : NSObject

// `cacheData` is the whole (already decompressed) kernelcache; `topLevel` is
// the MH_FILESET Mach-O whose segments map the entire cache.
- (instancetype)initWithCacheData:(NSData *)cacheData topLevel:(CDMachOFile *)topLevel;

// Scan every fileset entry's constructors, building the global metaclass map,
// then recover vtables. `entries` are the LC_FILESET_ENTRY load commands.
- (void)scanFilesetEntries:(NSArray<CDLCFilesetEntry *> *)entries;

// Number of classes recovered (for progress reporting).
@property (nonatomic, readonly) NSUInteger metaClassCount;

// Write one header per recovered class belonging to `kextID` into `outDir`.
// Returns YES even if the kext has no recovered classes (writes nothing).
- (BOOL)writeHeadersForKext:(NSString *)kextID toDirectory:(NSString *)outDir error:(NSError **)error;

@end
