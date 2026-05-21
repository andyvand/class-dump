// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.
//
//  Rebuilds a stand-alone Mach-O for a single LC_FILESET_ENTRY inside an
//  MH_FILESET kernel cache. Each kext's segments and shared __LINKEDIT slice
//  are copied out and the corresponding fileoffs in the load commands are
//  rewritten so the resulting file can be loaded by tools (Ghidra, otool,
//  jtool2) that don't understand the surrounding fileset container.

#import <Foundation/Foundation.h>

@class CDLCFilesetEntry;

extern NSString * const CDFilesetExtractorErrorDomain;

@interface CDFilesetExtractor : NSObject

// Extract the kext addressed by `entry` from `cacheData` (the bytes of the
// whole MH_FILESET kernel cache) and write the rebased stand-alone Mach-O
// to `outPath`. Returns YES on success; on failure populates `error` and
// writes nothing.
+ (BOOL)extractEntry:(CDLCFilesetEntry *)entry
           fromCache:(NSData *)cacheData
              toPath:(NSString *)outPath
               error:(NSError **)error;

@end
