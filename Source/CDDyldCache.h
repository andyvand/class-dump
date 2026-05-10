// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@interface CDDyldCacheImageInfo : NSObject

@property (nonatomic, readonly) uint64_t address;
@property (nonatomic, readonly) NSString *path;

@end

@interface CDDyldCache : NSObject

// Returns nil if `data` is not a recognizable dyld_shared_cache.
- (instancetype)initWithData:(NSData *)data;

// First 16 bytes, NUL-trimmed (e.g. "dyld_v1   arm64e").
@property (nonatomic, readonly) NSString *magic;

@property (nonatomic, readonly) uint32_t mappingCount;
@property (nonatomic, readonly) uint32_t mappingOffset;

// Image listing — empty if the cache uses a format we don't fully decode.
@property (nonatomic, readonly) NSArray<CDDyldCacheImageInfo *> *images;

// Best-effort platform extraction; 0 if not found.
@property (nonatomic, readonly) uint32_t platform;

// YES if the cache uses the old (pre-subcache) image table layout.
@property (nonatomic, readonly) BOOL usesLegacyImageTable;

// Read a NUL-terminated UTF-8 string from a cache vmaddr, walking the
// mapping table to translate vmaddr → file offset.
- (NSString *)stringAtAddress:(uint64_t)address;

// Read a 64-bit pointer slot at a cache vmaddr.
- (BOOL)readPointerAtAddress:(uint64_t)address into:(uint64_t *)outValue;

// YES if the cache has a mapping covering this vmaddr.
- (BOOL)containsAddress:(uint64_t)address;

@end
