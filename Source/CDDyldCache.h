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

@end
