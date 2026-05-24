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

// Convenience: open the main cache file at `path`, then walk its subcache
// table and mmap each subcache sibling (`.01`, `.02.dylddata`, etc.) so
// `stringAtAddress:` and friends can resolve VM addresses that live in
// the split-out subcache files. Returns nil if `path` is unreadable or
// not a dyld_shared_cache; falls back to single-file behaviour when the
// header has no subcache table.
- (instancetype)initWithPath:(NSString *)path;

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

// Read up to `length` raw bytes at a cache vmaddr. Returns nil when the
// vmaddr isn't in any cache mapping or the read would run off the end of
// the backing slice. Useful for walk-back lookups where we need to inspect
// bytes immediately before a possibly-misaligned selector pointer.
- (NSData *)bytesAtAddress:(uint64_t)address length:(NSUInteger)length;

// Read a 64-bit pointer slot at a cache vmaddr.
- (BOOL)readPointerAtAddress:(uint64_t)address into:(uint64_t *)outValue;

// Read a 64-bit pointer slot at a cache vmaddr and decode it as a
// DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE chain pointer (the on-disk
// representation used by modern arm64e dyld_shared_caches). The returned
// value is the target VM address (`cacheBase + runtimeOffset`). Use this when
// chasing protocol/class descriptor pointers that live inside the cache —
// `readPointerAtAddress:` gives back the raw chain bits and is not directly
// dereferenceable.
- (BOOL)readResolvedPointerAtAddress:(uint64_t)address into:(uint64_t *)outValue;

// VM address of the cache's lowest mapping (i.e. the cache base). 0 if the
// mapping table is empty.
@property (nonatomic, readonly) uint64_t cacheBaseAddress;

// YES if the cache has a mapping covering this vmaddr.
- (BOOL)containsAddress:(uint64_t)address;

@end
