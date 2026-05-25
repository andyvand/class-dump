// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@interface CDDyldCacheImageInfo : NSObject

@property (nonatomic, readonly) uint64_t address;
@property (nonatomic, readonly) NSString *path;

@end

// Description of one mapping region inside a single slice of a split
// dyld_shared_cache. Modern caches use `dyld_cache_mapping_and_slide_info`
// where `flags` distinguishes __TEXT_STUBS / __DATA_DIRTY / __DATA_CONST /
// __TPRO_CONST / __AUTH / __READ_ONLY etc. We surface the same string here
// so callers can print a human-friendly region map.
@interface CDDyldCacheMappingInfo : NSObject
@property (nonatomic, readonly) uint64_t address;
@property (nonatomic, readonly) uint64_t size;
@property (nonatomic, readonly) uint64_t fileOffset;
@property (nonatomic, readonly) uint32_t maxProt;
@property (nonatomic, readonly) uint32_t initProt;
@property (nonatomic, readonly) uint64_t flags;     // 0 for legacy mappings
@property (nonatomic, readonly) NSString *name;     // e.g. __TEXT, __LINKEDIT
@end

// Description of one subcache file that's been merged into the in-memory
// view. The "main" cache (the one originally opened) shows up here too with
// an empty `suffix`.
@interface CDDyldCacheSubcacheInfo : NSObject
@property (nonatomic, readonly) NSString *path;           // backing file path (nil for main if loaded from data)
@property (nonatomic, readonly) NSString *suffix;         // e.g. ".01.dylddata", "" for main
@property (nonatomic, readonly) NSString *uuid;           // upper-case canonical UUID, or @"" if unknown
@property (nonatomic, readonly) uint64_t  vmOffset;       // unslid offset from cache base (0 for main)
@property (nonatomic, readonly) uint64_t  fileSize;       // bytes
@property (nonatomic, readonly) NSArray<CDDyldCacheMappingInfo *> *mappings;
@end

@interface CDDyldCache : NSObject

// Returns nil if `data` is not a recognizable dyld_shared_cache.
- (instancetype)initWithData:(NSData *)data;

// Convenience: open the main cache file at `path`, then walk its subcache
// table and mmap each subcache sibling (`.01`, `.02.dylddata`,
// `.03.dyldreadonly`, `.04.dyldlinkedit`, etc.) so `stringAtAddress:` and
// friends can resolve VM addresses that live in the split-out subcache
// files. Returns nil if `path` is unreadable or not a dyld_shared_cache;
// falls back to single-file behaviour when the header has no subcache
// table.
- (instancetype)initWithPath:(NSString *)path;

// First 16 bytes, NUL-trimmed (e.g. "dyld_v1   arm64e").
@property (nonatomic, readonly) NSString *magic;

@property (nonatomic, readonly) uint32_t mappingCount;
@property (nonatomic, readonly) uint32_t mappingOffset;

// Image listing — empty if the cache uses a format we don't fully decode.
@property (nonatomic, readonly) NSArray<CDDyldCacheImageInfo *> *images;

// Best-effort platform extraction; 0 if not found.
@property (nonatomic, readonly) uint32_t platform;

// Main cache UUID (uppercase canonical), or @"" if unknown.
@property (nonatomic, readonly) NSString *uuid;

// 0=development, 1=production, 2=universal/multi-cache. Best-effort.
@property (nonatomic, readonly) uint64_t cacheType;

// YES if the cache uses the old (pre-subcache) image table layout.
@property (nonatomic, readonly) BOOL usesLegacyImageTable;

// All cache slices that have been merged into the in-memory view, ordered
// with the main cache first. Always contains at least one entry.
@property (nonatomic, readonly) NSArray<CDDyldCacheSubcacheInfo *> *subcaches;

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
