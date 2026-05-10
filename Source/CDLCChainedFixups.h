// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCLinkeditData.h"

@interface CDLCChainedFixups : CDLCLinkeditData

@property (nonatomic, readonly) uint32_t fixupsVersion;
@property (nonatomic, readonly) uint32_t startsOffset;
@property (nonatomic, readonly) uint32_t importsOffset;
@property (nonatomic, readonly) uint32_t symbolsOffset;
@property (nonatomic, readonly) uint32_t importsCount;
@property (nonatomic, readonly) uint32_t importsFormat;
@property (nonatomic, readonly) uint32_t symbolsFormat;

@property (nonatomic, readonly) NSArray<NSString *> *importNames;

// Walks every chain in the LC's payload and rewrites raw chain-encoded
// pointer slots in `data` to resolved 64-bit VM addresses (rebases) or zero
// (binds). Used after dsc_extractor extracts a dylib from a dyld_shared_cache
// — it leaves chained-fixup raw bits in __DATA pointer slots that downstream
// readers (e.g. CDObjectiveC2Processor) can't follow until rewritten.
//
// `imageBase` is the image's __TEXT vmaddr (used for *_OFFSET pointer formats
// where target is image-relative, not absolute).
- (void)applyToMutableData:(NSMutableData *)data imageBase:(uint64_t)imageBase;

@end
