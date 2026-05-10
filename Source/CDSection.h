// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

@class CDMachOFileDataCursor;
@class CDLCSegment;

@interface CDSection : NSObject

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor segment:(CDLCSegment *)segment;

@property (weak, readonly) CDLCSegment *segment;

@property (nonatomic, readonly) NSData *data;

@property (nonatomic, readonly) NSString *segmentName;
@property (nonatomic, readonly) NSString *sectionName;

@property (nonatomic, readonly) NSUInteger addr;
@property (nonatomic, readonly) NSUInteger size;
@property (nonatomic, readonly) uint32_t offset;
@property (nonatomic, readonly) uint32_t align;
@property (nonatomic, readonly) uint32_t reloff;
@property (nonatomic, readonly) uint32_t nreloc;
@property (nonatomic, readonly) uint32_t flags;
@property (nonatomic, readonly) uint32_t reserved1;
@property (nonatomic, readonly) uint32_t reserved2;

- (BOOL)containsAddress:(NSUInteger)address;
- (NSUInteger)fileOffsetForAddress:(NSUInteger)address;

- (NSString *)flagsDescription;
- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;

@end
