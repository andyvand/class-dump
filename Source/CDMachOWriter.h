// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

extern NSString * const CDMachOWriterErrorDomain;

typedef NS_ENUM(NSInteger, CDMachOWriterError) {
    CDMachOWriterErrorNotMachO              = 1,
    CDMachOWriterErrorPathTooLong           = 2,
    CDMachOWriterErrorPathNotFound          = 3,
    CDMachOWriterErrorNoCodeSignature       = 4,
    CDMachOWriterErrorNoSpace               = 5,
    CDMachOWriterErrorRPathExists           = 6,
    CDMachOWriterErrorBadFile               = 7,
    CDMachOWriterErrorArchNotFound          = 8,
};

// Operates on a single (thin) Mach-O image stored in a contiguous byte range
// within a mutable buffer. The slice may move/shrink/grow within `data`; callers
// driving fat archives should re-pack offsets after each operation.
@interface CDMachOWriter : NSObject

- (instancetype)initWithData:(NSMutableData *)data sliceOffset:(NSUInteger)offset sliceLength:(NSUInteger)length;

@property (nonatomic, readonly) NSUInteger sliceOffset;
@property (nonatomic, readonly) NSUInteger sliceLength;
@property (nonatomic, readonly) BOOL is64Bit;
@property (nonatomic, readonly) BOOL isLittleEndian;

- (BOOL)setDylibID:(NSString *)newPath error:(NSError **)error;
- (BOOL)changeInstallName:(NSString *)oldPath to:(NSString *)newPath error:(NSError **)error;
- (BOOL)changeRPath:(NSString *)oldPath to:(NSString *)newPath error:(NSError **)error;
- (BOOL)addRPath:(NSString *)path error:(NSError **)error;
- (BOOL)deleteRPath:(NSString *)path error:(NSError **)error;
- (BOOL)stripCodeSignature:(NSError **)error;

@end

// Helpers for fat archives.
@interface CDMachOWriter (Fat)

// If `data` is a fat (FAT_MAGIC/FAT_CIGAM/_64) archive, returns the slice for
// the named arch (e.g. "arm64", "x86_64") as a fresh thin Mach-O NSData.
+ (NSData *)thinSliceForArch:(NSString *)archName fromFatData:(NSData *)data error:(NSError **)error;

// Returns @[ @"arm64", @"x86_64", ... ] for a fat archive, or @[archName] for
// a single Mach-O.
+ (NSArray<NSString *> *)architecturesInData:(NSData *)data;

@end
