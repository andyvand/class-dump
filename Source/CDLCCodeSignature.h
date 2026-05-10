// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCLinkeditData.h"

@interface CDLCCodeSignature : CDLCLinkeditData

@property (nonatomic, readonly) NSString *signingIdentifier;
@property (nonatomic, readonly) NSString *teamIdentifier;
@property (nonatomic, readonly) uint8_t hashType;
@property (nonatomic, readonly) uint32_t codeDirectoryFlags;

@end
