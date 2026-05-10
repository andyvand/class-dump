// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLoadCommand.h"

@interface CDLCLinkerOption : CDLoadCommand

@property (nonatomic, readonly) uint32_t count;
@property (nonatomic, readonly) NSArray<NSString *> *options;

@end
