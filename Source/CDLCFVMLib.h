// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLoadCommand.h"

// LC_IDFVMLIB / LC_LOADFVMLIB (obsolete, fixed-VM shared libraries).
@interface CDLCFVMLib : CDLoadCommand

@property (nonatomic, readonly) NSString *path;
@property (nonatomic, readonly) uint32_t minorVersion;
@property (nonatomic, readonly) uint32_t headerAddr;

@end
