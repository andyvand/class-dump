// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLoadCommand.h"

// LC_FVMFILE (obsolete, fixed-VM file inclusion).
@interface CDLCFVMFile : CDLoadCommand

@property (nonatomic, readonly) NSString *path;
@property (nonatomic, readonly) uint32_t headerAddr;

@end
