// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCLinkeditData.h"

@interface CDLCExportsTrie : CDLCLinkeditData

@property (nonatomic, readonly) NSDictionary<NSString *, NSNumber *> *exports;

@end
