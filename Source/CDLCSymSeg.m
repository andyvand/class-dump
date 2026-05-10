// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCSymSeg.h"

#import "CDMachOFile.h"

@implementation CDLCSymSeg
{
    struct symseg_command _command;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _command.cmd     = [cursor readInt32];
        _command.cmdsize = [cursor readInt32];
        _command.offset  = [cursor readInt32];
        _command.size    = [cursor readInt32];
    }
    return self;
}

- (uint32_t)cmd     { return _command.cmd; }
- (uint32_t)cmdsize { return _command.cmdsize; }
- (uint32_t)offset  { return _command.offset; }
- (uint32_t)size    { return _command.size; }

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    [resultString appendFormat:@"  offset %u\n", _command.offset];
    [resultString appendFormat:@"    size %u\n", _command.size];
}

@end
