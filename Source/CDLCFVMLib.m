// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCFVMLib.h"

#import "CDMachOFile.h"

@implementation CDLCFVMLib
{
    struct fvmlib_command _command;
    NSString *_path;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _command.cmd     = [cursor readInt32];
        _command.cmdsize = [cursor readInt32];

        uint32_t nameOffset    = [cursor readInt32];
        _command.fvmlib.minor_version = [cursor readInt32];
        _command.fvmlib.header_addr   = [cursor readInt32];

        NSUInteger headerSize = sizeof(uint32_t) * 5;
        if (nameOffset >= headerSize && nameOffset <= _command.cmdsize) {
            NSUInteger skip = nameOffset - headerSize;
            for (NSUInteger i = 0; i < skip; i++) [cursor readByte];
        }

        NSUInteger remaining = (_command.cmdsize > nameOffset) ? (_command.cmdsize - nameOffset) : 0;
        _path = [cursor readStringOfLength:remaining encoding:NSASCIIStringEncoding];
    }
    return self;
}

- (uint32_t)cmd     { return _command.cmd; }
- (uint32_t)cmdsize { return _command.cmdsize; }
- (NSString *)path  { return _path; }
- (uint32_t)minorVersion { return _command.fvmlib.minor_version; }
- (uint32_t)headerAddr   { return _command.fvmlib.header_addr; }

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    [resultString appendFormat:@"          name %@\n", _path ?: @""];
    [resultString appendFormat:@" minor_version %u\n", _command.fvmlib.minor_version];
    [resultString appendFormat:@"   header_addr 0x%x\n", _command.fvmlib.header_addr];
}

@end
