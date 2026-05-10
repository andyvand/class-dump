// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCTargetTriple.h"

#import "CDMachOFile.h"

#ifndef LC_TARGET_TRIPLE
#define LC_TARGET_TRIPLE 0x39
struct target_triple_command {
    uint32_t     cmd;
    uint32_t     cmdsize;
    union lc_str triple;
};
#endif

@implementation CDLCTargetTriple
{
    struct target_triple_command _command;
    NSString *_triple;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _command.cmd     = [cursor readInt32];
        _command.cmdsize = [cursor readInt32];

        uint32_t stringOffset = [cursor readInt32];

        NSUInteger headerSize = sizeof(uint32_t) * 3;
        if (stringOffset >= headerSize && stringOffset <= _command.cmdsize) {
            NSUInteger skip = stringOffset - headerSize;
            for (NSUInteger i = 0; i < skip; i++) [cursor readByte];
        }

        NSUInteger remaining = (_command.cmdsize > stringOffset) ? (_command.cmdsize - stringOffset) : 0;
        _triple = [cursor readStringOfLength:remaining encoding:NSUTF8StringEncoding];
    }
    return self;
}

- (uint32_t)cmd     { return _command.cmd; }
- (uint32_t)cmdsize { return _command.cmdsize; }

- (NSString *)triple { return _triple; }

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    [resultString appendFormat:@"  triple %@\n", _triple ?: @""];
}

@end
