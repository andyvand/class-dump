// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCIdent.h"

#import "CDMachOFile.h"

@implementation CDLCIdent
{
    struct ident_command _command;
    NSArray<NSString *> *_strings;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _command.cmd     = [cursor readInt32];
        _command.cmdsize = [cursor readInt32];

        NSUInteger payload = _command.cmdsize - sizeof(struct ident_command);
        NSMutableData *buffer = [NSMutableData dataWithLength:payload];
        [cursor readBytesOfLength:payload intoBuffer:[buffer mutableBytes]];

        const char *bytes = (const char *)[buffer bytes];
        NSMutableArray<NSString *> *out = [NSMutableArray array];
        NSUInteger i = 0;
        while (i < payload) {
            if (bytes[i] == '\0') { i++; continue; }
            NSUInteger start = i;
            while (i < payload && bytes[i] != '\0') i++;
            NSString *s = [[NSString alloc] initWithBytes:bytes + start length:(i - start) encoding:NSUTF8StringEncoding];
            if (s) [out addObject:s];
        }
        _strings = [out copy];
    }
    return self;
}

- (uint32_t)cmd     { return _command.cmd; }
- (uint32_t)cmdsize { return _command.cmdsize; }
- (NSArray<NSString *> *)strings { return _strings; }

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    NSUInteger idx = 0;
    for (NSString *s in _strings) {
        [resultString appendFormat:@"  string #%lu %@\n", (unsigned long)idx++, s];
    }
}

@end
