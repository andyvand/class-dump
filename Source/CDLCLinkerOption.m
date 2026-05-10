// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCLinkerOption.h"

#import "CDMachOFile.h"

@implementation CDLCLinkerOption
{
    struct linker_option_command _command;
    NSArray<NSString *> *_options;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _command.cmd     = [cursor readInt32];
        _command.cmdsize = [cursor readInt32];
        _command.count   = [cursor readInt32];

        NSUInteger payload = _command.cmdsize - sizeof(struct linker_option_command);
        NSMutableArray<NSString *> *options = [NSMutableArray arrayWithCapacity:_command.count];
        NSMutableData *buffer = [NSMutableData dataWithLength:payload];
        [cursor readBytesOfLength:payload intoBuffer:[buffer mutableBytes]];

        const char *bytes = (const char *)[buffer bytes];
        NSUInteger i = 0;
        for (uint32_t n = 0; n < _command.count && i < payload; n++) {
            NSUInteger start = i;
            while (i < payload && bytes[i] != '\0') i++;
            NSString *str = [[NSString alloc] initWithBytes:bytes + start length:(i - start) encoding:NSUTF8StringEncoding];
            [options addObject:str ?: @""];
            if (i < payload) i++;
        }
        _options = [options copy];
    }
    return self;
}

- (uint32_t)cmd      { return _command.cmd; }
- (uint32_t)cmdsize  { return _command.cmdsize; }
- (uint32_t)count    { return _command.count; }
- (NSArray<NSString *> *)options { return _options; }

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    [resultString appendFormat:@"   count %u\n", _command.count];
    NSUInteger idx = 0;
    for (NSString *opt in _options) {
        [resultString appendFormat:@"  string #%lu %@\n", (unsigned long)idx++, opt];
    }
}

@end
