// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCFunctionStarts.h"

#import "CDMachOFile.h"
#import "CDLCSegment.h"
#import "ULEB128.h"

@implementation CDLCFunctionStarts
{
    NSArray *_functionStarts;
}

#pragma mark -

- (NSArray *)functionStarts;
{
    if (_functionStarts == nil) {
        NSData *functionStartsData = [self linkeditData];
        const uint8_t *start = (uint8_t *)[functionStartsData bytes];
        const uint8_t *end = start + [functionStartsData length];
        uint64_t startAddress;
        uint64_t previousAddress = 0;
        NSMutableArray *functionStarts = [[NSMutableArray alloc] init];
        while ((startAddress = read_uleb128(&start, end))) {
            [functionStarts addObject:@(startAddress + previousAddress)];
            previousAddress += startAddress;
        }
        _functionStarts = [functionStarts copy];
    }
    return _functionStarts;
}

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];

    if (!isVerbose) return;

    NSArray *starts = self.functionStarts;
    CDLCSegment *textSeg = [self.machOFile segmentWithName:@"__TEXT"];
    uint64_t base = textSeg ? (uint64_t)textSeg.vmaddr : 0;
    for (NSNumber *offset in starts) {
        [resultString appendFormat:@"        0x%016llx\n", base + [offset unsignedLongLongValue]];
    }
}

@end
