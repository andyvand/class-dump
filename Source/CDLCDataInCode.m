// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCDataInCode.h"

#import "CDMachOFile.h"

@implementation CDLCDataInCode
{
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
    }

    return self;
}

#pragma mark -

static NSString *DICEKindName(uint16_t kind)
{
    switch (kind) {
        case DICE_KIND_DATA:             return @"DATA";
        case DICE_KIND_JUMP_TABLE8:      return @"JUMP_TABLE8";
        case DICE_KIND_JUMP_TABLE16:     return @"JUMP_TABLE16";
        case DICE_KIND_JUMP_TABLE32:     return @"JUMP_TABLE32";
        case DICE_KIND_ABS_JUMP_TABLE32: return @"ABS_JUMP_TABLE32";
        default:                         return [NSString stringWithFormat:@"0x%04x", kind];
    }
}

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];

    if (!isVerbose) return;

    NSData *blob = [self linkeditData];
    const uint8_t *bytes = (const uint8_t *)[blob bytes];
    NSUInteger total = [blob length];
    NSUInteger entrySize = sizeof(struct data_in_code_entry);
    NSUInteger count = total / entrySize;

    [resultString appendFormat:@"  count %lu\n", (unsigned long)count];
    for (NSUInteger i = 0; i < count; i++) {
        struct data_in_code_entry e;
        memcpy(&e, bytes + i * entrySize, entrySize);
        [resultString appendFormat:@"    offset 0x%08x  length %u  kind %@\n",
            e.offset, e.length, DICEKindName(e.kind)];
    }
}

@end
