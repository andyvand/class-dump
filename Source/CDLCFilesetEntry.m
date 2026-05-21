// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCFilesetEntry.h"

#import "CDMachOFile.h"

#ifndef LC_FILESET_ENTRY
#define LC_FILESET_ENTRY (0x35 | LC_REQ_DYLD)
struct fileset_entry_command {
    uint32_t     cmd;
    uint32_t     cmdsize;
    uint64_t     vmaddr;
    uint64_t     fileoff;
    union lc_str entry_id;
    uint32_t     reserved;
};
#endif

@implementation CDLCFilesetEntry
{
    struct fileset_entry_command _command;
    NSString *_entryID;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _command.cmd      = [cursor readInt32];
        _command.cmdsize  = [cursor readInt32];
        _command.vmaddr   = [cursor readInt64];
        _command.fileoff  = [cursor readInt64];
        uint32_t stringOffset = [cursor readInt32];
        _command.reserved = [cursor readInt32];

        NSUInteger headerSize = sizeof(uint32_t) * 4 + sizeof(uint64_t) * 2;
        if (stringOffset >= headerSize && stringOffset <= _command.cmdsize) {
            NSUInteger skip = stringOffset - headerSize;
            for (NSUInteger i = 0; i < skip; i++) [cursor readByte];
        }

        NSUInteger remaining = (_command.cmdsize > stringOffset) ? (_command.cmdsize - stringOffset) : 0;
        NSString *raw = [cursor readStringOfLength:remaining encoding:NSUTF8StringEncoding];

        // The entry_id occupies the rest of the load command, NUL-padded out to
        // _command.cmdsize. Strip embedded NULs so the resulting NSString can be
        // used as a path component without `fileSystemRepresentation` truncating
        // mid-string. Also trim any trailing whitespace produced by stray bytes.
        if (raw != nil) {
            NSRange nul = [raw rangeOfString:@"\0"];
            if (nul.location != NSNotFound) raw = [raw substringToIndex:nul.location];
            raw = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        }
        _entryID = raw;
    }
    return self;
}

- (uint32_t)cmd     { return _command.cmd; }
- (uint32_t)cmdsize { return _command.cmdsize; }
- (uint64_t)vmaddr  { return _command.vmaddr; }
- (uint64_t)fileoff { return _command.fileoff; }
- (NSString *)entryID { return _entryID; }

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    [resultString appendFormat:@"  vmaddr 0x%016llx\n", _command.vmaddr];
    [resultString appendFormat:@" fileoff 0x%016llx\n", _command.fileoff];
    [resultString appendFormat:@"entry_id %@\n", _entryID ?: @""];
}

@end
