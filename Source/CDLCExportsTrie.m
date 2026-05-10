// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCExportsTrie.h"

#import "CDMachOFile.h"
#import "ULEB128.h"

#include <mach-o/loader.h>

@implementation CDLCExportsTrie
{
    NSMutableDictionary<NSString *, NSNumber *> *_exports;
}

- (NSDictionary<NSString *, NSNumber *> *)exports
{
    if (_exports == nil) {
        _exports = [NSMutableDictionary dictionary];
        NSData *blob = [self linkeditData];
        if ([blob length] > 0) {
            const uint8_t *start = (const uint8_t *)[blob bytes];
            const uint8_t *end = start + [blob length];
            [self walk:start end:end prefix:@"" offset:0];
        }
    }
    return _exports;
}

- (void)walk:(const uint8_t *)start end:(const uint8_t *)end prefix:(NSString *)prefix offset:(uint64_t)offset
{
    const uint8_t *ptr = start + offset;
    if (ptr >= end) return;

    uint64_t terminalSize = read_uleb128(&ptr, end);
    const uint8_t *terminal = ptr;
    ptr += terminalSize;
    if (ptr > end) return;

    if (terminalSize > 0) {
        const uint8_t *t = terminal;
        uint64_t flags = read_uleb128(&t, end);
        uint64_t addr = 0;
        if (!(flags & EXPORT_SYMBOL_FLAGS_REEXPORT)) {
            addr = read_uleb128(&t, end);
        }
        _exports[prefix] = @(addr);
    }

    if (ptr >= end) return;
    uint8_t childCount = *ptr++;
    for (uint8_t i = 0; i < childCount && ptr < end; i++) {
        const uint8_t *edge = ptr;
        while (ptr < end && *ptr != 0) ptr++;
        if (ptr >= end) return;
        NSString *edgeStr = [[NSString alloc] initWithBytes:edge length:(ptr - edge) encoding:NSUTF8StringEncoding];
        ptr++;
        uint64_t childOffset = read_uleb128(&ptr, end);
        [self walk:start end:end prefix:[NSString stringWithFormat:@"%@%@", prefix, edgeStr ?: @""] offset:childOffset];
    }
}

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];
    if (!isVerbose) return;

    NSDictionary *exp = self.exports;
    [resultString appendFormat:@"  %lu exports\n", (unsigned long)[exp count]];
    NSArray *keys = [[exp allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *name in keys) {
        [resultString appendFormat:@"    0x%016llx  %@\n", [exp[name] unsignedLongLongValue], name];
    }
}

@end
