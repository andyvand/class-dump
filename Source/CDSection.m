// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDSection.h"

#include <mach-o/loader.h>
#import "CDMachOFile.h"
#import "CDMachOFileDataCursor.h"
#import "CDLCSegment.h"

@implementation CDSection
{
    struct section_64 _section; // 64-bit, also holding 32-bit
}

@synthesize data = _data;

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor segment:(CDLCSegment *)segment;
{
    if ((self = [super init])) {
        _segment = segment;
        
        _sectionName = [cursor readStringOfLength:16 encoding:NSASCIIStringEncoding];
        size_t sectionNameLength = [_sectionName lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        memcpy(_section.sectname, [_sectionName UTF8String], MIN(sectionNameLength, sizeof(_section.sectname)));
        size_t segmentNameLength = [_sectionName lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        _segmentName = [cursor readStringOfLength:16 encoding:NSASCIIStringEncoding];
        memcpy(_section.segname, [_segmentName UTF8String], MIN(segmentNameLength, sizeof(_section.segname)));
        _section.addr      = [cursor readPtr];
        _section.size      = [cursor readPtr];
        _section.offset    = [cursor readInt32];
        uint32_t dyldOffset = (uint32_t)(_section.addr - segment.vmaddr + segment.fileoff);
        if (_section.offset > 0 && _section.offset != dyldOffset) {
            fprintf(stderr, "Warning: Invalid section offset 0x%08x replaced with 0x%08x in %s,%s\n", _section.offset, dyldOffset, [_segmentName UTF8String], [_sectionName UTF8String]);
            _section.offset = dyldOffset;
        }
        _section.align     = [cursor readInt32];
        _section.reloff    = [cursor readInt32];
        _section.nreloc    = [cursor readInt32];
        _section.flags     = [cursor readInt32];
        _section.reserved1 = [cursor readInt32];
        _section.reserved2 = [cursor readInt32];
        if (cursor.machOFile.uses64BitABI) {
            _section.reserved3 = [cursor readInt32];
        }
    }

    return self;
}

#pragma mark -

- (NSData *)data;
{
    if (!_data) {
        _data = [[NSData alloc] initWithBytes:(uint8_t *)[self.segment.machOFile.data bytes] + _section.offset length:_section.size];
    }
    return _data;
}

- (NSUInteger)addr;
{
    return _section.addr;
}

- (NSUInteger)size;
{
    return _section.size;
}

- (BOOL)containsAddress:(NSUInteger)address;
{
    return (address >= _section.addr) && (address < _section.addr + _section.size);
}

- (NSUInteger)fileOffsetForAddress:(NSUInteger)address;
{
    NSParameterAssert([self containsAddress:address]);
    return _section.offset + address - _section.addr;
}

- (uint32_t)offset    { return _section.offset; }
- (uint32_t)align     { return _section.align; }
- (uint32_t)reloff    { return _section.reloff; }
- (uint32_t)nreloc    { return _section.nreloc; }
- (uint32_t)flags     { return _section.flags; }
- (uint32_t)reserved1 { return _section.reserved1; }
- (uint32_t)reserved2 { return _section.reserved2; }

- (NSString *)sectionTypeName:(uint32_t)type;
{
    switch (type) {
        case S_REGULAR:                             return @"S_REGULAR";
        case S_ZEROFILL:                            return @"S_ZEROFILL";
        case S_CSTRING_LITERALS:                    return @"S_CSTRING_LITERALS";
        case S_4BYTE_LITERALS:                      return @"S_4BYTE_LITERALS";
        case S_8BYTE_LITERALS:                      return @"S_8BYTE_LITERALS";
        case S_LITERAL_POINTERS:                    return @"S_LITERAL_POINTERS";
        case S_NON_LAZY_SYMBOL_POINTERS:            return @"S_NON_LAZY_SYMBOL_POINTERS";
        case S_LAZY_SYMBOL_POINTERS:                return @"S_LAZY_SYMBOL_POINTERS";
        case S_SYMBOL_STUBS:                        return @"S_SYMBOL_STUBS";
        case S_MOD_INIT_FUNC_POINTERS:              return @"S_MOD_INIT_FUNC_POINTERS";
        case S_MOD_TERM_FUNC_POINTERS:              return @"S_MOD_TERM_FUNC_POINTERS";
        case S_COALESCED:                           return @"S_COALESCED";
        case S_GB_ZEROFILL:                         return @"S_GB_ZEROFILL";
        case S_INTERPOSING:                         return @"S_INTERPOSING";
        case S_16BYTE_LITERALS:                     return @"S_16BYTE_LITERALS";
        case S_DTRACE_DOF:                          return @"S_DTRACE_DOF";
        case S_LAZY_DYLIB_SYMBOL_POINTERS:          return @"S_LAZY_DYLIB_SYMBOL_POINTERS";
        case S_THREAD_LOCAL_REGULAR:                return @"S_THREAD_LOCAL_REGULAR";
        case S_THREAD_LOCAL_ZEROFILL:               return @"S_THREAD_LOCAL_ZEROFILL";
        case S_THREAD_LOCAL_VARIABLES:              return @"S_THREAD_LOCAL_VARIABLES";
        case S_THREAD_LOCAL_VARIABLE_POINTERS:      return @"S_THREAD_LOCAL_VARIABLE_POINTERS";
        case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: return @"S_THREAD_LOCAL_INIT_FUNCTION_POINTERS";
        default:                                    return [NSString stringWithFormat:@"0x%02x", type];
    }
}

- (NSString *)flagsDescription;
{
    NSMutableArray *parts = [NSMutableArray array];
    [parts addObject:[self sectionTypeName:_section.flags & SECTION_TYPE]];
    uint32_t attrs = _section.flags & SECTION_ATTRIBUTES;
    if (attrs & S_ATTR_PURE_INSTRUCTIONS)   [parts addObject:@"PURE_INSTRUCTIONS"];
    if (attrs & S_ATTR_NO_TOC)              [parts addObject:@"NO_TOC"];
    if (attrs & S_ATTR_STRIP_STATIC_SYMS)   [parts addObject:@"STRIP_STATIC_SYMS"];
    if (attrs & S_ATTR_NO_DEAD_STRIP)       [parts addObject:@"NO_DEAD_STRIP"];
    if (attrs & S_ATTR_LIVE_SUPPORT)        [parts addObject:@"LIVE_SUPPORT"];
    if (attrs & S_ATTR_SELF_MODIFYING_CODE) [parts addObject:@"SELF_MODIFYING_CODE"];
    if (attrs & S_ATTR_DEBUG)               [parts addObject:@"DEBUG"];
    if (attrs & S_ATTR_SOME_INSTRUCTIONS)   [parts addObject:@"SOME_INSTRUCTIONS"];
    if (attrs & S_ATTR_EXT_RELOC)           [parts addObject:@"EXT_RELOC"];
    if (attrs & S_ATTR_LOC_RELOC)           [parts addObject:@"LOC_RELOC"];
    return [parts componentsJoinedByString:@" "];
}

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    int padding = (int)self.segment.machOFile.ptrSize * 2;
    [resultString appendFormat:@"Section\n"];
    [resultString appendFormat:@"  sectname %@\n", self.sectionName ?: @""];
    [resultString appendFormat:@"   segname %@\n", self.segmentName ?: @""];
    [resultString appendFormat:@"      addr 0x%0*llx\n", padding, (unsigned long long)_section.addr];
    [resultString appendFormat:@"      size 0x%0*llx\n", padding, (unsigned long long)_section.size];
    [resultString appendFormat:@"    offset %u\n",  _section.offset];
    [resultString appendFormat:@"     align 2^%u (%u)\n", _section.align, (1u << _section.align)];
    [resultString appendFormat:@"    reloff %u\n",  _section.reloff];
    [resultString appendFormat:@"    nreloc %u\n",  _section.nreloc];
    if (isVerbose) {
        [resultString appendFormat:@"     flags %@\n", [self flagsDescription]];
    } else {
        [resultString appendFormat:@"     flags 0x%08x\n", _section.flags];
    }
    [resultString appendFormat:@" reserved1 %u\n",  _section.reserved1];
    [resultString appendFormat:@" reserved2 %u\n",  _section.reserved2];
}

#pragma mark - Debugging

- (NSString *)description;
{
    int padding = (int)self.segment.machOFile.ptrSize * 2;
    return [NSString stringWithFormat:@"<%@:%p> '%@,%-16s' addr: %0*llx, size: %0*llx",
            NSStringFromClass([self class]), self,
            self.segmentName, [self.sectionName UTF8String],
            padding, _section.addr, padding, _section.size];
}

@end
