// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDCPlusPlusDumper.h"

#import "CDMachOFile.h"
#import "CDLCSymbolTable.h"
#import "CDSymbol.h"

#include <cxxabi.h>
#include <stdlib.h>
#include <string.h>

@implementation CDCPlusPlusDumper

+ (NSString *)demangle:(NSString *)mangled
{
    if (mangled == nil) return nil;
    const char *cstr = [mangled UTF8String];
    if (cstr == NULL) return mangled;

    // Mach-O prepends an underscore to all C/C++ symbols. abi::__cxa_demangle
    // expects the bare Itanium ABI name, which starts with `_Z`.
    const char *itanium = cstr;
    if (itanium[0] == '_' && itanium[1] == '_' && itanium[2] == 'Z') {
        itanium = cstr + 1; // skip the leading Mach-O underscore
    } else if (itanium[0] != '_' || itanium[1] != 'Z') {
        return mangled;
    }

    int status = 0;
    size_t len = 0;
    char *out = abi::__cxa_demangle(itanium, NULL, &len, &status);
    if (out == NULL || status != 0) {
        if (out) free(out);
        return mangled;
    }
    NSString *result = [[NSString alloc] initWithUTF8String:out];
    free(out);
    return result ?: mangled;
}

// Find the class scope from a demangled signature like:
//   "int Foo::Bar::doIt(int, double const&) const"
// or "Foo::Bar::doIt(int)" — returns ("Foo::Bar", "int doIt(int, double const&) const").
// Returns nil class for free functions.
//
// The return type, when present in the demangled string, is preserved verbatim
// at the front of *outRest. Constructors/destructors and conversion operators
// have no return type in Itanium-demangled output and pass through unchanged.
static void CDSplitDemangled(NSString *demangled, NSString **outClass, NSString **outRest)
{
    // Locate the first `(` (start of arglist), then look backward for the
    // last `::` before it. The return type, if any, is the prefix before the
    // last top-level space; the qualified name is what follows that space.
    NSRange paren = [demangled rangeOfString:@"("];
    if (paren.location == NSNotFound) {
        *outClass = nil;
        *outRest = demangled;
        return;
    }

    NSString *uptoParen = [demangled substringToIndex:paren.location];
    // Find the last space at bracket depth 0 — spaces inside template args
    // (`std::vector<int, allocator<int>>`) must not split the return type
    // from the qualified name.
    NSInteger bracket = 0;
    NSInteger lastSpace = -1;
    for (NSInteger i = 0; i < (NSInteger)[uptoParen length]; i++) {
        unichar c = [uptoParen characterAtIndex:i];
        if (c == '<') bracket++;
        else if (c == '>') bracket--;
        else if (c == ' ' && bracket == 0) lastSpace = i;
    }
    NSString *returnType = (lastSpace >= 0)
        ? [uptoParen substringToIndex:(NSUInteger)lastSpace]
        : nil;
    NSString *qualified = (lastSpace >= 0)
        ? [uptoParen substringFromIndex:(NSUInteger)(lastSpace + 1)]
        : uptoParen;

    NSRange lastColons = [qualified rangeOfString:@"::" options:NSBackwardsSearch];
    if (lastColons.location == NSNotFound) {
        *outClass = nil;
        *outRest = demangled;
        return;
    }
    *outClass = [qualified substringToIndex:lastColons.location];
    NSString *methodName = [qualified substringFromIndex:lastColons.location + 2];
    NSString *signature = [demangled substringFromIndex:paren.location];
    NSString *body = [methodName stringByAppendingString:signature];
    *outRest = ([returnType length] > 0)
        ? [NSString stringWithFormat:@"%@ %@", returnType, body]
        : body;
}

+ (NSDictionary<NSString *, NSArray<NSString *> *> *)groupedSymbolsByClassFromMachOFile:(CDMachOFile *)machOFile
{
    NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *groups = [NSMutableDictionary dictionary];
    CDLCSymbolTable *st = machOFile.symbolTable;
    if (st == nil) return @{};

    [st loadSymbols];
    int matched = 0;
    int total = 0;
    for (CDSymbol *sym in st.symbols) {
        NSString *raw = sym.name;
        total++;
        if (raw == nil) continue;
        if (![raw hasPrefix:@"__Z"]) continue;
        matched++;

        NSString *demangled = [self demangle:raw];
        if (demangled == nil || [demangled isEqualToString:raw]) continue;

        NSString *className = nil;
        NSString *signature = nil;
        CDSplitDemangled(demangled, &className, &signature);
        if (className == nil) {
            // Free function — bucket under "(global)".
            className = @"(global)";
        }
        NSMutableArray *arr = groups[className];
        if (arr == nil) { arr = [NSMutableArray array]; groups[className] = arr; }
        if (signature && ![arr containsObject:signature]) [arr addObject:signature];
    }
    (void)matched; (void)total;
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithCapacity:[groups count]];
    for (NSString *k in groups) out[k] = [groups[k] copy];
    return out;
}

+ (NSString *)_headerStringForClass:(NSString *)className signatures:(NSArray<NSString *> *)signatures
{
    NSMutableString *s = [NSMutableString string];
    [s appendString:@"//\n//     Generated by class-dump 3.5 (64 bit) — C++ symbol-derived view.\n//\n\n"];
    if ([className isEqualToString:@"(global)"]) {
        [s appendString:@"// Global C++ functions\n\n"];
        for (NSString *sig in [signatures sortedArrayUsingSelector:@selector(compare:)]) {
            [s appendFormat:@"%@;\n", sig];
        }
        return [s copy];
    }

    [s appendFormat:@"class %@ {\npublic: // (access info unavailable from symbols alone)\n", className];
    for (NSString *sig in [signatures sortedArrayUsingSelector:@selector(compare:)]) {
        [s appendFormat:@"    %@;\n", sig];
    }
    [s appendString:@"};\n"];
    return [s copy];
}

+ (NSString *)dumpHeaderForMachOFile:(CDMachOFile *)machOFile
{
    NSDictionary *groups = [self groupedSymbolsByClassFromMachOFile:machOFile];
    NSMutableString *out = [NSMutableString string];
    NSArray *names = [[groups allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *name in names) {
        [out appendString:[self _headerStringForClass:name signatures:groups[name]]];
        [out appendString:@"\n"];
    }
    return [out copy];
}

+ (BOOL)writeHeadersForMachOFile:(CDMachOFile *)machOFile toDirectory:(NSString *)outDir error:(NSError **)error
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:outDir]) {
        if (![fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    }

    NSDictionary *groups = [self groupedSymbolsByClassFromMachOFile:machOFile];
    for (NSString *className in groups) {
        NSString *body = [self _headerStringForClass:className signatures:groups[className]];

        // Sanitize file name: replace `::` with `_` and any invalid path
        // characters with `_`.
        NSString *fileName = [[className stringByReplacingOccurrencesOfString:@"::" withString:@"_"]
                                          stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        if ([fileName length] == 0) fileName = @"global";
        NSString *path = [[outDir stringByAppendingPathComponent:fileName] stringByAppendingPathExtension:@"h"];
        if (![body writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:error]) return NO;
    }
    return YES;
}

@end
