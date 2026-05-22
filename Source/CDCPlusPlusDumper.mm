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

// Returns YES if the substring `s[0..end)` ends with the `operator` keyword
// as a whole word (i.e., the char immediately before it, if any, is not part
// of an identifier).
static BOOL CDEndsWithOperatorKeyword(NSString *s, NSUInteger end)
{
    static NSString *kw = @"operator";
    NSUInteger kwLen = [kw length];
    if (end < kwLen) return NO;
    NSRange tail = NSMakeRange(end - kwLen, kwLen);
    if (![[s substringWithRange:tail] isEqualToString:kw]) return NO;
    if (end == kwLen) return YES;
    unichar prev = [s characterAtIndex:end - kwLen - 1];
    if ((prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z') ||
        (prev >= '0' && prev <= '9') || prev == '_') return NO;
    return YES;
}

// Find the matching `)` for the `(` at position `open` in `s`, tracking nested
// parens and angle brackets. Returns NSNotFound if unbalanced.
static NSUInteger CDMatchingParen(NSString *s, NSUInteger open)
{
    NSUInteger len = [s length];
    NSInteger pdepth = 0;
    NSInteger adepth = 0;
    for (NSUInteger i = open; i < len; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == '<') adepth++;
        else if (c == '>' && adepth > 0) adepth--;
        else if (adepth == 0) {
            if (c == '(') pdepth++;
            else if (c == ')') {
                pdepth--;
                if (pdepth == 0) return i;
            }
        }
    }
    return NSNotFound;
}

// Locate the start of the function's argument list — the first `(` at
// angle-bracket-depth 0 that genuinely opens args. A `(` is treated as the
// args list unless it's at the very start (e.g. `(anonymous namespace)...`),
// directly follows a `::` separator (another namespace marker), or is part
// of an `operator()` name.
static NSUInteger CDFindArgListStart(NSString *s)
{
    NSUInteger len = [s length];
    NSInteger adepth = 0;
    for (NSUInteger i = 0; i < len; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == '<') { adepth++; continue; }
        if (c == '>' && adepth > 0) { adepth--; continue; }
        if (c != '(' || adepth != 0) continue;

        NSInteger j = (NSInteger)i - 1;
        while (j >= 0 && [[NSCharacterSet whitespaceCharacterSet] characterIsMember:[s characterAtIndex:(NSUInteger)j]]) j--;

        BOOL skip = NO;
        if (j < 0) {
            skip = YES;
        } else if ([s characterAtIndex:(NSUInteger)j] == ':') {
            // Preceded by `::` — what follows is a parenthesized name segment
            // (anonymous namespace, lambda marker, etc.), not args.
            skip = YES;
        } else if (CDEndsWithOperatorKeyword(s, (NSUInteger)(j + 1))) {
            // The `()` is the operator() name, not the args list.
            skip = YES;
        }

        if (skip) {
            NSUInteger end = CDMatchingParen(s, i);
            if (end == NSNotFound) return NSNotFound;
            i = end;
            continue;
        }
        return i;
    }
    return NSNotFound;
}

// Find the last `::` at angle-bracket- and paren-depth 0 in `s`. The paren
// tracking ignores `::` inside `(anonymous namespace)`-style markers.
static NSRange CDLastTopLevelDoubleColon(NSString *s)
{
    NSUInteger len = [s length];
    NSInteger adepth = 0;
    NSInteger pdepth = 0;
    NSRange found = (NSRange){ NSNotFound, 0 };
    for (NSUInteger i = 0; i + 1 < len; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == '<') { adepth++; continue; }
        if (c == '>' && adepth > 0) { adepth--; continue; }
        if (c == '(') { pdepth++; continue; }
        if (c == ')' && pdepth > 0) { pdepth--; continue; }
        if (adepth == 0 && pdepth == 0 && c == ':' && [s characterAtIndex:i + 1] == ':') {
            found = NSMakeRange(i, 2);
            i++;
        }
    }
    return found;
}

// Find the position of the last whitespace at angle-bracket- and paren-depth 0
// in `s`. Returns -1 if none.
static NSInteger CDLastTopLevelWhitespace(NSString *s)
{
    NSCharacterSet *ws = [NSCharacterSet whitespaceCharacterSet];
    NSUInteger len = [s length];
    NSInteger adepth = 0;
    NSInteger pdepth = 0;
    NSInteger found = -1;
    for (NSUInteger i = 0; i < len; i++) {
        unichar c = [s characterAtIndex:i];
        if (c == '<') { adepth++; continue; }
        if (c == '>' && adepth > 0) { adepth--; continue; }
        if (c == '(') { pdepth++; continue; }
        if (c == ')' && pdepth > 0) { pdepth--; continue; }
        if (adepth == 0 && pdepth == 0 && [ws characterIsMember:c]) found = (NSInteger)i;
    }
    return found;
}

// Return the unqualified, non-templated leaf of a class path, e.g.
// "std::vector<int>" -> "vector", "Ns::Inner<T>" -> "Inner".
static NSString *CDLeafClassName(NSString *className)
{
    NSRange lc = CDLastTopLevelDoubleColon(className);
    NSString *leaf = (lc.location == NSNotFound)
        ? className
        : [className substringFromIndex:lc.location + 2];
    NSRange lt = [leaf rangeOfString:@"<"];
    if (lt.location != NSNotFound) leaf = [leaf substringToIndex:lt.location];
    return leaf;
}

// When the demangled signature carries no return type, derive one heuristically.
// Returns @"" when the method legitimately has no return type spelling in C++
// source (constructors, destructors, conversion operators).
static NSString *CDDeriveReturnType(NSString *className, NSString *methodName)
{
    if (className != nil) {
        NSString *leaf = CDLeafClassName(className);
        if ([leaf length] > 0) {
            if ([methodName isEqualToString:leaf]) return @"";
            NSString *dtor = [@"~" stringByAppendingString:leaf];
            if ([methodName isEqualToString:dtor]) return @"";
        }
    }

    if ([methodName hasPrefix:@"operator"]) {
        // Whole-word check: char after `operator` must not continue an identifier.
        if ([methodName length] == 8) return @"auto";
        unichar after = [methodName characterAtIndex:8];
        BOOL isWord = (after >= 'A' && after <= 'Z') || (after >= 'a' && after <= 'z') ||
                      (after >= '0' && after <= '9') || after == '_';
        if (!isWord) {
            if (after == ' ') {
                NSString *opPart = [methodName substringFromIndex:9];
                if ([opPart isEqualToString:@"new"] || [opPart isEqualToString:@"new[]"]) return @"void *";
                if ([opPart isEqualToString:@"delete"] || [opPart isEqualToString:@"delete[]"]) return @"void";
                // Conversion operator — the type is implicit in the name.
                return @"";
            }
            // Symbolic operator (operator+, operator==, operator(), operator[], ...).
            return @"auto";
        }
    }

    return @"auto";
}

// Find the class scope from a demangled signature like:
//   "int Foo::Bar::doIt(int, double const&) const"
// or "Foo::Bar::doIt(int)" — returns ("Foo::Bar", "int doIt(int, double const&) const").
// Returns nil class for free functions.
//
// Itanium mangling doesn't encode return types for non-template member
// functions, so the demangled string usually has no return-type prefix. When
// none is present, we derive one: omit for ctors/dtors/conv-operators, use
// `void *`/`void` for `operator new`/`delete`, otherwise emit `auto`.
static void CDSplitDemangled(NSString *demangled, NSString **outClass, NSString **outRest)
{
    NSUInteger parenLoc = CDFindArgListStart(demangled);
    if (parenLoc == NSNotFound) {
        *outClass = nil;
        *outRest = demangled;
        return;
    }

    NSString *uptoParen = [demangled substringToIndex:parenLoc];
    NSString *argList = [demangled substringFromIndex:parenLoc];

    NSRange lastColons = CDLastTopLevelDoubleColon(uptoParen);
    NSString *className = nil;
    NSString *methodName = nil;
    NSString *returnType = @"";

    if (lastColons.location == NSNotFound) {
        // Free function. The whole `uptoParen` is `[return-type ]methodName`.
        // `operator <stuff>` may have internal spaces, so anchor on the keyword.
        NSRange opRange = [uptoParen rangeOfString:@"operator"];
        if (opRange.location != NSNotFound &&
            CDEndsWithOperatorKeyword(uptoParen, opRange.location + opRange.length)) {
            methodName = [uptoParen substringFromIndex:opRange.location];
            returnType = (opRange.location > 0)
                ? [[uptoParen substringToIndex:opRange.location]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]
                : @"";
        } else {
            NSInteger ws = CDLastTopLevelWhitespace(uptoParen);
            if (ws < 0) {
                methodName = uptoParen;
            } else {
                methodName = [uptoParen substringFromIndex:(NSUInteger)(ws + 1)];
                returnType = [[uptoParen substringToIndex:(NSUInteger)ws]
                                  stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            }
        }
    } else {
        methodName = [uptoParen substringFromIndex:lastColons.location + 2];
        NSString *beforeColons = [uptoParen substringToIndex:lastColons.location];
        // `beforeColons` is `[return-type ]classPath`. Class path itself cannot
        // contain top-level spaces (operators live in the unqualified name).
        NSInteger ws = CDLastTopLevelWhitespace(beforeColons);
        if (ws < 0) {
            className = beforeColons;
        } else {
            className = [beforeColons substringFromIndex:(NSUInteger)(ws + 1)];
            returnType = [[beforeColons substringToIndex:(NSUInteger)ws]
                              stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        }
    }

    *outClass = ([className length] > 0) ? className : nil;

    if ([returnType length] == 0) {
        returnType = CDDeriveReturnType(className, methodName);
    }

    NSString *body = [methodName stringByAppendingString:argList];
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
