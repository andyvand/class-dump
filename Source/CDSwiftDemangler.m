// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDSwiftDemangler.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

// Apple's libswiftCore exports:
//   char *swift_demangle(const char *mangledName,
//                        size_t      mangledNameLength,
//                        char *      outputBuffer,    // NULL for malloc'd
//                        size_t *    outputBufferSize,
//                        uint32_t    flags);
typedef char *(*swift_demangle_fn)(const char *, size_t, char *, size_t *, uint32_t);

// Lazy load of libswiftCore. Searched paths cover toolchain copies (during
// development) and the on-system library (resolved via dyld shared cache).
static swift_demangle_fn _swift_demangle_load(void)
{
    static dispatch_once_t once;
    static swift_demangle_fn fn = NULL;
    dispatch_once(&once, ^{
        // dyld will resolve the shared-cache copy when given the bare name.
        const char *kCandidates[] = {
            "/usr/lib/swift/libswiftCore.dylib",
            "libswiftCore.dylib",
            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-5.0/macosx/libswiftCore.dylib",
            NULL,
        };
        void *h = NULL;
        for (size_t i = 0; kCandidates[i] != NULL; i++) {
            h = dlopen(kCandidates[i], RTLD_LAZY | RTLD_LOCAL);
            if (h) break;
        }
        if (!h) return;
        fn = (swift_demangle_fn)dlsym(h, "swift_demangle");
    });
    return fn;
}

@implementation CDSwiftDemangler

+ (BOOL)isMangledSwiftName:(NSString *)name
{
    if ([name length] < 3) return NO;
    return ([name hasPrefix:@"$s"] ||
            [name hasPrefix:@"$S"] ||
            [name hasPrefix:@"_$s"] ||
            [name hasPrefix:@"_$S"] ||
            [name hasPrefix:@"_T0"] ||
            [name hasPrefix:@"_Tt"] ||
            [name hasPrefix:@"_TM"] ||
            [name hasPrefix:@"_TF"] ||
            [name hasPrefix:@"_TW"]);
}

+ (NSString *)demangle:(NSString *)mangled
{
    if (mangled == nil) return nil;
    if (![self isMangledSwiftName:mangled]) return mangled;

    swift_demangle_fn fn = _swift_demangle_load();
    if (fn == NULL) return mangled;

    // For Swift 5+ ($s/$S) the ObjC-export symbol has a leading underscore that
    // must be stripped before calling swift_demangle. For old-style _T0/_T
    // Swift 4-era mangling, the leading underscore IS part of the prefix and
    // must be kept.
    NSString *toMangle = mangled;
    if ([mangled hasPrefix:@"_$"]) toMangle = [mangled substringFromIndex:1];
    const char *cstr = [toMangle UTF8String];
    if (cstr == NULL) return mangled;
    size_t inLen = strlen(cstr);

    char *out = fn(cstr, inLen, NULL, NULL, 0);
    if (out == NULL) return mangled;

    NSString *result = [[NSString alloc] initWithUTF8String:out];
    free(out);
    return result ?: mangled;
}

+ (NSString *)sanitizePrivateDiscriminator:(NSString *)name
{
    if (name == nil) return nil;
    NSRange parenOpen = [name rangeOfString:@".("];
    if (parenOpen.location == NSNotFound) return name;
    NSRange parenClose = [name rangeOfString:@")" options:NSBackwardsSearch];
    if (parenClose.location == NSNotFound || parenClose.location <= parenOpen.location) return name;

    NSString *prefix = [name substringToIndex:parenOpen.location];
    NSRange innerRange = NSMakeRange(NSMaxRange(parenOpen), parenClose.location - NSMaxRange(parenOpen));
    NSString *body = [name substringWithRange:innerRange];
    NSString *tail = [name substringFromIndex:NSMaxRange(parenClose)];

    NSRange inMarker = [body rangeOfString:@" in _"];
    NSString *transformed;
    if (inMarker.location != NSNotFound) {
        NSString *baseName = [body substringToIndex:inMarker.location];
        NSString *discriminator = [body substringFromIndex:NSMaxRange(inMarker)];
        transformed = [NSString stringWithFormat:@"%@.%@__priv_%@", prefix, baseName, discriminator];
    } else {
        transformed = [NSString stringWithFormat:@"%@.%@", prefix, body];
    }
    if ([tail length] > 0)
        transformed = [transformed stringByAppendingString:tail];
    return transformed;
}

+ (NSString *)cleanClassName:(NSString *)name
{
    NSString *resolved = name;
    if ([self isMangledSwiftName:name]) {
        NSString *out = [self demangle:name];
        if ([out length] > 0)
            resolved = out;
    }
    return [self sanitizePrivateDiscriminator:resolved];
}

@end
