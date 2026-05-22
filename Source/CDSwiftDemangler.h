// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@interface CDSwiftDemangler : NSObject

// Returns YES if `name` looks like a Swift mangled symbol.
+ (BOOL)isMangledSwiftName:(NSString *)name;

// Returns the demangled form of a Swift mangled name, or `name` unchanged
// if it isn't Swift-mangled or libswiftCore is unavailable. Also strips a
// leading underscore (ObjC-export convention) if present before checking.
+ (NSString *)demangle:(NSString *)mangled;

// Rewrite Swift's private-discriminator form `Module.(Name in _HEX)` into
// `Module.Name__priv_HEX` so the result is a single valid C identifier.
// Returns `name` unchanged when no discriminator is present.
+ (NSString *)sanitizePrivateDiscriminator:(NSString *)name;

// Convenience: demangle (if applicable) and sanitize discriminators. Use
// this on any class-like name (class.name, ivar type name, protocol name)
// that may have come straight out of the runtime metadata.
+ (NSString *)cleanClassName:(NSString *)name;

@end
