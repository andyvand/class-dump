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

@end
