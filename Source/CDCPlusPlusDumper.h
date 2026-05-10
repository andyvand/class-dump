// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@class CDMachOFile;

@interface CDCPlusPlusDumper : NSObject

// Walks the symbol table, demangles every Itanium-mangled C++ symbol, and
// groups the results by the leading class scope. The keys are class names
// (potentially nested with `::`), the values are arrays of demangled
// signature strings — typically full method declarations like
// `int Foo::Bar::doIt(int, double const&) const`.
+ (NSDictionary<NSString *, NSArray<NSString *> *> *)groupedSymbolsByClassFromMachOFile:(CDMachOFile *)machOFile;

// Returns a single header-style listing of all classes and their methods.
+ (NSString *)dumpHeaderForMachOFile:(CDMachOFile *)machOFile;

// Writes one .h per class into outDir.
+ (BOOL)writeHeadersForMachOFile:(CDMachOFile *)machOFile toDirectory:(NSString *)outDir error:(NSError **)error;

// Demangle a single Itanium-mangled (Mach-O `__Z…`) C symbol. Returns the
// original string if not mangled or if libc++abi rejects it.
+ (NSString *)demangle:(NSString *)mangled;

@end
