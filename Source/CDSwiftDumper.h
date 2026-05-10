// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@class CDMachOFile;

@interface CDSwiftDumper : NSObject

// Group every Swift-mangled symbol in LC_SYMTAB by parent type/extension.
// Keys are demangled scope strings (e.g. "Foundation.NSString",
// "(extension in Foundation):Swift.String"); values are arrays of demangled
// member signatures.
+ (NSDictionary<NSString *, NSArray<NSString *> *> *)groupedSymbolsFromMachOFile:(CDMachOFile *)machOFile;

// Returns a single Swift-flavoured "header" listing of all types found.
+ (NSString *)dumpHeaderForMachOFile:(CDMachOFile *)machOFile;

// Writes one .swift per type into outDir.
+ (BOOL)writeHeadersForMachOFile:(CDMachOFile *)machOFile toDirectory:(NSString *)outDir error:(NSError **)error;

@end
