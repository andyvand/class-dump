// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import <Foundation/Foundation.h>

@class CDClassDump, CDMachOFile;

// Emit a per-image listing of every routine (function) in `mf`, joining
// LC_FUNCTION_STARTS, LC_SYMTAB and (when available) the Objective-C runtime
// metadata that `classDump` has already processed.
//
// Each line is one routine, sorted by ascending vmaddr. Output columns:
//   ADDR  size  segment,section  kind  name [demangled] [objc-binding]
// where `kind` is one of:
//   objc  — address matches an Objective-C method IMP
//   cxx   — symbol is Itanium-mangled C++
//   swift — symbol is Swift-mangled
//   func  — has a regular C / external symbol
//   sub   — no symbol; addr came purely from LC_FUNCTION_STARTS (synthesized
//           name like `sub_<offset>`)
//
// Used by --dsc-class-dump to label every routine in each dumped image so
// dyld_shared_cache slices that lost their LC_SYMTAB locals are still legible.
@interface CDRoutineDumper : NSObject

// Writes `<outDir>/<binary>.routines.txt`. Returns NO and fills *error on
// I/O failure; returns YES (and writes a stub-with-banner file) when the
// image has no LC_FUNCTION_STARTS / LC_SYMTAB to consult.
+ (BOOL)writeRoutinesForMachOFile:(CDMachOFile *)mf
                        classDump:(CDClassDump *)classDump
                      toDirectory:(NSString *)outDir
                            error:(NSError **)error;

@end
