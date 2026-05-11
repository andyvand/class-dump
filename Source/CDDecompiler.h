// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.
//
//  Drives Ghidra's headless analyzer to produce a pseudo-C decompilation of
//  a Mach-O input. The Ghidra install is discovered at runtime via the
//  GHIDRA_HOME environment variable, falling back to common install paths.

@interface CDDecompiler : NSObject

// Returns the discovered Ghidra install root (the directory containing
// support/analyzeHeadless), or nil if none was found.
+ (NSString *)findGhidraHome;

// Returns a human-readable description of where Ghidra is expected to be
// found. Used for error messages when -findGhidraHome returns nil.
+ (NSString *)installHint;

// Decompiles the Mach-O file at `inputPath` and writes the resulting
// pseudo-C to `outputCPath`. Returns YES on success; on failure populates
// `error` and writes nothing.
//
// Internally: creates a temp Ghidra project and script directory, drops
// the bundled CDDecompile.java script, spawns analyzeHeadless via NSTask,
// captures stderr for diagnostics, and tears the temp dir down afterwards.
+ (BOOL)decompileMachOAtPath:(NSString *)inputPath
                      toPath:(NSString *)outputCPath
                       error:(NSError **)error;

@end

extern NSString *CDErrorDomain_Decompiler;
