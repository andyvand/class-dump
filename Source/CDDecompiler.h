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

// Decompiles only the Swift-mangled functions (names beginning with $s /
// _$s / $S / _$S) and writes the demangled-name pseudo-C output to
// `outputSwiftPath`. If the binary contains no Swift functions the file
// is deleted after the run and YES is returned (so callers can ignore
// "no Swift" as a non-error). Same temp-dir lifecycle as -decompileMachO.
//
// NOTE: Ghidra emits pseudo-C, not real Swift source. The .swift
// extension is a convention for downstream tooling.
+ (BOOL)decompileSwiftMachOAtPath:(NSString *)inputPath
                           toPath:(NSString *)outputSwiftPath
                            error:(NSError **)error;

// Decompiles only the Itanium-mangled C++ functions (names beginning
// with _Z / __Z) and writes the demangled-name pseudo-C output to
// `outputCppPath`. Before decompiling each function the demangler is
// applied to its symbol so the resulting pseudo-C carries the
// declared return type and parameter types from the mangle rather
// than Ghidra's default `undefined` placeholders. If the binary
// contains no C++ functions the file is deleted after the run and
// YES is returned. Same temp-dir lifecycle as -decompileMachO.
+ (BOOL)decompileCppMachOAtPath:(NSString *)inputPath
                         toPath:(NSString *)outputCppPath
                          error:(NSError **)error;

@end

extern NSString *CDErrorDomain_Decompiler;
