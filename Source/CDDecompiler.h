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
// _$s / $S / _$S) and writes Swift-shaped output to `outputSwiftPath`:
// functions are grouped under their owning type as
//     class Module.Type { func foo(...) -> T { ... } }
// and bodies are translated heuristically from Ghidra pseudo-C into
// Swift-ish syntax (swift_retain/release stripped, `->` rewritten to
// `.`, C casts removed). If the binary contains no Swift functions the
// file is deleted after the run and YES is returned. Same temp-dir
// lifecycle as -decompileMachO.
//
// NOTE: the output is a Swift-shaped sketch, not real compilable Swift
// source; it is meant for reading and grepping, not feeding back to a
// compiler.
+ (BOOL)decompileSwiftMachOAtPath:(NSString *)inputPath
                           toPath:(NSString *)outputSwiftPath
                            error:(NSError **)error;

// Decompiles only the Objective-C method IMPs (functions whose name is
// `-[Class sel]` or `+[Class sel]`, as labelled by Ghidra's ObjC
// analyzer from __objc_classlist / __objc_methlist metadata) and writes
// ObjC-shaped output to `outputObjcPath`: methods are grouped by class
// as
//     @implementation Class
//     - (id)foo:(id)arg0 { ... }
//     @end
// and bodies are translated heuristically from Ghidra pseudo-C into
// Obj-C-ish syntax (objc_msgSend(recv,"sel",args) rewritten as
// [recv sel:args], ARC retain/release/autorelease calls dropped,
// _OBJC_CLASS_$_Foo rewritten as [Foo class]). If the binary contains
// no Obj-C method IMPs the file is deleted after the run and YES is
// returned. Same temp-dir lifecycle as -decompileMachO.
//
// NOTE: the output is an ObjC-shaped sketch, not real compilable
// Objective-C source.
+ (BOOL)decompileObjcMachOAtPath:(NSString *)inputPath
                          toPath:(NSString *)outputObjcPath
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
