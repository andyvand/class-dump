// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#include <stdio.h>
#include <libc.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/wait.h>
#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>

#import "CDClassDump.h"
#import "CDFindMethodVisitor.h"
#import "CDClassDumpVisitor.h"
#import "CDMultiFileVisitor.h"
#import "CDFile.h"
#import "CDMachOFile.h"
#import "CDLCSymbolTable.h"
#import "CDFatFile.h"
#import "CDFatArch.h"
#import "CDSearchPathState.h"
#import "CDMachOWriter.h"
#import "CDDyldCache.h"
#import "CDLCFilesetEntry.h"
#import "CDLoadCommand.h"
#import "CDCPlusPlusDumper.h"
#import "CDSwiftDumper.h"
#import "CDDecompiler.h"
#import "CDFilesetExtractor.h"
#import "CDIOKitDumper.h"
#import "CDKernelCache.h"
#import "CDRoutineDumper.h"

void print_usage(void)
{
    fprintf(stderr,
            "class-dump %s\n"
            "Usage: class-dump [options] <mach-o-file>\n"
            "\n"
            "  where options are:\n"
            "        -a             show instance variable offsets\n"
            "        -A             show implementation addresses\n"
            "        --arch <arch>  choose a specific architecture from a universal binary (ppc, ppc64, i386, x86_64, armv6, armv7, armv7s, arm64)\n"
            "        -C <regex>     only display classes matching regular expression\n"
            "        -f <str>       find string in method name\n"
            "        -H             generate header files in current directory, or directory specified with -o\n"
            "        -I             sort classes, categories, and protocols by inheritance (overrides -s)\n"
            "        -o <dir>       output directory used for -H\n"
            "        -r             recursively expand frameworks and fixed VM shared libraries\n"
            "        -s             sort classes and categories by name\n"
            "        -S             sort methods by name\n"
            "        -t             suppress header in output, for testing\n"
            "        --list-arches  list the arches in the file, then exit\n"
            "        --sdk-ios      specify iOS SDK version (will look for /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS<version>.sdk\n"
            "                       or /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS<version>.sdk)\n"
            "        --sdk-mac      specify Mac OS X version (will look for /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX<version>.sdk\n"
            "                       or /Developer/SDKs/MacOSX<version>.sdk)\n"
            "        --sdk-root     specify the full SDK root path (or use --sdk-ios/--sdk-mac for a shortcut)\n"
            "        --show-mach-header   dump the Mach-O header and exit\n"
            "        --show-load-commands dump the Mach-O load commands and exit\n"
            "        --lipo-info          list architectures in a fat archive and exit\n"
            "        --thin <arch>        extract a single architecture (with --out FILE)\n"
            "        --out <file>         output path for write/extract operations\n"
            "        --id <name>          set LC_ID_DYLIB (must fit in original space)\n"
            "        --change OLD,NEW     change LC_LOAD_DYLIB / LC_REEXPORT_DYLIB / etc. matching OLD\n"
            "        --rpath OLD,NEW      change LC_RPATH matching OLD\n"
            "        --add-rpath <path>   add LC_RPATH (uses load command region slack)\n"
            "        --delete-rpath <path>delete LC_RPATH\n"
            "        --strip-codesig      remove LC_CODE_SIGNATURE and trailing signature data\n"
            "        --dsc-info           print dyld_shared_cache header info\n"
            "        --dsc-list-images    list all images in a dyld_shared_cache\n"
            "        --list-fileset       list LC_FILESET_ENTRY entries (kernelcache)\n"
            "        --extract-fileset NAME --out FILE\n"
            "                             extract a fileset entry by name (raw slice)\n"
            "        --fileset-class-dump --out OUTDIR\n"
            "                             walk every LC_FILESET_ENTRY in a fileset kernelcache and\n"
            "                             dump headers for each contained kext into\n"
            "                             OUTDIR/<entry-id>/. Without --cpp/--swift this emits the\n"
            "                             usual Objective-C header bundle (-H equivalent);\n"
            "                             combine with --cpp for C++ headers derived from the\n"
            "                             kext's LC_SYMTAB (kexts are mostly C++), and/or\n"
            "                             --swift for Swift extensions. Combine with --decompile,\n"
            "                             --decompile-swift, --decompile-cpp and/or --decompile-objc\n"
            "                             to additionally rebase each kext into a stand-alone Mach-O\n"
            "                             (segments and __LINKEDIT slice copied out, fileoffs\n"
            "                             rewritten) and run Ghidra on it; the resulting\n"
            "                             .c/.swift/.cpp/.m file is written into the same\n"
            "                             OUTDIR/<entry-id>/ directory.\n"
            "        --decompress --out FILE\n"
            "                             decompress a 'comp' (LZSS/LZVN) prelinked kernel or a\n"
            "                             bare LZFSE stream and write the raw bytes to FILE\n"
            "        --decrypt --out FILE\n"
            "                             unwrap an IMG4/IM4P kernelcache (and expand its inner\n"
            "                             LZFSE/LZSS payload) and write the result to FILE\n"
            "        --compress lzss|lzvn|lzfse --out FILE\n"
            "                             re-compress a raw kernel into a 'comp' container (lzss/\n"
            "                             lzvn) or a bare LZFSE stream and write it to FILE.\n"
            "                             Compressed/encrypted kernelcaches are also unwrapped\n"
            "                             automatically on the normal class-dump / --*-fileset path.\n"
            "        --dsc-extract DIR    extract every dylib from a dyld_shared_cache to DIR\n"
            "                             (uses Apple's dsc_extractor.bundle from Xcode).\n"
            "                             Combine with --cpp / --swift to additionally write C++\n"
            "                             and Swift header dumps (one .h/.swift per type) into\n"
            "                             <DIR>/<install-path>.cpp_h/ and .swift_h/ subdirs.\n"
            "        --with-cache FILE    use a dyld_shared_cache file to resolve selectors and\n"
            "                             type strings when class-dumping cache-extracted dylibs\n"
            "        --cpp                dump C++ classes (from LC_SYMTAB Itanium-mangled symbols)\n"
            "        --swift              dump Swift extensions/types (from LC_SYMTAB mangled symbols,\n"
            "                             demangled via libswiftCore swift_demangle)\n"
            "        --dsc-class-dump CACHE_OR_DIR --out OUTDIR\n"
            "                             extract every dylib from a cache (or use already-extracted\n"
            "                             dir) and class-dump each into OUTDIR/<install-path>/\n"
            "                             (combine with --cpp and/or --swift to additionally write\n"
            "                             C++ .h files and Swift .swift files per image).\n"
            "                             Each image is dumped in an isolated child class-dump\n"
            "                             process so that a hang or crash in one image (e.g.\n"
            "                             WebKit) cannot stall the rest of the batch.\n"
            "                             Always writes <basename>.routines.txt next to the\n"
            "                             headers: one line per function in the image, joining\n"
            "                             LC_FUNCTION_STARTS + LC_SYMTAB + ObjC method IMPs and\n"
            "                             demangling C++/Swift names, so every routine is\n"
            "                             labelled (synthesized `sub_<addr>` for unnamed code).\n"
            "        --dsc-image-timeout SEC\n"
            "                             per-image wall-clock timeout for --dsc-class-dump\n"
            "                             (default 180s; 0 disables; child is SIGTERM'd then\n"
            "                             SIGKILL'd on timeout and reported as failed). While\n"
            "                             waiting, the parent prints a heartbeat every 15s\n"
            "                             naming the stuck worker's pid so you can `sample` it.\n"
            "        --dsc-skip-existing  with --dsc-class-dump, skip images whose output subdir\n"
            "                             already exists and is non-empty (resumable batch runs).\n"
            "        --dsc-in-process     with --dsc-class-dump, run all images in-process (legacy\n"
            "                             behaviour). A hang in one image stops the whole batch.\n"
            "        --scan-dir DIR       recursively scan DIR for Mach-O/dylib files and feed their\n"
            "                             Objective-C type encodings into a shared type pool so that\n"
            "                             struct/union/protocol references in the primary binary get\n"
            "                             resolved to fuller definitions across the binary set\n"
            "                             (repeatable; pool images themselves are not emitted)\n"
            "        --auto-scan          also scan the input file's containing directory as a\n"
            "                             --scan-dir pool source (excluding the input itself)\n"
            "        --decompile          run Ghidra's headless decompiler over each extracted\n"
            "                             or class-dumped binary, writing a pseudo-C .c file\n"
            "                             next to the .h output (requires Ghidra; honors\n"
            "                             $GHIDRA_HOME or searches /Applications/ghidra*, ~/ghidra*,\n"
            "                             /opt/ghidra*, /opt/homebrew/Caskroom/ghidra/*).\n"
            "                             Hooks into --dsc-class-dump, --dsc-extract, and\n"
            "                             --extract-fileset; also runs on a plain class-dump.\n"
            "        --decompile-swift    like --decompile, but emits a <binary>.swift file\n"
            "                             containing only Swift-mangled functions, demangled\n"
            "                             via Ghidra's Swift demangler and grouped under their\n"
            "                             owning type as `class Module.Type { func ... }`. The\n"
            "                             bodies are heuristically translated from Ghidra\n"
            "                             pseudo-C into Swift-ish syntax (output is a Swift-\n"
            "                             shaped sketch, not real compilable Swift).\n"
            "                             Can be combined with --decompile.\n"
            "        --decompile-objc     like --decompile, but emits a <binary>.m file\n"
            "                             containing only Objective-C method IMPs\n"
            "                             (`-[Class sel]` / `+[Class sel]`), grouped by class\n"
            "                             into `@implementation ... @end` blocks. Bodies are\n"
            "                             heuristically translated: objc_msgSend rewrites to\n"
            "                             `[recv sel:args]`, ARC retain/release calls drop out,\n"
            "                             `_OBJC_CLASS_$_Foo` rewrites to `[Foo class]`. Output\n"
            "                             is an ObjC-shaped sketch, not compilable source.\n"
            "                             Can be combined with --decompile / --decompile-swift /\n"
            "                             --decompile-cpp.\n"
            "        --decompile-cpp      like --decompile, but emits a <binary>.cpp file\n"
            "                             containing only Itanium-mangled C++ functions, with\n"
            "                             their names demangled and return/parameter types\n"
            "                             applied from the mangle before decompiling (so the\n"
            "                             pseudo-C signatures carry real types rather than\n"
            "                             Ghidra's `undefined` placeholders).\n"
            "                             Can be combined with --decompile and --decompile-swift.\n"
            ,
            CLASS_DUMP_VERSION
       );
}

#define CD_OPT_ARCH        1
#define CD_OPT_LIST_ARCHES 2
#define CD_OPT_VERSION     3
#define CD_OPT_SDK_IOS     4
#define CD_OPT_SDK_MAC     5
#define CD_OPT_SDK_ROOT    6
#define CD_OPT_HIDE        7
#define CD_OPT_SHOW_LC     8
#define CD_OPT_SHOW_HEADER 9
#define CD_OPT_OUT         20
#define CD_OPT_SET_ID      21
#define CD_OPT_CHANGE      22
#define CD_OPT_RPATH_CHG   23
#define CD_OPT_RPATH_ADD   24
#define CD_OPT_RPATH_DEL   25
#define CD_OPT_STRIP_SIG   26
#define CD_OPT_THIN        27
#define CD_OPT_LIPO_INFO   28
#define CD_OPT_DSC_INFO    30
#define CD_OPT_DSC_IMAGES  31
#define CD_OPT_FILESET_LS  32
#define CD_OPT_FILESET_EX  33
#define CD_OPT_DSC_EXTRACT 34
#define CD_OPT_WITH_CACHE  35
#define CD_OPT_CPP         36
#define CD_OPT_DSC_DUMPALL 37
#define CD_OPT_SWIFT       38
#define CD_OPT_SCAN_DIR    39
#define CD_OPT_AUTO_SCAN   40
#define CD_OPT_DECOMPILE   41
#define CD_OPT_DECOMPILE_SWIFT 42
#define CD_OPT_DECOMPILE_CPP 43
#define CD_OPT_DECOMPILE_OBJC 52
#define CD_OPT_DSC_TIMEOUT       44
#define CD_OPT_DSC_SKIP_EXISTING 45
#define CD_OPT_DSC_IN_PROCESS    46
#define CD_OPT_DSC_WORKER        47
#define CD_OPT_FILESET_DUMPALL   48
#define CD_OPT_DECOMPRESS        49
#define CD_OPT_DECRYPT           50
#define CD_OPT_COMPRESS          51

// Resolve the absolute path to the currently running class-dump executable.
// Used by --dsc-class-dump to re-spawn self as a per-image worker.
static NSString *CDExecutablePath(void)
{
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0) {
        // Buffer was too small — try once more with the needed size.
        char *dyn = malloc(size);
        if (dyn == NULL) return nil;
        if (_NSGetExecutablePath(dyn, &size) != 0) { free(dyn); return nil; }
        NSString *r = [NSString stringWithUTF8String:dyn];
        free(dyn);
        return [r stringByStandardizingPath];
    }
    return [[NSString stringWithUTF8String:buf] stringByStandardizingPath];
}

// Returns YES if the directory exists and has at least one entry (any file).
static BOOL CDDirectoryHasOutput(NSString *dir)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) return NO;
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:dir];
    for (NSString *child in en) {
        (void)child;
        return YES;
    }
    return NO;
}

// Run a child class-dump with argv `args` and wait up to `timeoutSec`
// seconds. If timeoutSec <= 0, wait indefinitely.
// `label` is used in heartbeat lines so the user can identify which image
// the worker is processing. The parent prints a heartbeat every 15s while
// waiting (with the worker's pid, so a stuck process can be `sample`d).
// Returns:
//   0   — child exited 0 (success)
//  -1   — child failed to launch
//  -2   — child was killed because it exceeded the timeout
// other — child exit status (non-zero)
static int CDRunChildWithTimeout(NSString *exePath,
                                 NSArray<NSString *> *args,
                                 double timeoutSec,
                                 NSString *label)
{
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = exePath;
    task.arguments = args;
    // Inherit stdout/stderr so the child's messages are visible.
    task.standardInput = [NSFileHandle fileHandleWithNullDevice];

    @try {
        if (@available(macOS 10.13, *)) {
            NSError *e = nil;
            if (![task launchAndReturnError:&e]) return -1;
        } else {
            [task launch];
        }
    } @catch (NSException *exc) {
        return -1;
    }

    pid_t childPid = task.processIdentifier;
    fprintf(stderr, "class-dump: spawned worker pid %d for %s\n",
            childPid, [label UTF8String] ?: "");
    fflush(stderr);

    if (timeoutSec <= 0.0) {
        [task waitUntilExit];
        return [task terminationStatus];
    }

    // Poll the task and print a heartbeat every 15 s so the user can see
    // which worker is still active and `sample` it if needed.
    NSTimeInterval start = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval lastBeat = start;
    const useconds_t kPollUs = 100 * 1000; // 100 ms
    const NSTimeInterval kHeartbeatSec = 15.0;
    while ([task isRunning]) {
        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
        NSTimeInterval elapsed = now - start;
        if (elapsed >= timeoutSec) {
            fprintf(stderr,
                    "class-dump: child pid %d exceeded %.0fs on %s — SIGTERM\n",
                    childPid, timeoutSec, [label UTF8String] ?: "");
            fflush(stderr);
            kill(childPid, SIGTERM);
            NSTimeInterval graceStart = [NSDate timeIntervalSinceReferenceDate];
            while ([task isRunning] && ([NSDate timeIntervalSinceReferenceDate] - graceStart) < 3.0) {
                usleep(kPollUs);
            }
            if ([task isRunning]) {
                fprintf(stderr, "class-dump: child pid %d ignored SIGTERM — SIGKILL\n", childPid);
                fflush(stderr);
                kill(childPid, SIGKILL);
                [task waitUntilExit];
            }
            return -2;
        }
        if (now - lastBeat >= kHeartbeatSec) {
            fprintf(stderr,
                    "class-dump: still waiting on pid %d (%.0fs / %.0fs) %s\n",
                    childPid, elapsed, timeoutSec, [label UTF8String] ?: "");
            fflush(stderr);
            lastBeat = now;
        }
        usleep(kPollUs);
    }
    return [task terminationStatus];
}

// Process a single Mach-O image: class-dump (multi-file) into outDir, then
// optionally also write C++/Swift symbol-derived headers and run the Ghidra
// decompilers, all into outDir. backingCache, if non-nil, is used for
// cross-image type/selector resolution.
// Returns 0 on success, 1 if the file could not be parsed, 2 if class-dump
// raised an Objective-C exception during processing.
static int CDDumpSingleImage(NSString *fullPath,
                             NSString *outDir,
                             CDDyldCache *backingCache,
                             BOOL dumpCpp,
                             BOOL dumpSwift,
                             BOOL decompile,
                             BOOL decompileSwift,
                             BOOL decompileCpp,
                             BOOL decompileObjc)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:NULL];

    @autoreleasepool {
        CDClassDump *cd = [[CDClassDump alloc] init];
        if (backingCache) cd.backingCache = backingCache;
        cd.searchPathState.executablePath = [fullPath stringByDeletingLastPathComponent];

        CDFile *file = [CDFile fileWithContentsOfFile:fullPath searchPathState:cd.searchPathState];
        if (file == nil) return 1;
        CDArch arch;
        if (![file bestMatchForLocalArch:&arch]) return 1;
        cd.targetArch = arch;
        NSError *err = nil;
        if (![cd loadFile:file error:&err]) return 1;

        @try {
            [cd processObjectiveCData];
            [cd registerTypes];
            CDMultiFileVisitor *v = [[CDMultiFileVisitor alloc] init];
            v.classDump = cd;
            cd.typeController.delegate = v;
            v.outputPath = outDir;
            [cd recursivelyVisit:v];

            // Always emit a routine listing alongside the headers so every
            // function in the image is labelled, including non-ObjC code.
            {
                CDMachOFile *mf = [cd.machOFiles lastObject];
                if (mf) {
                    NSError *re = nil;
                    if (![CDRoutineDumper writeRoutinesForMachOFile:mf
                                                          classDump:cd
                                                        toDirectory:outDir
                                                              error:&re]) {
                        fprintf(stderr, "class-dump: routine dump failed: %s\n",
                                [[re localizedDescription] UTF8String]);
                    }
                }
            }

            if (dumpCpp || dumpSwift) {
                CDMachOFile *mf = [cd.machOFiles lastObject];
                if (mf) {
                    if (dumpCpp) {
                        NSError *e = nil;
                        if (![CDCPlusPlusDumper writeHeadersForMachOFile:mf toDirectory:outDir error:&e]) {
                            fprintf(stderr, "class-dump: cpp dump failed: %s\n",
                                    [[e localizedDescription] UTF8String]);
                        }
                    }
                    if (dumpSwift) {
                        NSError *e = nil;
                        if (![CDSwiftDumper writeHeadersForMachOFile:mf toDirectory:outDir error:&e]) {
                            fprintf(stderr, "class-dump: swift dump failed: %s\n",
                                    [[e localizedDescription] UTF8String]);
                        }
                    }
                }
            }

            NSString *base = [fullPath lastPathComponent];
            if (decompile) {
                NSString *cOut = [outDir stringByAppendingPathComponent:
                                  [base stringByAppendingPathExtension:@"c"]];
                NSError *de = nil;
                if (![CDDecompiler decompileMachOAtPath:fullPath toPath:cOut error:&de]) {
                    fprintf(stderr, "class-dump: decompile failed: %s\n",
                            [[de localizedFailureReason] UTF8String]);
                }
            }
            if (decompileSwift) {
                NSString *sOut = [outDir stringByAppendingPathComponent:
                                  [base stringByAppendingPathExtension:@"swift"]];
                NSError *de = nil;
                if (![CDDecompiler decompileSwiftMachOAtPath:fullPath toPath:sOut error:&de]) {
                    fprintf(stderr, "class-dump: decompile-swift failed: %s\n",
                            [[de localizedFailureReason] UTF8String]);
                }
            }
            if (decompileCpp) {
                NSString *cppOut = [outDir stringByAppendingPathComponent:
                                    [base stringByAppendingPathExtension:@"cpp"]];
                NSError *de = nil;
                if (![CDDecompiler decompileCppMachOAtPath:fullPath toPath:cppOut error:&de]) {
                    fprintf(stderr, "class-dump: decompile-cpp failed: %s\n",
                            [[de localizedFailureReason] UTF8String]);
                }
            }
            if (decompileObjc) {
                NSString *mOut = [outDir stringByAppendingPathComponent:
                                  [base stringByAppendingPathExtension:@"m"]];
                NSError *de = nil;
                if (![CDDecompiler decompileObjcMachOAtPath:fullPath toPath:mOut error:&de]) {
                    fprintf(stderr, "class-dump: decompile-objc failed: %s\n",
                            [[de localizedFailureReason] UTF8String]);
                }
            }
        } @catch (NSException *e) {
            fprintf(stderr, "class-dump: exception while dumping %s: %s\n",
                    [fullPath UTF8String], [[e reason] UTF8String]);
            return 2;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    @autoreleasepool {
        NSString *searchString;
        BOOL shouldGenerateSeparateHeaders = NO;
        BOOL shouldListArches = NO;
        BOOL shouldPrintVersion = NO;
        CDArch targetArch;
        BOOL hasSpecifiedArch = NO;
        NSString *outputPath;
        NSMutableSet *hiddenSections = [NSMutableSet set];

        int ch;
        BOOL errorFlag = NO;

        struct option longopts[] = {
            { "show-ivar-offsets",       no_argument,       NULL, 'a' },
            { "show-imp-addr",           no_argument,       NULL, 'A' },
            { "match",                   required_argument, NULL, 'C' },
            { "find",                    required_argument, NULL, 'f' },
            { "generate-multiple-files", no_argument,       NULL, 'H' },
            { "sort-by-inheritance",     no_argument,       NULL, 'I' },
            { "output-dir",              required_argument, NULL, 'o' },
            { "recursive",               no_argument,       NULL, 'r' },
            { "sort",                    no_argument,       NULL, 's' },
            { "sort-methods",            no_argument,       NULL, 'S' },
            { "arch",                    required_argument, NULL, CD_OPT_ARCH },
            { "list-arches",             no_argument,       NULL, CD_OPT_LIST_ARCHES },
            { "suppress-header",         no_argument,       NULL, 't' },
            { "version",                 no_argument,       NULL, CD_OPT_VERSION },
            { "sdk-ios",                 required_argument, NULL, CD_OPT_SDK_IOS },
            { "sdk-mac",                 required_argument, NULL, CD_OPT_SDK_MAC },
            { "sdk-root",                required_argument, NULL, CD_OPT_SDK_ROOT },
            { "hide",                    required_argument, NULL, CD_OPT_HIDE },
            { "show-load-commands",      no_argument,       NULL, CD_OPT_SHOW_LC },
            { "show-mach-header",        no_argument,       NULL, CD_OPT_SHOW_HEADER },
            { "out",                     required_argument, NULL, CD_OPT_OUT },
            { "id",                      required_argument, NULL, CD_OPT_SET_ID },
            { "change",                  required_argument, NULL, CD_OPT_CHANGE },
            { "rpath",                   required_argument, NULL, CD_OPT_RPATH_CHG },
            { "add-rpath",               required_argument, NULL, CD_OPT_RPATH_ADD },
            { "delete-rpath",            required_argument, NULL, CD_OPT_RPATH_DEL },
            { "strip-codesig",           no_argument,       NULL, CD_OPT_STRIP_SIG },
            { "thin",                    required_argument, NULL, CD_OPT_THIN },
            { "lipo-info",               no_argument,       NULL, CD_OPT_LIPO_INFO },
            { "dsc-info",                no_argument,       NULL, CD_OPT_DSC_INFO },
            { "dsc-list-images",         no_argument,       NULL, CD_OPT_DSC_IMAGES },
            { "list-fileset",            no_argument,       NULL, CD_OPT_FILESET_LS },
            { "extract-fileset",         required_argument, NULL, CD_OPT_FILESET_EX },
            { "dsc-extract",             required_argument, NULL, CD_OPT_DSC_EXTRACT },
            { "with-cache",              required_argument, NULL, CD_OPT_WITH_CACHE },
            { "cpp",                     no_argument,       NULL, CD_OPT_CPP },
            { "dsc-class-dump",          required_argument, NULL, CD_OPT_DSC_DUMPALL },
            { "swift",                   no_argument,       NULL, CD_OPT_SWIFT },
            { "scan-dir",                required_argument, NULL, CD_OPT_SCAN_DIR },
            { "auto-scan",               no_argument,       NULL, CD_OPT_AUTO_SCAN },
            { "decompile",               no_argument,       NULL, CD_OPT_DECOMPILE },
            { "decompile-swift",         no_argument,       NULL, CD_OPT_DECOMPILE_SWIFT },
            { "decompile-cpp",           no_argument,       NULL, CD_OPT_DECOMPILE_CPP },
            { "decompile-objc",          no_argument,       NULL, CD_OPT_DECOMPILE_OBJC },
            { "dsc-image-timeout",       required_argument, NULL, CD_OPT_DSC_TIMEOUT },
            { "dsc-skip-existing",       no_argument,       NULL, CD_OPT_DSC_SKIP_EXISTING },
            { "dsc-in-process",          no_argument,       NULL, CD_OPT_DSC_IN_PROCESS },
            { "dsc-worker",              no_argument,       NULL, CD_OPT_DSC_WORKER },
            { "fileset-class-dump",      no_argument,       NULL, CD_OPT_FILESET_DUMPALL },
            { "decompress",              no_argument,       NULL, CD_OPT_DECOMPRESS },
            { "decrypt",                 no_argument,       NULL, CD_OPT_DECRYPT },
            { "compress",                required_argument, NULL, CD_OPT_COMPRESS },
            { NULL,                      0,                 NULL, 0 },
        };

        BOOL shouldShowLoadCommands = NO;
        BOOL shouldShowMachHeader = NO;
        NSString *writeOutPath = nil;
        NSString *newDylibID = nil;
        NSString *changeOldPath = nil;
        NSString *changeNewPath = nil;
        NSString *rpathOldPath = nil;
        NSString *rpathNewPath = nil;
        NSMutableArray<NSString *> *addRPaths = [NSMutableArray array];
        NSMutableArray<NSString *> *deleteRPaths = [NSMutableArray array];
        BOOL shouldStripCodesig = NO;
        NSString *thinArch = nil;
        BOOL shouldLipoInfo = NO;
        BOOL shouldDscInfo = NO;
        BOOL shouldDscListImages = NO;
        BOOL shouldListFileset = NO;
        BOOL shouldFilesetClassDump = NO;
        NSString *extractFilesetName = nil;
        BOOL shouldDecompress = NO;
        BOOL shouldDecrypt = NO;
        NSString *compressMethodName = nil;
        NSString *dscExtractDir = nil;
        BOOL shouldDumpCpp = NO;
        BOOL shouldDumpSwift = NO;
        NSString *dscDumpAllInput = nil;
        NSMutableArray<NSString *> *scanDirs = [NSMutableArray array];
        BOOL shouldAutoScan = NO;
        BOOL shouldDecompile = NO;
        BOOL shouldDecompileSwift = NO;
        BOOL shouldDecompileCpp = NO;
        BOOL shouldDecompileObjc = NO;
        double dscImageTimeout = 180.0;
        BOOL dscSkipExisting = NO;
        BOOL dscInProcess = NO;
        BOOL dscWorkerMode = NO;

        if (argc == 1) {
            print_usage();
            exit(0);
        }

        CDClassDump *classDump = [[CDClassDump alloc] init];

        while ( (ch = getopt_long(argc, argv, "aAC:f:HIo:rRsSt", longopts, NULL)) != -1) {
            switch (ch) {
                case CD_OPT_ARCH: {
                    NSString *name = [NSString stringWithUTF8String:optarg];
                    targetArch = CDArchFromName(name);
                    if (targetArch.cputype != CPU_TYPE_ANY)
                        hasSpecifiedArch = YES;
                    else {
                        fprintf(stderr, "Error: Unknown arch %s\n\n", optarg);
                        errorFlag = YES;
                    }
                    break;
                }
                    
                case CD_OPT_LIST_ARCHES:
                    shouldListArches = YES;
                    break;
                    
                case CD_OPT_VERSION:
                    shouldPrintVersion = YES;
                    break;
                    
                case CD_OPT_SDK_IOS: {
                    NSString *root = [NSString stringWithUTF8String:optarg];
                    //NSLog(@"root: %@", root);
                    NSString *str;
                    if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Applications/Xcode.app"]) {
                        str = [NSString stringWithFormat:@"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS%@.sdk", root];
                    } else if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Developer"]) {
                        str = [NSString stringWithFormat:@"/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS%@.sdk", root];
                    }
                    classDump.sdkRoot = str;
                    
                    break;
                }
                    
                case CD_OPT_SDK_MAC: {
                    NSString *root = [NSString stringWithUTF8String:optarg];
                    //NSLog(@"root: %@", root);
                    NSString *str;
                    if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Applications/Xcode.app"]) {
                        str = [NSString stringWithFormat:@"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX%@.sdk", root];
                    } else if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Developer"]) {
                        str = [NSString stringWithFormat:@"/Developer/SDKs/MacOSX%@.sdk", root];
                    }
                    classDump.sdkRoot = str;
                    
                    break;
                }
                    
                case CD_OPT_SDK_ROOT: {
                    NSString *root = [NSString stringWithUTF8String:optarg];
                    //NSLog(@"root: %@", root);
                    classDump.sdkRoot = root;
                    
                    break;
                }
                    
                case CD_OPT_SHOW_LC:
                    shouldShowLoadCommands = YES;
                    break;

                case CD_OPT_SHOW_HEADER:
                    shouldShowMachHeader = YES;
                    break;

                case CD_OPT_OUT:
                    writeOutPath = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_SET_ID:
                    newDylibID = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_CHANGE: {
                    NSString *arg = [NSString stringWithUTF8String:optarg];
                    NSRange comma = [arg rangeOfString:@","];
                    if (comma.location == NSNotFound) {
                        fprintf(stderr, "class-dump: --change expects OLD,NEW\n");
                        errorFlag = YES;
                        break;
                    }
                    changeOldPath = [arg substringToIndex:comma.location];
                    changeNewPath = [arg substringFromIndex:comma.location + 1];
                    break;
                }

                case CD_OPT_RPATH_CHG: {
                    NSString *arg = [NSString stringWithUTF8String:optarg];
                    NSRange comma = [arg rangeOfString:@","];
                    if (comma.location == NSNotFound) {
                        fprintf(stderr, "class-dump: --rpath expects OLD,NEW\n");
                        errorFlag = YES;
                        break;
                    }
                    rpathOldPath = [arg substringToIndex:comma.location];
                    rpathNewPath = [arg substringFromIndex:comma.location + 1];
                    break;
                }

                case CD_OPT_RPATH_ADD:
                    [addRPaths addObject:[NSString stringWithUTF8String:optarg]];
                    break;

                case CD_OPT_RPATH_DEL:
                    [deleteRPaths addObject:[NSString stringWithUTF8String:optarg]];
                    break;

                case CD_OPT_STRIP_SIG:
                    shouldStripCodesig = YES;
                    break;

                case CD_OPT_THIN:
                    thinArch = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_LIPO_INFO:
                    shouldLipoInfo = YES;
                    break;

                case CD_OPT_DSC_INFO:
                    shouldDscInfo = YES;
                    break;

                case CD_OPT_DSC_IMAGES:
                    shouldDscListImages = YES;
                    break;

                case CD_OPT_FILESET_LS:
                    shouldListFileset = YES;
                    break;

                case CD_OPT_FILESET_EX:
                    extractFilesetName = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_DSC_EXTRACT:
                    dscExtractDir = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_CPP:
                    shouldDumpCpp = YES;
                    break;

                case CD_OPT_DSC_DUMPALL:
                    dscDumpAllInput = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_SWIFT:
                    shouldDumpSwift = YES;
                    break;

                case CD_OPT_SCAN_DIR:
                    [scanDirs addObject:[NSString stringWithUTF8String:optarg]];
                    break;

                case CD_OPT_AUTO_SCAN:
                    shouldAutoScan = YES;
                    break;

                case CD_OPT_DECOMPILE:
                    shouldDecompile = YES;
                    break;

                case CD_OPT_DECOMPILE_SWIFT:
                    shouldDecompileSwift = YES;
                    break;

                case CD_OPT_DECOMPILE_CPP:
                    shouldDecompileCpp = YES;
                    break;

                case CD_OPT_DECOMPILE_OBJC:
                    shouldDecompileObjc = YES;
                    break;

                case CD_OPT_DSC_TIMEOUT: {
                    char *endp = NULL;
                    double v = strtod(optarg, &endp);
                    if (endp == optarg || v < 0) {
                        fprintf(stderr, "class-dump: --dsc-image-timeout: invalid value %s\n", optarg);
                        errorFlag = YES;
                    } else {
                        dscImageTimeout = v;
                    }
                    break;
                }

                case CD_OPT_DSC_SKIP_EXISTING:
                    dscSkipExisting = YES;
                    break;

                case CD_OPT_DSC_IN_PROCESS:
                    dscInProcess = YES;
                    break;

                case CD_OPT_DSC_WORKER:
                    dscWorkerMode = YES;
                    break;

                case CD_OPT_FILESET_DUMPALL:
                    shouldFilesetClassDump = YES;
                    break;

                case CD_OPT_DECOMPRESS:
                    shouldDecompress = YES;
                    break;

                case CD_OPT_DECRYPT:
                    shouldDecrypt = YES;
                    break;

                case CD_OPT_COMPRESS:
                    compressMethodName = [NSString stringWithUTF8String:optarg];
                    break;

                case CD_OPT_WITH_CACHE: {
                    NSString *cachePath = [NSString stringWithUTF8String:optarg];
                    // Use initWithPath: so subcache siblings (`.01`,
                    // `.02.dylddata`, etc.) get mapped too — modern shared
                    // caches are split, and the actual __TEXT/__DATA pages
                    // (including the shared selector pool) live in the
                    // subcaches, not the main file.
                    CDDyldCache *cache = [[CDDyldCache alloc] initWithPath:cachePath];
                    if (cache == nil) {
                        fprintf(stderr, "class-dump: %s is not a dyld_shared_cache\n", optarg);
                        errorFlag = YES;
                        break;
                    }
                    classDump.backingCache = cache;
                    break;
                }

                case CD_OPT_HIDE: {
                    NSString *str = [NSString stringWithUTF8String:optarg];
                    if ([str isEqualToString:@"all"]) {
                        [hiddenSections addObject:@"structures"];
                        [hiddenSections addObject:@"protocols"];
                    } else {
                        [hiddenSections addObject:str];
                    }
                    break;
                }
                    
                case 'a':
                    classDump.shouldShowIvarOffsets = YES;
                    break;
                    
                case 'A':
                    classDump.shouldShowMethodAddresses = YES;
                    break;
                    
                case 'C': {
                    NSError *error;
                    NSRegularExpression *regularExpression = [NSRegularExpression regularExpressionWithPattern:[NSString stringWithUTF8String:optarg]
                                                                                                       options:(NSRegularExpressionOptions)0
                                                                                                         error:&error];
                    if (regularExpression != nil) {
                        classDump.regularExpression = regularExpression;
                    } else {
                        fprintf(stderr, "class-dump: Error with regular expression: %s\n\n", [[error localizedFailureReason] UTF8String]);
                        errorFlag = YES;
                    }

                    // Last one wins now.
                    break;
                }
                    
                case 'f': {
                    searchString = [NSString stringWithUTF8String:optarg];
                    break;
                }
                    
                case 'H':
                    shouldGenerateSeparateHeaders = YES;
                    break;
                    
                case 'I':
                    classDump.shouldSortClassesByInheritance = YES;
                    break;
                    
                case 'o':
                    outputPath = [NSString stringWithUTF8String:optarg];
                    break;
                    
                case 'r':
                    classDump.shouldProcessRecursively = YES;
                    break;
                    
                case 's':
                    classDump.shouldSortClasses = YES;
                    break;
                    
                case 'S':
                    classDump.shouldSortMethods = YES;
                    break;
                    
                case 't':
                    classDump.shouldShowHeader = NO;
                    break;
                    
                case '?':
                default:
                    errorFlag = YES;
                    break;
            }
        }

        if (errorFlag) {
            print_usage();
            exit(2);
        }

        if (shouldPrintVersion) {
            printf("class-dump %s compiled %s\n", CLASS_DUMP_VERSION, __DATE__ " " __TIME__);
            exit(0);
        }

        // Fail-fast: if --decompile / --decompile-swift / --decompile-cpp /
        // --decompile-objc was requested but Ghidra cannot be found, tell
        // the user now rather than after the dump has produced its other
        // output.
        if (shouldDecompile || shouldDecompileSwift || shouldDecompileCpp || shouldDecompileObjc) {
            NSString *gh = [CDDecompiler findGhidraHome];
            if (gh == nil) {
                const char *which = shouldDecompile      ? ""        :
                                    shouldDecompileSwift ? "-swift"  :
                                    shouldDecompileObjc  ? "-objc"   :
                                                           "-cpp";
                fprintf(stderr, "class-dump: --decompile%s: Ghidra not found.\n%s\n",
                        which, [[CDDecompiler installHint] UTF8String]);
                exit(1);
            }
            // Suppress the banner in worker mode so the parent's batch output
            // isn't spammed with one of these per image.
            if (!dscWorkerMode) {
                fprintf(stderr, "class-dump: decompile: using Ghidra at %s\n", [gh UTF8String]);
            }
        }

        // --dsc-worker: internal mode used when --dsc-class-dump re-spawns
        // this binary per image. It expects a single positional Mach-O path
        // and --out OUTDIR. All other flags (--cpp/--swift/--decompile*) are
        // honoured. Failure is signalled via exit code.
        if (dscWorkerMode) {
            if (optind >= argc || writeOutPath == nil) {
                fprintf(stderr, "class-dump: --dsc-worker: usage: --dsc-worker --out OUT FILE\n");
                exit(2);
            }
            NSString *full = [NSString stringWithFileSystemRepresentation:argv[optind]];
            int rc = CDDumpSingleImage(full, writeOutPath, classDump.backingCache,
                                       shouldDumpCpp, shouldDumpSwift,
                                       shouldDecompile, shouldDecompileSwift, shouldDecompileCpp,
                                       shouldDecompileObjc);
            exit(rc);
        }

        if (dscDumpAllInput) {
            if (writeOutPath == nil) {
                fprintf(stderr, "class-dump: --dsc-class-dump requires --out DIR\n");
                exit(1);
            }
            NSFileManager *fm = [NSFileManager defaultManager];
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:dscDumpAllInput isDirectory:&isDir]) {
                fprintf(stderr, "class-dump: %s does not exist\n", [dscDumpAllInput UTF8String]);
                exit(1);
            }

            NSString *extractedDir = dscDumpAllInput;
            CDDyldCache *bulkCache = classDump.backingCache;

            if (!isDir) {
                // Treat as a cache file: extract first to a temp dir, then walk.
                NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:
                                 [@"class-dump-dsc-" stringByAppendingString:[[NSUUID UUID] UUIDString]]];
                if (![fm createDirectoryAtPath:tmp withIntermediateDirectories:YES attributes:nil error:NULL]) {
                    fprintf(stderr, "class-dump: cannot create %s\n", [tmp UTF8String]);
                    exit(1);
                }
                static NSString * const kBundleSearchPaths[] = {
                    @"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle",
                    @"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/usr/lib/dsc_extractor.bundle",
                    @"/Applications/Xcode.app/Contents/Developer/Platforms/AppleTVOS.platform/usr/lib/dsc_extractor.bundle",
                    @"/Applications/Xcode.app/Contents/Developer/Platforms/WatchOS.platform/usr/lib/dsc_extractor.bundle",
                    @"/Applications/Xcode.app/Contents/Developer/Platforms/XROS.platform/usr/lib/dsc_extractor.bundle",
                };
                void *bundle = NULL;
                for (size_t i = 0; i < sizeof(kBundleSearchPaths)/sizeof(kBundleSearchPaths[0]); i++) {
                    if ([fm fileExistsAtPath:kBundleSearchPaths[i]]) {
                        bundle = dlopen([kBundleSearchPaths[i] fileSystemRepresentation], RTLD_LAZY);
                        if (bundle) break;
                    }
                }
                if (bundle == NULL) {
                    fprintf(stderr, "class-dump: dsc_extractor.bundle not found\n");
                    exit(1);
                }
                int (*extract)(const char *, const char *, void (^)(unsigned, unsigned)) =
                    dlsym(bundle, "dyld_shared_cache_extract_dylibs_progress");
                if (extract == NULL) {
                    fprintf(stderr, "class-dump: dyld_shared_cache_extract_dylibs_progress not found\n");
                    exit(1);
                }
                fprintf(stderr, "class-dump: extracting cache to %s\n", [tmp UTF8String]);
                __block unsigned last = 0;
                int rc = extract([dscDumpAllInput fileSystemRepresentation],
                                 [tmp fileSystemRepresentation],
                                 ^(unsigned cur, unsigned total) {
                    if (cur == total || cur - last >= 100 || cur == 1) {
                        fprintf(stderr, "\rclass-dump: extract %u/%u", cur, total);
                        fflush(stderr);
                        last = cur;
                    }
                });
                fprintf(stderr, "\n");
                if (rc != 0) {
                    fprintf(stderr, "class-dump: extraction failed (rc=%d)\n", rc);
                    exit(1);
                }
                extractedDir = tmp;

                // In-process mode needs the cache loaded here for cross-image
                // resolution. In subprocess mode each worker loads its own
                // copy via --with-cache, so skip the parent-side load.
                if (dscInProcess && bulkCache == nil) {
                    bulkCache = [[CDDyldCache alloc] initWithPath:dscDumpAllInput];
                }
            }

            if (![fm fileExistsAtPath:writeOutPath]) {
                [fm createDirectoryAtPath:writeOutPath withIntermediateDirectories:YES attributes:nil error:NULL];
            }

            // The path passed to child workers as --with-cache, if we have one.
            NSString *childCachePath = (!isDir) ? dscDumpAllInput : nil;

            // Resolve self path for subprocess re-invocation. If we cannot
            // determine it, fall back to in-process mode.
            NSString *selfPath = nil;
            if (!dscInProcess) {
                selfPath = CDExecutablePath();
                if (selfPath == nil) {
                    fprintf(stderr,
                            "class-dump: could not resolve self path; falling back to --dsc-in-process\n");
                    dscInProcess = YES;
                }
            }
            if (!dscInProcess) {
                fprintf(stderr,
                        "class-dump: per-image worker: %s (timeout=%.0fs%s%s)\n",
                        [selfPath UTF8String], dscImageTimeout,
                        dscSkipExisting ? ", skip-existing" : "",
                        childCachePath ? ", with-cache" : "");
            } else {
                // In-process: keep the eagerly-loaded bulkCache for cross-image
                // resolution. (The variable is referenced by the in-process
                // branch below.)
                (void)bulkCache;
            }

            // Walk extractedDir for Mach-O dylibs and class-dump each.
            NSDirectoryEnumerator *en = [fm enumeratorAtPath:extractedDir];
            unsigned processed = 0, succeeded = 0, failed = 0, skipped = 0, timedOut = 0;
            for (NSString *rel in en) {
                NSString *full = [extractedDir stringByAppendingPathComponent:rel];
                NSDictionary *attrs = [en fileAttributes];
                if (![[attrs fileType] isEqualToString:NSFileTypeRegular]) continue;
                if ([attrs fileSize] < 4) continue;

                NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:full];
                NSData *head = [fh readDataOfLength:4];
                [fh closeFile];
                if ([head length] != 4) continue;
                uint32_t magic;
                memcpy(&magic, [head bytes], 4);
                if (magic != MH_MAGIC && magic != MH_MAGIC_64
                    && magic != MH_CIGAM && magic != MH_CIGAM_64
                    && magic != FAT_MAGIC && magic != FAT_CIGAM
                    && magic != FAT_MAGIC_64 && magic != FAT_CIGAM_64) continue;

                NSString *outSub = [writeOutPath stringByAppendingPathComponent:rel];

                if (dscSkipExisting && CDDirectoryHasOutput(outSub)) {
                    skipped++;
                    fprintf(stderr, "class-dump: skip (exists)  %s\n", [rel UTF8String]);
                    fflush(stderr);
                    continue;
                }

                processed++;
                // Always print the current image up-front so a hang is visible.
                fprintf(stderr, "class-dump: [%u] dumping %s\n", processed, [rel UTF8String]);
                fflush(stderr);

                [fm createDirectoryAtPath:outSub withIntermediateDirectories:YES attributes:nil error:NULL];

                if (dscInProcess) {
                    @autoreleasepool {
                        CDClassDump *cd = [[CDClassDump alloc] init];
                        if (bulkCache) cd.backingCache = bulkCache;
                        cd.searchPathState.executablePath = [full stringByDeletingLastPathComponent];
                        CDFile *file = [CDFile fileWithContentsOfFile:full searchPathState:cd.searchPathState];
                        if (file == nil) { failed++; continue; }
                        CDArch arch;
                        if (![file bestMatchForLocalArch:&arch]) { failed++; continue; }
                        cd.targetArch = arch;
                        NSError *err = nil;
                        if (![cd loadFile:file error:&err]) { failed++; continue; }

                        @try {
                            [cd processObjectiveCData];
                            [cd registerTypes];
                            CDMultiFileVisitor *v = [[CDMultiFileVisitor alloc] init];
                            v.classDump = cd;
                            cd.typeController.delegate = v;
                            v.outputPath = outSub;
                            [cd recursivelyVisit:v];

                            {
                                CDMachOFile *mf = [cd.machOFiles lastObject];
                                if (mf) {
                                    NSError *re = nil;
                                    if (![CDRoutineDumper writeRoutinesForMachOFile:mf
                                                                          classDump:cd
                                                                        toDirectory:outSub
                                                                              error:&re]) {
                                        fprintf(stderr, "class-dump: routine dump for %s failed: %s\n",
                                                [rel UTF8String], [[re localizedDescription] UTF8String]);
                                    }
                                }
                            }

                            if (shouldDumpCpp || shouldDumpSwift) {
                                CDMachOFile *mf = [cd.machOFiles lastObject];
                                if (mf) {
                                    if (shouldDumpCpp) {
                                        NSError *e = nil;
                                        if (![CDCPlusPlusDumper writeHeadersForMachOFile:mf toDirectory:outSub error:&e]) {
                                            fprintf(stderr, "class-dump: cpp dump for %s failed: %s\n",
                                                    [rel UTF8String], [[e localizedDescription] UTF8String]);
                                        }
                                    }
                                    if (shouldDumpSwift) {
                                        NSError *e = nil;
                                        if (![CDSwiftDumper writeHeadersForMachOFile:mf toDirectory:outSub error:&e]) {
                                            fprintf(stderr, "class-dump: swift dump for %s failed: %s\n",
                                                    [rel UTF8String], [[e localizedDescription] UTF8String]);
                                        }
                                    }
                                }
                            }

                            if (shouldDecompile) {
                                NSString *cOut = [outSub stringByAppendingPathComponent:
                                                  [[full lastPathComponent] stringByAppendingPathExtension:@"c"]];
                                NSError *de = nil;
                                if (![CDDecompiler decompileMachOAtPath:full toPath:cOut error:&de]) {
                                    fprintf(stderr, "class-dump: decompile %s failed: %s\n",
                                            [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                                }
                            }
                            if (shouldDecompileSwift) {
                                NSString *sOut = [outSub stringByAppendingPathComponent:
                                                  [[full lastPathComponent] stringByAppendingPathExtension:@"swift"]];
                                NSError *de = nil;
                                if (![CDDecompiler decompileSwiftMachOAtPath:full toPath:sOut error:&de]) {
                                    fprintf(stderr, "class-dump: decompile-swift %s failed: %s\n",
                                            [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                                }
                            }
                            if (shouldDecompileCpp) {
                                NSString *cppOut = [outSub stringByAppendingPathComponent:
                                                    [[full lastPathComponent] stringByAppendingPathExtension:@"cpp"]];
                                NSError *de = nil;
                                if (![CDDecompiler decompileCppMachOAtPath:full toPath:cppOut error:&de]) {
                                    fprintf(stderr, "class-dump: decompile-cpp %s failed: %s\n",
                                            [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                                }
                            }
                            if (shouldDecompileObjc) {
                                NSString *mOut = [outSub stringByAppendingPathComponent:
                                                  [[full lastPathComponent] stringByAppendingPathExtension:@"m"]];
                                NSError *de = nil;
                                if (![CDDecompiler decompileObjcMachOAtPath:full toPath:mOut error:&de]) {
                                    fprintf(stderr, "class-dump: decompile-objc %s failed: %s\n",
                                            [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                                }
                            }

                            succeeded++;
                        } @catch (NSException *e) {
                            failed++;
                            fprintf(stderr, "class-dump: exception %s: %s\n",
                                    [rel UTF8String], [[e reason] UTF8String]);
                        }
                    }
                } else {
                    // Spawn class-dump --dsc-worker as a child, kill it if it
                    // exceeds dscImageTimeout. The child's stdout/stderr are
                    // inherited so its errors stay visible to the user.
                    NSMutableArray *childArgs = [NSMutableArray array];
                    [childArgs addObject:@"--dsc-worker"];
                    [childArgs addObject:@"--out"];   [childArgs addObject:outSub];
                    if (childCachePath) {
                        [childArgs addObject:@"--with-cache"]; [childArgs addObject:childCachePath];
                    }
                    if (shouldDumpCpp)        [childArgs addObject:@"--cpp"];
                    if (shouldDumpSwift)      [childArgs addObject:@"--swift"];
                    if (shouldDecompile)      [childArgs addObject:@"--decompile"];
                    if (shouldDecompileSwift) [childArgs addObject:@"--decompile-swift"];
                    if (shouldDecompileCpp)   [childArgs addObject:@"--decompile-cpp"];
                    if (shouldDecompileObjc)  [childArgs addObject:@"--decompile-objc"];
                    [childArgs addObject:full];

                    int rc = CDRunChildWithTimeout(selfPath, childArgs, dscImageTimeout, rel);
                    if (rc == 0) {
                        succeeded++;
                    } else if (rc == -2) {
                        timedOut++;
                        failed++;
                        fprintf(stderr, "class-dump: TIMEOUT (%.0fs)  %s\n",
                                dscImageTimeout, [rel UTF8String]);
                    } else {
                        failed++;
                        fprintf(stderr, "class-dump: failed (rc=%d)  %s\n",
                                rc, [rel UTF8String]);
                    }
                }

                if (processed % 25 == 0) {
                    fprintf(stderr, "class-dump: progress: processed=%u ok=%u fail=%u skip=%u timeout=%u\n",
                            processed, succeeded, failed, skipped, timedOut);
                    fflush(stderr);
                }
            }
            fprintf(stderr,
                    "class-dump: dumped %u images (ok=%u fail=%u skip=%u timeout=%u) into %s\n",
                    processed, succeeded, failed, skipped, timedOut, [writeOutPath UTF8String]);
            exit(0);
        }

        BOOL hasWriteOp = (newDylibID || changeOldPath || rpathOldPath ||
                           [addRPaths count] || [deleteRPaths count] ||
                           shouldStripCodesig || thinArch);

        if (optind < argc && dscExtractDir) {
            NSString *cachePath = [NSString stringWithFileSystemRepresentation:argv[optind]];

            // dyld_shared_cache_extract_dylibs_progress lives in dsc_extractor.bundle
            // (shipped with Xcode). It works on caches for any platform.
            static NSString * const kBundleSearchPaths[] = {
                @"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle",
                @"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/usr/lib/dsc_extractor.bundle",
                @"/Applications/Xcode.app/Contents/Developer/Platforms/AppleTVOS.platform/usr/lib/dsc_extractor.bundle",
                @"/Applications/Xcode.app/Contents/Developer/Platforms/WatchOS.platform/usr/lib/dsc_extractor.bundle",
                @"/Applications/Xcode.app/Contents/Developer/Platforms/XROS.platform/usr/lib/dsc_extractor.bundle",
            };
            void *bundle = NULL;
            NSFileManager *fm = [NSFileManager defaultManager];
            for (size_t i = 0; i < sizeof(kBundleSearchPaths)/sizeof(kBundleSearchPaths[0]); i++) {
                if ([fm fileExistsAtPath:kBundleSearchPaths[i]]) {
                    bundle = dlopen([kBundleSearchPaths[i] fileSystemRepresentation], RTLD_LAZY);
                    if (bundle) break;
                }
            }
            if (bundle == NULL) {
                fprintf(stderr, "class-dump: dsc_extractor.bundle not found in any Xcode platform; install Xcode\n");
                exit(1);
            }
            int (*extract)(const char *, const char *, void (^)(unsigned, unsigned)) =
                dlsym(bundle, "dyld_shared_cache_extract_dylibs_progress");
            if (extract == NULL) {
                fprintf(stderr, "class-dump: dyld_shared_cache_extract_dylibs_progress not found in dsc_extractor.bundle\n");
                exit(1);
            }

            if (![fm fileExistsAtPath:dscExtractDir]) {
                NSError *e = nil;
                if (![fm createDirectoryAtPath:dscExtractDir withIntermediateDirectories:YES attributes:nil error:&e]) {
                    fprintf(stderr, "class-dump: cannot create %s: %s\n",
                            [dscExtractDir UTF8String], [[e localizedDescription] UTF8String]);
                    exit(1);
                }
            }

            __block unsigned lastReported = 0;
            int rc = extract([cachePath fileSystemRepresentation],
                             [dscExtractDir fileSystemRepresentation],
                             ^(unsigned cur, unsigned total) {
                if (cur == total || cur - lastReported >= 50 || cur == 1) {
                    fprintf(stderr, "\rclass-dump: extracting %u/%u", cur, total);
                    fflush(stderr);
                    lastReported = cur;
                }
            });
            fprintf(stderr, "\n");
            if (rc != 0) {
                fprintf(stderr, "class-dump: dyld_shared_cache_extract_dylibs_progress failed (rc=%d)\n", rc);
                exit(1);
            }

            if (shouldDecompile || shouldDecompileSwift || shouldDecompileCpp || shouldDecompileObjc
                || shouldDumpCpp || shouldDumpSwift) {
                NSDirectoryEnumerator *den = [fm enumeratorAtPath:dscExtractDir];
                unsigned dcDone = 0, dcFail = 0, swDone = 0, swFail = 0, cppDone = 0, cppFail = 0;
                unsigned objcDone = 0, objcFail = 0;
                unsigned hCppDone = 0, hCppFail = 0, hSwDone = 0, hSwFail = 0;
                for (NSString *rel in den) {
                    @autoreleasepool {
                        NSString *full = [dscExtractDir stringByAppendingPathComponent:rel];
                        NSDictionary *attrs = [den fileAttributes];
                        if (![[attrs fileType] isEqualToString:NSFileTypeRegular]) continue;
                        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:full];
                        NSData *head = [fh readDataOfLength:4];
                        [fh closeFile];
                        if ([head length] != 4) continue;
                        uint32_t magic;
                        memcpy(&magic, [head bytes], 4);
                        if (magic != MH_MAGIC && magic != MH_MAGIC_64
                            && magic != MH_CIGAM && magic != MH_CIGAM_64) continue;

                        if (shouldDumpCpp || shouldDumpSwift) {
                            CDSearchPathState *sp = [[CDSearchPathState alloc] init];
                            sp.executablePath = [full stringByDeletingLastPathComponent];
                            id parsed = [CDFile fileWithContentsOfFile:full searchPathState:sp];
                            CDMachOFile *mf = nil;
                            if ([parsed isKindOfClass:[CDMachOFile class]]) {
                                mf = parsed;
                            } else if ([parsed isKindOfClass:[CDFatFile class]]) {
                                CDArch a;
                                if ([parsed bestMatchForLocalArch:&a])
                                    mf = [parsed machOFileWithArch:a];
                            }
                            if (mf) {
                                if (shouldDumpCpp) {
                                    NSString *outSub = [full stringByAppendingString:@".cpp_h"];
                                    [fm createDirectoryAtPath:outSub withIntermediateDirectories:YES attributes:nil error:NULL];
                                    NSError *e = nil;
                                    if ([CDCPlusPlusDumper writeHeadersForMachOFile:mf toDirectory:outSub error:&e]) hCppDone++;
                                    else {
                                        hCppFail++;
                                        fprintf(stderr, "class-dump: cpp header dump %s failed: %s\n",
                                                [rel UTF8String], [[e localizedDescription] UTF8String]);
                                    }
                                }
                                if (shouldDumpSwift) {
                                    NSString *outSub = [full stringByAppendingString:@".swift_h"];
                                    [fm createDirectoryAtPath:outSub withIntermediateDirectories:YES attributes:nil error:NULL];
                                    NSError *e = nil;
                                    if ([CDSwiftDumper writeHeadersForMachOFile:mf toDirectory:outSub error:&e]) hSwDone++;
                                    else {
                                        hSwFail++;
                                        fprintf(stderr, "class-dump: swift header dump %s failed: %s\n",
                                                [rel UTF8String], [[e localizedDescription] UTF8String]);
                                    }
                                }
                            } else {
                                if (shouldDumpCpp) hCppFail++;
                                if (shouldDumpSwift) hSwFail++;
                            }
                        }

                        if (shouldDecompile) {
                            NSString *cOut = [full stringByAppendingPathExtension:@"c"];
                            NSError *de = nil;
                            if ([CDDecompiler decompileMachOAtPath:full toPath:cOut error:&de]) dcDone++;
                            else {
                                dcFail++;
                                fprintf(stderr, "class-dump: decompile %s failed: %s\n",
                                        [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                            }
                        }
                        if (shouldDecompileSwift) {
                            NSString *sOut = [full stringByAppendingPathExtension:@"swift"];
                            NSError *de = nil;
                            if ([CDDecompiler decompileSwiftMachOAtPath:full toPath:sOut error:&de]) swDone++;
                            else {
                                swFail++;
                                fprintf(stderr, "class-dump: decompile-swift %s failed: %s\n",
                                        [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                            }
                        }
                        if (shouldDecompileCpp) {
                            NSString *cppOut = [full stringByAppendingPathExtension:@"cpp"];
                            NSError *de = nil;
                            if ([CDDecompiler decompileCppMachOAtPath:full toPath:cppOut error:&de]) cppDone++;
                            else {
                                cppFail++;
                                fprintf(stderr, "class-dump: decompile-cpp %s failed: %s\n",
                                        [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                            }
                        }
                        if (shouldDecompileObjc) {
                            NSString *mOut = [full stringByAppendingPathExtension:@"m"];
                            NSError *de = nil;
                            if ([CDDecompiler decompileObjcMachOAtPath:full toPath:mOut error:&de]) objcDone++;
                            else {
                                objcFail++;
                                fprintf(stderr, "class-dump: decompile-objc %s failed: %s\n",
                                        [rel UTF8String], [[de localizedFailureReason] UTF8String]);
                            }
                        }
                        unsigned total = dcDone + dcFail + swDone + swFail + cppDone + cppFail
                                        + objcDone + objcFail
                                        + hCppDone + hCppFail + hSwDone + hSwFail;
                        if (total % 20 == 0) {
                            fprintf(stderr, "\rclass-dump: c=%u/%u swift=%u/%u cpp=%u/%u m=%u/%u cpp_h=%u/%u swift_h=%u/%u",
                                    dcDone, dcDone + dcFail,
                                    swDone, swDone + swFail,
                                    cppDone, cppDone + cppFail,
                                    objcDone, objcDone + objcFail,
                                    hCppDone, hCppDone + hCppFail,
                                    hSwDone, hSwDone + hSwFail);
                            fflush(stderr);
                        }
                    }
                }
                fprintf(stderr, "\nclass-dump: finished: c ok=%u fail=%u, swift ok=%u fail=%u, cpp ok=%u fail=%u, m ok=%u fail=%u, cpp_h ok=%u fail=%u, swift_h ok=%u fail=%u\n",
                        dcDone, dcFail, swDone, swFail, cppDone, cppFail,
                        objcDone, objcFail,
                        hCppDone, hCppFail, hSwDone, hSwFail);
            }
            exit(0);
        }

        if (optind < argc && (shouldDscInfo || shouldDscListImages)) {
            NSString *arg = [NSString stringWithFileSystemRepresentation:argv[optind]];
            CDDyldCache *cache = [[CDDyldCache alloc] initWithPath:arg];
            if (cache == nil) {
                fprintf(stderr, "class-dump: %s is not a dyld_shared_cache\n", [arg UTF8String]);
                exit(1);
            }
            if (shouldDscInfo) {
                printf("magic:        %s\n", [cache.magic UTF8String]);
                printf("mappings:     %u (offset 0x%x)\n", cache.mappingCount, cache.mappingOffset);
                printf("images:       %lu\n", (unsigned long)[cache.images count]);
                printf("layout:       %s\n", cache.usesLegacyImageTable ? "legacy" : "modern");
                if (cache.platform) printf("platform:     %u\n", cache.platform);
                if ([cache.uuid length]) printf("uuid:         %s\n", [cache.uuid UTF8String]);
                {
                    const char *tname =
                        cache.cacheType == 0 ? " (development)" :
                        cache.cacheType == 1 ? " (production)"  :
                        cache.cacheType == 2 ? " (universal)"   : "";
                    printf("cacheType:    %llu%s\n", cache.cacheType, tname);
                }
                NSArray<CDDyldCacheSubcacheInfo *> *subs = cache.subcaches;
                if (subs.count > 1) {
                    printf("subcaches:    %lu\n", (unsigned long)(subs.count - 1));
                    for (NSUInteger i = 0; i < subs.count; i++) {
                        CDDyldCacheSubcacheInfo *si = subs[i];
                        NSString *label = (i == 0) ? @"<main>" : si.suffix;
                        printf("  [%2lu] %-20s %10llu bytes  %lu region(s)\n",
                               (unsigned long)i,
                               [label UTF8String] ?: "",
                               si.fileSize,
                               (unsigned long)si.mappings.count);
                        for (CDDyldCacheMappingInfo *mi in si.mappings) {
                            printf("        %-14s vm 0x%010llx + 0x%09llx  prot %x/%x  flags 0x%llx\n",
                                   [mi.name UTF8String], mi.address, mi.size,
                                   mi.initProt, mi.maxProt, mi.flags);
                        }
                    }
                }
            }
            if (shouldDscListImages) {
                for (CDDyldCacheImageInfo *img in cache.images) {
                    printf("0x%016llx  %s\n", img.address, [img.path UTF8String]);
                }
            }
            exit(0);
        }

        // Standalone kernelcache container operations: --decompress / --decrypt
        // / --compress. Each reads the raw input file, transforms it, and writes
        // to --out, then exits. These operate on the file bytes directly (not via
        // CDFile, which would auto-unwrap the very container we want to inspect).
        if (optind < argc && (shouldDecompress || shouldDecrypt || compressMethodName != nil)) {
            int opCount = (shouldDecompress ? 1 : 0) + (shouldDecrypt ? 1 : 0) + (compressMethodName != nil ? 1 : 0);
            if (opCount > 1) {
                fprintf(stderr, "class-dump: --decompress, --decrypt and --compress are mutually exclusive\n");
                exit(1);
            }
            if (writeOutPath == nil) {
                fprintf(stderr, "class-dump: --decompress/--decrypt/--compress require --out FILE\n");
                exit(1);
            }
            NSString *inPath = [NSString stringWithFileSystemRepresentation:argv[optind]];
            NSError *readErr = nil;
            NSData *inData = [NSData dataWithContentsOfFile:inPath
                                                   options:NSDataReadingMappedAlways
                                                     error:&readErr];
            if (inData == nil) {
                fprintf(stderr, "class-dump: cannot read %s: %s\n",
                        [inPath UTF8String], [[readErr localizedDescription] UTF8String]);
                exit(1);
            }

            NSError *kcErr = nil;
            NSData *outData = nil;
            if (shouldDecompress) {
                outData = [CDKernelCache decompressData:inData error:&kcErr];
            } else if (shouldDecrypt) {
                NSString *payloadType = nil;
                outData = [CDKernelCache extractIMG4Payload:inData type:&payloadType error:&kcErr];
                if (outData != nil && payloadType != nil)
                    fprintf(stderr, "class-dump: extracted IM4P payload type '%s'\n", [payloadType UTF8String]);
            } else {
                CDKernelCacheCompression method;
                NSString *m = [compressMethodName lowercaseString];
                if ([m isEqualToString:@"lzss"])       method = CDKernelCacheCompressionLZSS;
                else if ([m isEqualToString:@"lzvn"])   method = CDKernelCacheCompressionLZVN;
                else if ([m isEqualToString:@"lzfse"])  method = CDKernelCacheCompressionLZFSE;
                else {
                    fprintf(stderr, "class-dump: --compress expects lzss, lzvn or lzfse (got '%s')\n",
                            [compressMethodName UTF8String]);
                    exit(1);
                }
                outData = [CDKernelCache compressData:inData method:method error:&kcErr];
            }

            if (outData == nil) {
                fprintf(stderr, "class-dump: %s\n", [[kcErr localizedDescription] UTF8String]);
                exit(1);
            }
            if (![outData writeToFile:writeOutPath atomically:YES]) {
                fprintf(stderr, "class-dump: cannot write %s\n", [writeOutPath UTF8String]);
                exit(1);
            }
            fprintf(stderr, "class-dump: wrote %lu bytes to %s\n",
                    (unsigned long)[outData length], [writeOutPath UTF8String]);
            exit(0);
        }

        if (optind < argc && (shouldListFileset || extractFilesetName || shouldFilesetClassDump)) {
            NSString *arg = [NSString stringWithFileSystemRepresentation:argv[optind]];
            NSData *fileData = [NSData dataWithContentsOfFile:arg
                                                      options:NSDataReadingMappedAlways
                                                        error:NULL];
            if (fileData == nil) {
                fprintf(stderr, "class-dump: cannot read %s\n", [arg UTF8String]);
                exit(1);
            }
            CDSearchPathState *sp = [[CDSearchPathState alloc] init];
            sp.executablePath = [arg stringByDeletingLastPathComponent];
            id parsed = [CDFile fileWithContentsOfFile:arg searchPathState:sp];
            CDMachOFile *macho = nil;
            if ([parsed isKindOfClass:[CDMachOFile class]]) macho = parsed;
            else if ([parsed isKindOfClass:[CDFatFile class]]) {
                CDArch a;
                if ([parsed bestMatchForLocalArch:&a]) macho = [parsed machOFileWithArch:a];
            }
            if (macho == nil) {
                fprintf(stderr, "class-dump: not a Mach-O\n");
                exit(1);
            }

            NSMutableArray<CDLCFilesetEntry *> *entries = [NSMutableArray array];
            for (CDLoadCommand *lc in macho.loadCommands) {
                if ([lc isKindOfClass:[CDLCFilesetEntry class]]) [entries addObject:(CDLCFilesetEntry *)lc];
            }
            if ([entries count] == 0) {
                fprintf(stderr, "class-dump: no LC_FILESET_ENTRY load commands found\n");
                exit(1);
            }

            if (shouldListFileset) {
                NSArray *sorted = [entries sortedArrayUsingComparator:^NSComparisonResult(CDLCFilesetEntry *a, CDLCFilesetEntry *b) {
                    if (a.fileoff < b.fileoff) return NSOrderedAscending;
                    if (a.fileoff > b.fileoff) return NSOrderedDescending;
                    return NSOrderedSame;
                }];
                for (CDLCFilesetEntry *e in sorted) {
                    printf("vmaddr 0x%016llx  fileoff 0x%016llx  %s\n",
                           e.vmaddr, e.fileoff, [e.entryID UTF8String]);
                }
            }

            if (extractFilesetName) {
                if (writeOutPath == nil) {
                    fprintf(stderr, "class-dump: --extract-fileset requires --out\n");
                    exit(1);
                }
                CDLCFilesetEntry *target = nil;
                for (CDLCFilesetEntry *e in entries) {
                    if ([e.entryID isEqualToString:extractFilesetName]) { target = e; break; }
                }
                if (target == nil) {
                    fprintf(stderr, "class-dump: fileset entry '%s' not found\n", [extractFilesetName UTF8String]);
                    exit(1);
                }
                // Naive extraction: copy from this entry's fileoff to the next entry's fileoff.
                // This works for typical kernelcache layouts where entries are contiguous;
                // it does NOT rebase per-segment fileoff fields, so the resulting Mach-O
                // segments still reference offsets relative to the original cache.
                uint64_t end = [fileData length];
                for (CDLCFilesetEntry *e in entries) {
                    if (e.fileoff > target.fileoff && e.fileoff < end) end = e.fileoff;
                }
                if (target.fileoff >= [fileData length]) {
                    fprintf(stderr, "class-dump: fileset entry fileoff 0x%llx out of bounds\n", target.fileoff);
                    exit(1);
                }
                NSData *slice = [fileData subdataWithRange:NSMakeRange((NSUInteger)target.fileoff,
                                                                       (NSUInteger)(end - target.fileoff))];
                if (![slice writeToFile:writeOutPath atomically:YES]) {
                    fprintf(stderr, "class-dump: cannot write %s\n", [writeOutPath UTF8String]);
                    exit(1);
                }
                fprintf(stderr, "class-dump: extracted %llu bytes to %s (raw slice; segment file offsets not rebased)\n",
                        end - target.fileoff, [writeOutPath UTF8String]);

                if (shouldDecompile) {
                    NSString *cOut = [writeOutPath stringByAppendingPathExtension:@"c"];
                    NSError *de = nil;
                    if ([CDDecompiler decompileMachOAtPath:writeOutPath toPath:cOut error:&de]) {
                        fprintf(stderr, "class-dump: decompiled to %s\n", [cOut UTF8String]);
                    } else {
                        fprintf(stderr, "class-dump: decompile failed: %s\n",
                                [[de localizedFailureReason] UTF8String]);
                    }
                }
                if (shouldDecompileSwift) {
                    NSString *sOut = [writeOutPath stringByAppendingPathExtension:@"swift"];
                    NSError *de = nil;
                    if ([CDDecompiler decompileSwiftMachOAtPath:writeOutPath toPath:sOut error:&de]) {
                        fprintf(stderr, "class-dump: swift decompiled to %s\n", [sOut UTF8String]);
                    } else {
                        fprintf(stderr, "class-dump: decompile-swift failed: %s\n",
                                [[de localizedFailureReason] UTF8String]);
                    }
                }
                if (shouldDecompileCpp) {
                    NSString *cppOut = [writeOutPath stringByAppendingPathExtension:@"cpp"];
                    NSError *de = nil;
                    if ([CDDecompiler decompileCppMachOAtPath:writeOutPath toPath:cppOut error:&de]) {
                        fprintf(stderr, "class-dump: c++ decompiled to %s\n", [cppOut UTF8String]);
                    } else {
                        fprintf(stderr, "class-dump: decompile-cpp failed: %s\n",
                                [[de localizedFailureReason] UTF8String]);
                    }
                }
                if (shouldDecompileObjc) {
                    NSString *mOut = [writeOutPath stringByAppendingPathExtension:@"m"];
                    NSError *de = nil;
                    if ([CDDecompiler decompileObjcMachOAtPath:writeOutPath toPath:mOut error:&de]) {
                        fprintf(stderr, "class-dump: obj-c decompiled to %s\n", [mOut UTF8String]);
                    } else {
                        fprintf(stderr, "class-dump: decompile-objc failed: %s\n",
                                [[de localizedFailureReason] UTF8String]);
                    }
                }
            }

            if (shouldFilesetClassDump) {
                if (writeOutPath == nil) {
                    fprintf(stderr, "class-dump: --fileset-class-dump requires --out OUTDIR\n");
                    exit(1);
                }
                // stringByAppendingPathComponent: silently returns nil when its
                // receiver is a non-absolute path that consists of only a name
                // under some Foundation versions; standardize/absolutize first.
                writeOutPath = [writeOutPath stringByExpandingTildeInPath];
                if (![writeOutPath isAbsolutePath]) {
                    NSString *cwd = [[NSFileManager defaultManager] currentDirectoryPath];
                    writeOutPath = [cwd stringByAppendingPathComponent:writeOutPath];
                }
                writeOutPath = [writeOutPath stringByStandardizingPath];

                NSFileManager *fm = [NSFileManager defaultManager];
                if (![fm fileExistsAtPath:writeOutPath]) {
                    NSError *e = nil;
                    if (![fm createDirectoryAtPath:writeOutPath withIntermediateDirectories:YES attributes:nil error:&e]) {
                        fprintf(stderr, "class-dump: cannot create %s: %s\n",
                                [writeOutPath UTF8String], [[e localizedDescription] UTF8String]);
                        exit(1);
                    }
                }

                NSArray *sortedEntries = [entries sortedArrayUsingComparator:^NSComparisonResult(CDLCFilesetEntry *a, CDLCFilesetEntry *b) {
                    if (a.fileoff < b.fileoff) return NSOrderedAscending;
                    if (a.fileoff > b.fileoff) return NSOrderedDescending;
                    return NSOrderedSame;
                }];

                // Stripped release kernelcaches carry no nlist symbols, so the
                // symbol-based C++ dumper produces nothing. When --cpp is asked
                // for and the cache has no symbol table, fall back to recovering
                // the IOKit/libkern class hierarchy from OSMetaClass metadata.
                CDIOKitDumper *iokit = nil;
                if (shouldDumpCpp && (macho.symbolTable == nil || [macho.symbolTable nsyms] == 0)) {
                    fprintf(stderr, "class-dump: no symbol table in fileset; recovering C++ classes from OSMetaClass metadata...\n");
                    iokit = [[CDIOKitDumper alloc] initWithCacheData:fileData topLevel:macho];
                    [iokit scanFilesetEntries:sortedEntries];
                    fprintf(stderr, "class-dump: recovered %lu IOKit classes across the cache\n",
                            (unsigned long)[iokit metaClassCount]);
                }

                NSUInteger total = [sortedEntries count];
                NSUInteger ok = 0;
                NSUInteger failed = 0;
                NSUInteger hCppDone = 0, hCppFail = 0;
                NSUInteger hSwiftDone = 0, hSwiftFail = 0;
                NSUInteger dcDone = 0, dcFail = 0;
                NSUInteger swDecDone = 0, swDecFail = 0;
                NSUInteger cppDecDone = 0, cppDecFail = 0;
                NSUInteger objcDecDone = 0, objcDecFail = 0;
                NSUInteger idx = 0;
                for (CDLCFilesetEntry *e in sortedEntries) {
                    idx++;
                    if (e.fileoff >= [fileData length]) {
                        fprintf(stderr, "class-dump: [%lu/%lu] skipping %s: fileoff 0x%llx out of bounds\n",
                                (unsigned long)idx, (unsigned long)total,
                                [e.entryID UTF8String], e.fileoff);
                        failed++;
                        continue;
                    }

                    @autoreleasepool {
                        NSString *entryID = e.entryID ?: [NSString stringWithFormat:@"entry_%llx", e.fileoff];
                        // Sanitize id into a directory-safe leaf (e.g. "com.apple.driver.AppleARMPlatform"
                        // stays as-is; anything containing slashes is collapsed).
                        NSString *safeName = [[entryID stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                                       stringByReplacingOccurrencesOfString:@"\0" withString:@""];
                        NSString *outSub = nil;
                        if ([safeName length] > 0 && [writeOutPath length] > 0) {
                            outSub = [writeOutPath stringByAppendingPathComponent:safeName];
                        }
                        if (outSub == nil) {
                            fprintf(stderr, "class-dump: [%lu/%lu] %s: bad output path (writeOutPath=%s safeName=%s)\n",
                                    (unsigned long)idx, (unsigned long)total,
                                    [entryID UTF8String],
                                    writeOutPath ? [writeOutPath UTF8String] : "(nil)",
                                    safeName ? [safeName UTF8String] : "(nil)");
                            failed++;
                            continue;
                        }
                        if (![fm fileExistsAtPath:outSub]) {
                            NSError *ce = nil;
                            if (![fm createDirectoryAtPath:outSub withIntermediateDirectories:YES attributes:nil error:&ce]) {
                                fprintf(stderr, "class-dump: [%lu/%lu] %s: cannot create %s: %s\n",
                                        (unsigned long)idx, (unsigned long)total,
                                        [entryID UTF8String], [outSub UTF8String],
                                        [[ce localizedDescription] UTF8String]);
                                failed++;
                                continue;
                            }
                        }

                        CDMachOFile *entryMacho = [[CDMachOFile alloc]
                            initWithData:fileData
                            headerOffset:(NSUInteger)e.fileoff
                                filename:[arg stringByAppendingFormat:@"#%@", safeName]
                         searchPathState:sp];
                        if (entryMacho == nil) {
                            fprintf(stderr, "class-dump: [%lu/%lu] %s: not a Mach-O at fileoff 0x%llx\n",
                                    (unsigned long)idx, (unsigned long)total,
                                    [entryID UTF8String], e.fileoff);
                            failed++;
                            continue;
                        }

                        // Objective-C header dump (default) unless explicitly only doing --cpp/--swift.
                        BOOL doObjC = !(shouldDumpCpp || shouldDumpSwift);
                        @try {
                            if (doObjC) {
                                CDClassDump *cd = [[CDClassDump alloc] init];
                                cd.searchPathState.executablePath = [arg stringByDeletingLastPathComponent];
                                cd.targetArch = (CDArch){ entryMacho.cputype, entryMacho.cpusubtype };
                                NSError *le = nil;
                                if ([cd loadFile:entryMacho error:&le]) {
                                    [cd processObjectiveCData];
                                    [cd registerTypes];
                                    CDMultiFileVisitor *v = [[CDMultiFileVisitor alloc] init];
                                    v.classDump = cd;
                                    cd.typeController.delegate = v;
                                    v.outputPath = outSub;
                                    [cd recursivelyVisit:v];
                                }
                            }

                            if (shouldDumpCpp) {
                                NSError *ce = nil;
                                BOOL cppOK = iokit
                                    ? [iokit writeHeadersForKext:entryID toDirectory:outSub error:&ce]
                                    : [CDCPlusPlusDumper writeHeadersForMachOFile:entryMacho toDirectory:outSub error:&ce];
                                if (cppOK) {
                                    hCppDone++;
                                } else {
                                    hCppFail++;
                                    fprintf(stderr, "class-dump: [%lu/%lu] %s: cpp dump failed: %s\n",
                                            (unsigned long)idx, (unsigned long)total,
                                            [entryID UTF8String],
                                            [[ce localizedDescription] UTF8String]);
                                }
                            }
                            if (shouldDumpSwift) {
                                NSError *se = nil;
                                if ([CDSwiftDumper writeHeadersForMachOFile:entryMacho toDirectory:outSub error:&se]) {
                                    hSwiftDone++;
                                } else {
                                    hSwiftFail++;
                                    fprintf(stderr, "class-dump: [%lu/%lu] %s: swift dump failed: %s\n",
                                            (unsigned long)idx, (unsigned long)total,
                                            [entryID UTF8String],
                                            [[se localizedDescription] UTF8String]);
                                }
                            }

                            // Decompilation runs against a stand-alone Mach-O that we
                            // rebase out of the cache: the fileset entry's segments and
                            // shared __LINKEDIT slice are copied into a new flat file
                            // so Ghidra can load the kext on its own. One extraction is
                            // shared across all three decompile variants.
                            if (shouldDecompile || shouldDecompileSwift || shouldDecompileCpp || shouldDecompileObjc) {
                                NSString *tmpName = [NSString stringWithFormat:@"class-dump-fileset-%@-%@",
                                                     safeName, [[NSUUID UUID] UUIDString]];
                                NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:tmpName];
                                NSError *xe = nil;
                                if (![CDFilesetExtractor extractEntry:e fromCache:fileData toPath:tmpPath error:&xe]) {
                                    fprintf(stderr, "class-dump: [%lu/%lu] %s: extract for decompile failed: %s\n",
                                            (unsigned long)idx, (unsigned long)total,
                                            [entryID UTF8String],
                                            [[xe localizedFailureReason] UTF8String] ?: [[xe localizedDescription] UTF8String]);
                                    if (shouldDecompile)      dcFail++;
                                    if (shouldDecompileSwift) swDecFail++;
                                    if (shouldDecompileCpp)   cppDecFail++;
                                    if (shouldDecompileObjc)  objcDecFail++;
                                } else {
                                    if (shouldDecompile) {
                                        NSString *cOut = [outSub stringByAppendingPathComponent:
                                                          [safeName stringByAppendingPathExtension:@"c"]];
                                        NSError *de = nil;
                                        if ([CDDecompiler decompileMachOAtPath:tmpPath toPath:cOut error:&de]) {
                                            dcDone++;
                                        } else {
                                            dcFail++;
                                            fprintf(stderr, "class-dump: [%lu/%lu] %s: decompile failed: %s\n",
                                                    (unsigned long)idx, (unsigned long)total,
                                                    [entryID UTF8String],
                                                    [[de localizedFailureReason] UTF8String]);
                                        }
                                    }
                                    if (shouldDecompileSwift) {
                                        NSString *sOut = [outSub stringByAppendingPathComponent:
                                                          [safeName stringByAppendingPathExtension:@"swift"]];
                                        NSError *de = nil;
                                        if ([CDDecompiler decompileSwiftMachOAtPath:tmpPath toPath:sOut error:&de]) {
                                            swDecDone++;
                                        } else {
                                            swDecFail++;
                                            fprintf(stderr, "class-dump: [%lu/%lu] %s: decompile-swift failed: %s\n",
                                                    (unsigned long)idx, (unsigned long)total,
                                                    [entryID UTF8String],
                                                    [[de localizedFailureReason] UTF8String]);
                                        }
                                    }
                                    if (shouldDecompileCpp) {
                                        NSString *cppOut = [outSub stringByAppendingPathComponent:
                                                            [safeName stringByAppendingPathExtension:@"cpp"]];
                                        NSError *de = nil;
                                        if ([CDDecompiler decompileCppMachOAtPath:tmpPath toPath:cppOut error:&de]) {
                                            cppDecDone++;
                                        } else {
                                            cppDecFail++;
                                            fprintf(stderr, "class-dump: [%lu/%lu] %s: decompile-cpp failed: %s\n",
                                                    (unsigned long)idx, (unsigned long)total,
                                                    [entryID UTF8String],
                                                    [[de localizedFailureReason] UTF8String]);
                                        }
                                    }
                                    if (shouldDecompileObjc) {
                                        NSString *mOut = [outSub stringByAppendingPathComponent:
                                                          [safeName stringByAppendingPathExtension:@"m"]];
                                        NSError *de = nil;
                                        if ([CDDecompiler decompileObjcMachOAtPath:tmpPath toPath:mOut error:&de]) {
                                            objcDecDone++;
                                        } else {
                                            objcDecFail++;
                                            fprintf(stderr, "class-dump: [%lu/%lu] %s: decompile-objc failed: %s\n",
                                                    (unsigned long)idx, (unsigned long)total,
                                                    [entryID UTF8String],
                                                    [[de localizedFailureReason] UTF8String]);
                                        }
                                    }
                                    [fm removeItemAtPath:tmpPath error:NULL];
                                }
                            }

                            ok++;
                        } @catch (NSException *exc) {
                            fprintf(stderr, "class-dump: [%lu/%lu] %s: exception: %s\n",
                                    (unsigned long)idx, (unsigned long)total,
                                    [entryID UTF8String], [[exc reason] UTF8String]);
                            failed++;
                        }
                    }
                }

                fprintf(stderr,
                        "class-dump: fileset class-dump complete — %lu/%lu entries processed",
                        (unsigned long)ok, (unsigned long)total);
                if (shouldDumpCpp)        fprintf(stderr, ", cpp %lu ok / %lu fail",
                                                   (unsigned long)hCppDone, (unsigned long)hCppFail);
                if (shouldDumpSwift)      fprintf(stderr, ", swift %lu ok / %lu fail",
                                                   (unsigned long)hSwiftDone, (unsigned long)hSwiftFail);
                if (shouldDecompile)      fprintf(stderr, ", decompile %lu ok / %lu fail",
                                                   (unsigned long)dcDone, (unsigned long)dcFail);
                if (shouldDecompileSwift) fprintf(stderr, ", decompile-swift %lu ok / %lu fail",
                                                   (unsigned long)swDecDone, (unsigned long)swDecFail);
                if (shouldDecompileCpp)   fprintf(stderr, ", decompile-cpp %lu ok / %lu fail",
                                                   (unsigned long)cppDecDone, (unsigned long)cppDecFail);
                if (shouldDecompileObjc)  fprintf(stderr, ", decompile-objc %lu ok / %lu fail",
                                                   (unsigned long)objcDecDone, (unsigned long)objcDecFail);
                if (failed)               fprintf(stderr, ", %lu failed", (unsigned long)failed);
                fprintf(stderr, "\n");
            }
            exit(0);
        }

        if (optind < argc && (hasWriteOp || shouldLipoInfo)) {
            NSString *arg = [NSString stringWithFileSystemRepresentation:argv[optind]];
            NSString *executablePath = [arg executablePathForFilename] ?: arg;
            NSData *fileData = [NSData dataWithContentsOfFile:executablePath];
            if (fileData == nil) {
                fprintf(stderr, "class-dump: cannot read %s\n", [executablePath UTF8String]);
                exit(1);
            }

            if (shouldLipoInfo) {
                NSArray *archs = [CDMachOWriter architecturesInData:fileData];
                printf("%s\n", [[archs componentsJoinedByString:@" "] UTF8String]);
                exit(0);
            }

            BOOL hasMutateOp = (newDylibID || changeOldPath || rpathOldPath ||
                                [addRPaths count] || [deleteRPaths count] || shouldStripCodesig);

            // For thin extraction with no other mutations, write the slice and exit.
            if (thinArch && !hasMutateOp) {
                if (writeOutPath == nil) {
                    fprintf(stderr, "class-dump: --thin requires --out\n");
                    exit(1);
                }
                NSError *err = nil;
                NSData *slice = [CDMachOWriter thinSliceForArch:thinArch fromFatData:fileData error:&err];
                if (slice == nil) {
                    fprintf(stderr, "class-dump: %s\n", [[err localizedDescription] UTF8String]);
                    exit(1);
                }
                if (![slice writeToFile:writeOutPath atomically:YES]) {
                    fprintf(stderr, "class-dump: cannot write %s\n", [writeOutPath UTF8String]);
                    exit(1);
                }
                exit(0);
            }

            // Mutating operations: require thin input.
            NSMutableData *workingData = nil;
            if (thinArch) {
                NSError *err = nil;
                NSData *slice = [CDMachOWriter thinSliceForArch:thinArch fromFatData:fileData error:&err];
                if (slice == nil) {
                    fprintf(stderr, "class-dump: %s\n", [[err localizedDescription] UTF8String]);
                    exit(1);
                }
                workingData = [slice mutableCopy];
            } else {
                NSArray *archs = [CDMachOWriter architecturesInData:fileData];
                if ([archs count] != 1) {
                    fprintf(stderr, "class-dump: input is fat (%s); use --thin <arch> first\n",
                            [[archs componentsJoinedByString:@" "] UTF8String]);
                    exit(1);
                }
                workingData = [fileData mutableCopy];
            }

            if (writeOutPath == nil) {
                fprintf(stderr, "class-dump: write operations require --out\n");
                exit(1);
            }

            CDMachOWriter *writer = [[CDMachOWriter alloc] initWithData:workingData
                                                            sliceOffset:0
                                                            sliceLength:[workingData length]];
            if (writer == nil) {
                fprintf(stderr, "class-dump: not a Mach-O image\n");
                exit(1);
            }

            NSError *err = nil;
            BOOL ok = YES;
            if (ok && newDylibID)        ok = [writer setDylibID:newDylibID error:&err];
            if (ok && changeOldPath)     ok = [writer changeInstallName:changeOldPath to:changeNewPath error:&err];
            if (ok && rpathOldPath)      ok = [writer changeRPath:rpathOldPath to:rpathNewPath error:&err];
            for (NSString *p in deleteRPaths) { if (!ok) break; ok = [writer deleteRPath:p error:&err]; }
            for (NSString *p in addRPaths)    { if (!ok) break; ok = [writer addRPath:p error:&err]; }
            if (ok && shouldStripCodesig) ok = [writer stripCodeSignature:&err];

            if (!ok) {
                fprintf(stderr, "class-dump: %s\n", [[err localizedDescription] UTF8String]);
                exit(1);
            }

            // Truncate workingData to current slice length (stripCodeSignature shrinks it).
            NSData *out = [workingData subdataWithRange:NSMakeRange(0, writer.sliceLength)];
            if (![out writeToFile:writeOutPath atomically:YES]) {
                fprintf(stderr, "class-dump: cannot write %s\n", [writeOutPath UTF8String]);
                exit(1);
            }
            exit(0);
        }

        if (optind < argc) {
            NSString *arg = [NSString stringWithFileSystemRepresentation:argv[optind]];
            NSString *executablePath = [arg executablePathForFilename];
            if (shouldListArches) {
                if (executablePath == nil) {
                    printf("none\n");
                } else {
                    CDSearchPathState *searchPathState = [[CDSearchPathState alloc] init];
                    searchPathState.executablePath = executablePath;
                    id macho = [CDFile fileWithContentsOfFile:executablePath searchPathState:searchPathState];
                    if (macho == nil) {
                        printf("none\n");
                    } else {
                        if ([macho isKindOfClass:[CDMachOFile class]]) {
                            printf("%s\n", [[macho archName] UTF8String]);
                        } else if ([macho isKindOfClass:[CDFatFile class]]) {
                            printf("%s\n", [[[macho archNames] componentsJoinedByString:@" "] UTF8String]);
                        }
                    }
                }
            } else {
                if (executablePath == nil) {
                    fprintf(stderr, "class-dump: Input file (%s) doesn't contain an executable.\n", [arg fileSystemRepresentation]);
                    exit(1);
                }

                classDump.searchPathState.executablePath = [executablePath stringByDeletingLastPathComponent];
                CDFile *file = [CDFile fileWithContentsOfFile:executablePath searchPathState:classDump.searchPathState];
                if (file == nil) {
                    NSFileManager *defaultManager = [NSFileManager defaultManager];
                    
                    if ([defaultManager fileExistsAtPath:executablePath]) {
                        if ([defaultManager isReadableFileAtPath:executablePath]) {
                            fprintf(stderr, "class-dump: Input file (%s) is neither a Mach-O file nor a fat archive.\n", [executablePath UTF8String]);
                        } else {
                            fprintf(stderr, "class-dump: Input file (%s) is not readable (check read permissions).\n", [executablePath UTF8String]);
                        }
                    } else {
                        fprintf(stderr, "class-dump: Input file (%s) does not exist.\n", [executablePath UTF8String]);
                    }

                    exit(1);
                }

                if (hasSpecifiedArch == NO) {
                    if ([file bestMatchForLocalArch:&targetArch] == NO) {
                        fprintf(stderr, "Error: Couldn't get local architecture\n");
                        exit(1);
                    }
                    //NSLog(@"No arch specified, best match for local arch is: (%08x, %08x)", targetArch.cputype, targetArch.cpusubtype);
                } else {
                    //NSLog(@"chosen arch is: (%08x, %08x)", targetArch.cputype, targetArch.cpusubtype);
                }

                classDump.targetArch = targetArch;
                classDump.searchPathState.executablePath = [executablePath stringByDeletingLastPathComponent];

                NSError *error;
                if (![classDump loadFile:file error:&error]) {
                    fprintf(stderr, "Error: %s\n", [[error localizedFailureReason] UTF8String]);
                    exit(1);
                } else {
                    if (shouldShowMachHeader) {
                        [classDump showHeader];
                    }
                    if (shouldShowLoadCommands) {
                        [classDump showLoadCommands];
                    }
                    if (shouldShowMachHeader || shouldShowLoadCommands) {
                        exit(0);
                    }

                    if (shouldDumpCpp || shouldDumpSwift) {
                        CDMachOFile *mf = [classDump.machOFiles lastObject];
                        if (mf) {
                            if (shouldGenerateSeparateHeaders) {
                                NSString *dir = outputPath ?: @".";
                                if (shouldDumpCpp) {
                                    NSError *e = nil;
                                    if (![CDCPlusPlusDumper writeHeadersForMachOFile:mf toDirectory:dir error:&e]) {
                                        fprintf(stderr, "class-dump: %s\n", [[e localizedDescription] UTF8String]);
                                        exit(1);
                                    }
                                }
                                if (shouldDumpSwift) {
                                    NSError *e = nil;
                                    if (![CDSwiftDumper writeHeadersForMachOFile:mf toDirectory:dir error:&e]) {
                                        fprintf(stderr, "class-dump: %s\n", [[e localizedDescription] UTF8String]);
                                        exit(1);
                                    }
                                }
                            } else {
                                if (shouldDumpCpp) {
                                    NSString *s = [CDCPlusPlusDumper dumpHeaderForMachOFile:mf];
                                    fwrite([s UTF8String], 1, [s lengthOfBytesUsingEncoding:NSUTF8StringEncoding], stdout);
                                }
                                if (shouldDumpSwift) {
                                    NSString *s = [CDSwiftDumper dumpHeaderForMachOFile:mf];
                                    fwrite([s UTF8String], 1, [s lengthOfBytesUsingEncoding:NSUTF8StringEncoding], stdout);
                                }
                            }
                        }
                        exit(0);
                    }

                    // Pool extra binaries into the shared type registry so
                    // that struct / union / protocol references resolve to
                    // their fullest definition across the binary set.
                    for (NSString *dir in scanDirs) {
                        NSError *poolErr = nil;
                        NSUInteger n = [classDump scanDirectoryForTypePool:dir
                                                                  excluding:executablePath
                                                                      error:&poolErr];
                        if (poolErr) {
                            fprintf(stderr, "class-dump: --scan-dir %s: %s\n",
                                    [dir UTF8String], [[poolErr localizedFailureReason] UTF8String]);
                        } else {
                            fprintf(stderr, "class-dump: scan-dir %s: pooled %lu image%s\n",
                                    [dir UTF8String], (unsigned long)n, n == 1 ? "" : "s");
                        }
                    }
                    if (shouldAutoScan) {
                        NSString *neighbor = [executablePath stringByDeletingLastPathComponent];
                        if ([neighbor length] > 0) {
                            NSError *poolErr = nil;
                            NSUInteger n = [classDump scanDirectoryForTypePool:neighbor
                                                                      excluding:executablePath
                                                                          error:&poolErr];
                            if (poolErr) {
                                fprintf(stderr, "class-dump: --auto-scan %s: %s\n",
                                        [neighbor UTF8String], [[poolErr localizedFailureReason] UTF8String]);
                            } else {
                                fprintf(stderr, "class-dump: auto-scan %s: pooled %lu image%s\n",
                                        [neighbor UTF8String], (unsigned long)n, n == 1 ? "" : "s");
                            }
                        }
                    }

                    [classDump processObjectiveCData];
                    [classDump registerTypes];

                    if (searchString != nil) {
                        CDFindMethodVisitor *visitor = [[CDFindMethodVisitor alloc] init];
                        visitor.classDump = classDump;
                        visitor.searchString = searchString;
                        [classDump recursivelyVisit:visitor];
                    } else if (shouldGenerateSeparateHeaders) {
                        CDMultiFileVisitor *multiFileVisitor = [[CDMultiFileVisitor alloc] init];
                        multiFileVisitor.classDump = classDump;
                        classDump.typeController.delegate = multiFileVisitor;
                        multiFileVisitor.outputPath = outputPath;
                        [classDump recursivelyVisit:multiFileVisitor];
                    } else {
                        CDClassDumpVisitor *visitor = [[CDClassDumpVisitor alloc] init];
                        visitor.classDump = classDump;
                        if ([hiddenSections containsObject:@"structures"]) visitor.shouldShowStructureSection = NO;
                        if ([hiddenSections containsObject:@"protocols"])  visitor.shouldShowProtocolSection  = NO;
                        [classDump recursivelyVisit:visitor];
                    }

                    if (shouldDecompile) {
                        NSString *cDir = outputPath ?: @".";
                        if (![[NSFileManager defaultManager] fileExistsAtPath:cDir]) {
                            [[NSFileManager defaultManager] createDirectoryAtPath:cDir
                                                       withIntermediateDirectories:YES
                                                                        attributes:nil
                                                                             error:NULL];
                        }
                        NSString *cOut = [cDir stringByAppendingPathComponent:
                                          [[executablePath lastPathComponent] stringByAppendingPathExtension:@"c"]];
                        NSError *de = nil;
                        fprintf(stderr, "class-dump: decompiling %s ...\n", [executablePath UTF8String]);
                        if ([CDDecompiler decompileMachOAtPath:executablePath toPath:cOut error:&de]) {
                            fprintf(stderr, "class-dump: wrote %s\n", [cOut UTF8String]);
                        } else {
                            fprintf(stderr, "class-dump: decompile failed: %s\n",
                                    [[de localizedFailureReason] UTF8String]);
                        }
                    }

                    if (shouldDecompileSwift) {
                        NSString *sDir = outputPath ?: @".";
                        if (![[NSFileManager defaultManager] fileExistsAtPath:sDir]) {
                            [[NSFileManager defaultManager] createDirectoryAtPath:sDir
                                                       withIntermediateDirectories:YES
                                                                        attributes:nil
                                                                             error:NULL];
                        }
                        NSString *sOut = [sDir stringByAppendingPathComponent:
                                          [[executablePath lastPathComponent] stringByAppendingPathExtension:@"swift"]];
                        NSError *de = nil;
                        fprintf(stderr, "class-dump: decompile-swift %s ...\n", [executablePath UTF8String]);
                        if ([CDDecompiler decompileSwiftMachOAtPath:executablePath toPath:sOut error:&de]) {
                            if ([[NSFileManager defaultManager] fileExistsAtPath:sOut]) {
                                fprintf(stderr, "class-dump: wrote %s\n", [sOut UTF8String]);
                            } else {
                                fprintf(stderr, "class-dump: decompile-swift: no Swift functions found in %s\n",
                                        [[executablePath lastPathComponent] UTF8String]);
                            }
                        } else {
                            fprintf(stderr, "class-dump: decompile-swift failed: %s\n",
                                    [[de localizedFailureReason] UTF8String]);
                        }
                    }

                    if (shouldDecompileCpp) {
                        NSString *cppDir = outputPath ?: @".";
                        if (![[NSFileManager defaultManager] fileExistsAtPath:cppDir]) {
                            [[NSFileManager defaultManager] createDirectoryAtPath:cppDir
                                                       withIntermediateDirectories:YES
                                                                        attributes:nil
                                                                             error:NULL];
                        }
                        NSString *cppOut = [cppDir stringByAppendingPathComponent:
                                            [[executablePath lastPathComponent] stringByAppendingPathExtension:@"cpp"]];
                        NSError *de = nil;
                        fprintf(stderr, "class-dump: decompile-cpp %s ...\n", [executablePath UTF8String]);
                        if ([CDDecompiler decompileCppMachOAtPath:executablePath toPath:cppOut error:&de]) {
                            if ([[NSFileManager defaultManager] fileExistsAtPath:cppOut]) {
                                fprintf(stderr, "class-dump: wrote %s\n", [cppOut UTF8String]);
                            } else {
                                fprintf(stderr, "class-dump: decompile-cpp: no C++ mangled functions found in %s\n",
                                        [[executablePath lastPathComponent] UTF8String]);
                            }
                        } else {
                            fprintf(stderr, "class-dump: decompile-cpp failed: %s\n",
                                    [[de localizedFailureReason] UTF8String]);
                        }
                    }

                    if (shouldDecompileObjc) {
                        NSString *mDir = outputPath ?: @".";
                        if (![[NSFileManager defaultManager] fileExistsAtPath:mDir]) {
                            [[NSFileManager defaultManager] createDirectoryAtPath:mDir
                                                       withIntermediateDirectories:YES
                                                                        attributes:nil
                                                                             error:NULL];
                        }
                        NSString *mOut = [mDir stringByAppendingPathComponent:
                                          [[executablePath lastPathComponent] stringByAppendingPathExtension:@"m"]];
                        NSError *de = nil;
                        fprintf(stderr, "class-dump: decompile-objc %s ...\n", [executablePath UTF8String]);
                        if ([CDDecompiler decompileObjcMachOAtPath:executablePath toPath:mOut error:&de]) {
                            if ([[NSFileManager defaultManager] fileExistsAtPath:mOut]) {
                                fprintf(stderr, "class-dump: wrote %s\n", [mOut UTF8String]);
                            } else {
                                fprintf(stderr, "class-dump: decompile-objc: no Obj-C method IMPs found in %s\n",
                                        [[executablePath lastPathComponent] UTF8String]);
                            }
                        } else {
                            fprintf(stderr, "class-dump: decompile-objc failed: %s\n",
                                    [[de localizedFailureReason] UTF8String]);
                        }
                    }
                }
            }
        }
        exit(0); // avoid costly autorelease pool drain, we’re exiting anyway
    }
}
