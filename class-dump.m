// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#include <stdio.h>
#include <libc.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#import "CDClassDump.h"
#import "CDFindMethodVisitor.h"
#import "CDClassDumpVisitor.h"
#import "CDMultiFileVisitor.h"
#import "CDFile.h"
#import "CDMachOFile.h"
#import "CDFatFile.h"
#import "CDFatArch.h"
#import "CDSearchPathState.h"
#import "CDMachOWriter.h"
#import "CDDyldCache.h"
#import "CDLCFilesetEntry.h"
#import "CDLoadCommand.h"
#import "CDCPlusPlusDumper.h"
#import "CDSwiftDumper.h"

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
            "        --dsc-extract DIR    extract every dylib from a dyld_shared_cache to DIR\n"
            "                             (uses Apple's dsc_extractor.bundle from Xcode)\n"
            "        --with-cache FILE    use a dyld_shared_cache file to resolve selectors and\n"
            "                             type strings when class-dumping cache-extracted dylibs\n"
            "        --cpp                dump C++ classes (from LC_SYMTAB Itanium-mangled symbols)\n"
            "        --swift              dump Swift extensions/types (from LC_SYMTAB mangled symbols,\n"
            "                             demangled via libswiftCore swift_demangle)\n"
            "        --dsc-class-dump CACHE_OR_DIR --out OUTDIR\n"
            "                             extract every dylib from a cache (or use already-extracted\n"
            "                             dir) and class-dump each into OUTDIR/<install-path>/\n"
            "                             (combine with --cpp and/or --swift to additionally write\n"
            "                             C++ .h files and Swift .swift files per image)\n"
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
        NSString *extractFilesetName = nil;
        NSString *dscExtractDir = nil;
        BOOL shouldDumpCpp = NO;
        BOOL shouldDumpSwift = NO;
        NSString *dscDumpAllInput = nil;

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

                case CD_OPT_WITH_CACHE: {
                    NSString *cachePath = [NSString stringWithUTF8String:optarg];
                    NSData *cacheData = [NSData dataWithContentsOfFile:cachePath
                                                               options:NSDataReadingMappedAlways
                                                                 error:NULL];
                    if (cacheData == nil) {
                        fprintf(stderr, "class-dump: cannot read cache %s\n", optarg);
                        errorFlag = YES;
                        break;
                    }
                    CDDyldCache *cache = [[CDDyldCache alloc] initWithData:cacheData];
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

                // Use the cache itself as backing for cross-image resolution.
                if (bulkCache == nil) {
                    NSData *cdata = [NSData dataWithContentsOfFile:dscDumpAllInput
                                                           options:NSDataReadingMappedAlways
                                                             error:NULL];
                    if (cdata) bulkCache = [[CDDyldCache alloc] initWithData:cdata];
                }
            }

            if (![fm fileExistsAtPath:writeOutPath]) {
                [fm createDirectoryAtPath:writeOutPath withIntermediateDirectories:YES attributes:nil error:NULL];
            }

            // Walk extractedDir for Mach-O dylibs and class-dump each.
            NSDirectoryEnumerator *en = [fm enumeratorAtPath:extractedDir];
            unsigned processed = 0, succeeded = 0, failed = 0;
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

                processed++;
                if (processed % 50 == 0) {
                    fprintf(stderr, "\rclass-dump: dumped %u/? ok=%u fail=%u", processed, succeeded, failed);
                    fflush(stderr);
                }

                @autoreleasepool {
                    CDClassDump *cd = [[CDClassDump alloc] init];
                    if (bulkCache) cd.backingCache = bulkCache;
                    CDSearchPathState *sp = [[CDSearchPathState alloc] init];
                    sp.executablePath = [full stringByDeletingLastPathComponent];
                    cd.searchPathState.executablePath = sp.executablePath;
                    CDFile *file = [CDFile fileWithContentsOfFile:full searchPathState:cd.searchPathState];
                    if (file == nil) { failed++; continue; }
                    CDArch arch;
                    if (![file bestMatchForLocalArch:&arch]) { failed++; continue; }
                    cd.targetArch = arch;
                    NSError *err = nil;
                    if (![cd loadFile:file error:&err]) { failed++; continue; }

                    NSString *outSub = [writeOutPath stringByAppendingPathComponent:rel];
                    [fm createDirectoryAtPath:outSub withIntermediateDirectories:YES attributes:nil error:NULL];

                    @try {
                        [cd processObjectiveCData];
                        [cd registerTypes];
                        CDMultiFileVisitor *v = [[CDMultiFileVisitor alloc] init];
                        v.classDump = cd;
                        cd.typeController.delegate = v;
                        v.outputPath = outSub;
                        [cd recursivelyVisit:v];

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

                        succeeded++;
                    } @catch (NSException *e) {
                        failed++;
                    }
                }
            }
            fprintf(stderr, "\nclass-dump: dumped %u images (ok=%u fail=%u) into %s\n",
                    processed, succeeded, failed, [writeOutPath UTF8String]);
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
            exit(0);
        }

        if (optind < argc && (shouldDscInfo || shouldDscListImages)) {
            NSString *arg = [NSString stringWithFileSystemRepresentation:argv[optind]];
            NSData *fileData = [NSData dataWithContentsOfFile:arg
                                                      options:NSDataReadingMappedAlways
                                                        error:NULL];
            if (fileData == nil) {
                fprintf(stderr, "class-dump: cannot read %s\n", [arg UTF8String]);
                exit(1);
            }
            CDDyldCache *cache = [[CDDyldCache alloc] initWithData:fileData];
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
            }
            if (shouldDscListImages) {
                for (CDDyldCacheImageInfo *img in cache.images) {
                    printf("0x%016llx  %s\n", img.address, [img.path UTF8String]);
                }
            }
            exit(0);
        }

        if (optind < argc && (shouldListFileset || extractFilesetName)) {
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
                }
            }
        }
        exit(0); // avoid costly autorelease pool drain, we’re exiting anyway
    }
}
