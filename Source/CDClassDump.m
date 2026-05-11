// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDClassDump.h"

#import <mach-o/loader.h>
#import <mach-o/fat.h>

#import "CDFatArch.h"
#import "CDFatFile.h"
#import "CDFile.h"
#import "CDLCDylib.h"
#import "CDMachOFile.h"
#import "CDObjectiveCProcessor.h"
#import "CDType.h"
#import "CDTypeFormatter.h"
#import "CDTypeParser.h"
#import "CDVisitor.h"
#import "CDLCSegment.h"
#import "CDTypeController.h"
#import "CDSearchPathState.h"

NSString *CDErrorDomain_ClassDump = @"CDErrorDomain_ClassDump";

NSString *CDErrorKey_Exception    = @"CDErrorKey_Exception";

@interface CDClassDump ()
@end

#pragma mark -

@implementation CDClassDump
{
    CDSearchPathState *_searchPathState;
    
    BOOL _shouldProcessRecursively;
    BOOL _shouldSortClasses; // And categories, protocols
    BOOL _shouldSortClassesByInheritance; // And categories, protocols
    BOOL _shouldSortMethods;
    
    BOOL _shouldShowIvarOffsets;
    BOOL _shouldShowMethodAddresses;
    BOOL _shouldShowHeader;
    
    NSRegularExpression *_regularExpression;
    
    NSString *_sdkRoot;
    NSMutableArray *_machOFiles;
    NSMutableDictionary *_machOFilesByName;
    NSMutableArray *_objcProcessors;
    // CDMachOFile instances loaded as type pool sources (pointer identity).
    NSHashTable *_typePoolMachOFiles;
    
    CDTypeController *_typeController;
    
    CDArch _targetArch;
}

- (id)init;
{
    if ((self = [super init])) {
        _searchPathState = [[CDSearchPathState alloc] init];
        _sdkRoot = nil;
        
        _machOFiles = [[NSMutableArray alloc] init];
        _machOFilesByName = [[NSMutableDictionary alloc] init];
        _objcProcessors = [[NSMutableArray alloc] init];
        _typePoolMachOFiles = [NSHashTable hashTableWithOptions:NSPointerFunctionsOpaquePersonality | NSPointerFunctionsOpaqueMemory];
        
        _typeController = [[CDTypeController alloc] initWithClassDump:self];
        
        // These can be ppc, ppc7400, ppc64, i386, x86_64
        _targetArch.cputype = CPU_TYPE_ANY;
        _targetArch.cpusubtype = 0;
        
        _shouldShowHeader = YES;
    }

    return self;
}

#pragma mark - Regular expression handling

- (BOOL)shouldShowName:(NSString *)name;
{
    if (self.regularExpression != nil) {
        NSTextCheckingResult *firstMatch = [self.regularExpression firstMatchInString:name options:(NSMatchingOptions)0 range:NSMakeRange(0, [name length])];
        return firstMatch != nil;
    }

    return YES;
}

#pragma mark -

- (BOOL)containsObjectiveCData;
{
    for (CDObjectiveCProcessor *processor in self.objcProcessors) {
        if ([processor hasObjectiveCData])
            return YES;
    }

    return NO;
}

- (BOOL)hasEncryptedFiles;
{
    for (CDMachOFile *machOFile in self.machOFiles) {
        if ([machOFile isEncrypted]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)hasObjectiveCRuntimeInfo;
{
    return self.containsObjectiveCData || self.hasEncryptedFiles;
}

- (BOOL)loadFile:(CDFile *)file error:(NSError *__autoreleasing *)error;
{
    //NSLog(@"targetArch: (%08x, %08x)", targetArch.cputype, targetArch.cpusubtype);
    CDMachOFile *machOFile = [file machOFileWithArch:_targetArch];
    //NSLog(@"machOFile: %@", machOFile);
    if (machOFile == nil) {
        if (error != NULL) {
            NSString *failureReason;
            NSString *targetArchName = CDNameForCPUType(_targetArch.cputype, _targetArch.cpusubtype);
            if ([file isKindOfClass:[CDFatFile class]] && [(CDFatFile *)file containsArchitecture:_targetArch]) {
                failureReason = [NSString stringWithFormat:@"Fat file doesn't contain a valid Mach-O file for the specified architecture (%@).  "
                                                            "It probably means that class-dump was run on a static library, which is not supported.", targetArchName];
            } else {
                failureReason = [NSString stringWithFormat:@"File doesn't contain the specified architecture (%@).  Available architectures are %@.", targetArchName, file.architectureNameDescription];
            }
            NSDictionary *userInfo = @{ NSLocalizedFailureReasonErrorKey : failureReason };
            *error = [NSError errorWithDomain:CDErrorDomain_ClassDump code:0 userInfo:userInfo];
        }
        return NO;
    }

    // Set before processing recursively.  This was getting caught on CoreUI on 10.6
    assert([machOFile filename] != nil);
    if (self.backingCache) machOFile.backingCache = self.backingCache;
    [_machOFiles addObject:machOFile];
    _machOFilesByName[machOFile.filename] = machOFile;

    if ([self shouldProcessRecursively]) {
        @try {
            for (CDLoadCommand *loadCommand in [machOFile loadCommands]) {
                if ([loadCommand isKindOfClass:[CDLCDylib class]]) {
                    CDLCDylib *dylibCommand = (CDLCDylib *)loadCommand;
                    if ([dylibCommand cmd] == LC_LOAD_DYLIB) {
                        [self.searchPathState pushSearchPaths:[machOFile runPaths]];
                        {
                            NSString *loaderPathPrefix = @"@loader_path";
                            
                            NSString *path = [dylibCommand path];
                            if ([path hasPrefix:loaderPathPrefix]) {
                                NSString *loaderPath = [machOFile.filename stringByDeletingLastPathComponent];
                                path = [[path stringByReplacingOccurrencesOfString:loaderPathPrefix withString:loaderPath] stringByStandardizingPath];
                            }
                            [self machOFileWithName:path]; // Loads as a side effect
                        }
                        [self.searchPathState popSearchPaths];
                    }
                }
            }
        }
        @catch (NSException *exception) {
            NSLog(@"Caught exception: %@", exception);
            if (error != NULL) {
                NSDictionary *userInfo = @{
                NSLocalizedFailureReasonErrorKey : @"Caught exception",
                CDErrorKey_Exception             : exception,
                };
                *error = [NSError errorWithDomain:CDErrorDomain_ClassDump code:0 userInfo:userInfo];
            }
            return NO;
        }
    }

    return YES;
}

- (BOOL)loadFileAsTypePoolSource:(CDFile *)file error:(NSError *__autoreleasing *)error;
{
    NSUInteger oldCount = [_machOFiles count];
    BOOL ok = [self loadFile:file error:error];
    // Mark every Mach-O file added by this load (including transitively
    // loaded dylibs when -shouldProcessRecursively is YES) as pool-only.
    for (NSUInteger i = oldCount; i < [_machOFiles count]; i++) {
        [_typePoolMachOFiles addObject:_machOFiles[i]];
    }
    return ok;
}

- (NSUInteger)scanDirectoryForTypePool:(NSString *)directoryPath
                              excluding:(NSString *)excludedPath
                                  error:(NSError *__autoreleasing *)error;
{
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:directoryPath isDirectory:&isDir] || !isDir) {
        if (error != NULL) {
            NSString *reason = [NSString stringWithFormat:@"Scan path is not a directory: %@", directoryPath];
            *error = [NSError errorWithDomain:CDErrorDomain_ClassDump code:0
                                     userInfo:@{ NSLocalizedFailureReasonErrorKey: reason }];
        }
        return 0;
    }

    NSString *standardizedExclude = [[excludedPath stringByStandardizingPath] stringByResolvingSymlinksInPath];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:directoryPath];
    NSUInteger loaded = 0;

    for (NSString *rel in en) {
        @autoreleasepool {
            NSString *full = [directoryPath stringByAppendingPathComponent:rel];
            NSDictionary *attrs = [en fileAttributes];
            if (![[attrs fileType] isEqualToString:NSFileTypeRegular]) continue;
            if ([attrs fileSize] < 4) continue;

            if (standardizedExclude) {
                NSString *stdFull = [[full stringByStandardizingPath] stringByResolvingSymlinksInPath];
                if ([stdFull isEqualToString:standardizedExclude]) continue;
            }

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

            // Don't load the same path twice (the primary or an earlier
            // pool entry may already be loaded under this filename).
            if (_machOFilesByName[full] != nil) continue;

            CDFile *poolFile = [CDFile fileWithContentsOfFile:full searchPathState:self.searchPathState];
            if (poolFile == nil) continue;

            // Pick the best arch for this file rather than forcing the
            // primary's targetArch — pool dylibs may not have it.
            CDArch savedArch = _targetArch;
            CDArch chosen;
            if (![poolFile bestMatchForLocalArch:&chosen]) continue;
            // Prefer the primary's CPU if the file has it, so type sizes
            // stay consistent.
            if ([poolFile machOFileWithArch:savedArch] != nil) chosen = savedArch;
            _targetArch = chosen;
            BOOL ok = [self loadFileAsTypePoolSource:poolFile error:NULL];
            _targetArch = savedArch;
            if (ok) loaded++;
        }
    }
    return loaded;
}

#pragma mark -

- (void)processObjectiveCData;
{
    for (CDMachOFile *machOFile in self.machOFiles) {
        CDObjectiveCProcessor *processor = [[[machOFile processorClass] alloc] initWithMachOFile:machOFile];
        BOOL isPool = [_typePoolMachOFiles containsObject:machOFile];
        if (isPool) {
            // A pool dylib may be malformed (stubs, dyld_shared_cache
            // placeholders, truncated symbol tables). Don't let an
            // Objective-C exception raised by its parser kill the
            // primary dump.
            @try {
                [processor process];
            } @catch (NSException *exc) {
                fprintf(stderr, "class-dump: scan-pool: skipping %s (%s)\n",
                        [machOFile.filename UTF8String], [[exc reason] UTF8String]);
                continue;
            }
            processor.isTypePoolSource = YES;
        } else {
            [processor process];
        }
        [_objcProcessors addObject:processor];
    }
}

// This visits everything segment processors, classes, categories.  It skips over modules.  Need something to visit modules so we can generate separate headers.
- (void)recursivelyVisit:(CDVisitor *)visitor;
{
    [visitor willBeginVisiting];

    for (CDObjectiveCProcessor *processor in self.objcProcessors) {
        if (processor.isTypePoolSource) continue;
        [processor recursivelyVisit:visitor];
    }

    [visitor didEndVisiting];
}

- (CDMachOFile *)machOFileWithName:(NSString *)name;
{
    NSString *adjustedName = nil;
    NSString *executablePathPrefix = @"@executable_path";
    NSString *rpathPrefix = @"@rpath";

    if ([name hasPrefix:executablePathPrefix]) {
        adjustedName = [name stringByReplacingOccurrencesOfString:executablePathPrefix withString:self.searchPathState.executablePath];
    } else if ([name hasPrefix:rpathPrefix]) {
        //NSLog(@"Searching for %@ through run paths: %@", name, [searchPathState searchPaths]);
        for (NSString *searchPath in [self.searchPathState searchPaths]) {
            NSString *str = [name stringByReplacingOccurrencesOfString:rpathPrefix withString:searchPath];
            //NSLog(@"trying %@", str);
            if ([[NSFileManager defaultManager] fileExistsAtPath:str]) {
                adjustedName = str;
                //NSLog(@"Found it!");
                break;
            }
        }
        if (adjustedName == nil) {
            adjustedName = name;
            //NSLog(@"Did not find it.");
        }
    } else if (self.sdkRoot != nil) {
        adjustedName = [self.sdkRoot stringByAppendingPathComponent:name];
    } else {
        adjustedName = name;
    }

    CDMachOFile *machOFile = _machOFilesByName[adjustedName];
    if (machOFile == nil) {
        CDFile *file = [CDFile fileWithContentsOfFile:adjustedName searchPathState:self.searchPathState];

        if (file == nil || [self loadFile:file error:NULL] == NO)
            NSLog(@"Warning: Failed to load: %@", adjustedName);

        machOFile = _machOFilesByName[adjustedName];
        if (machOFile == nil) {
            NSLog(@"Warning: Couldn't load MachOFile with ID: %@, adjustedID: %@", name, adjustedName);
        }
    }

    return machOFile;
}

- (void)appendHeaderToString:(NSMutableString *)resultString;
{
    // Since this changes each version, for regression testing it'll be better to be able to not show it.
    if (self.shouldShowHeader == NO)
        return;

    [resultString appendString:@"//\n"];
    [resultString appendFormat:@"//     Generated by class-dump %s.\n", CLASS_DUMP_VERSION];
    [resultString appendString:@"//\n"];
    [resultString appendString:@"//  Copyright (C) 1997-2019 Steve Nygard.\n"];
    [resultString appendString:@"//\n\n"];

    if (self.sdkRoot != nil) {
        [resultString appendString:@"//\n"];
        [resultString appendFormat:@"// SDK Root: %@\n", self.sdkRoot];
        [resultString appendString:@"//\n\n"];
    }
}

- (void)registerTypes;
{
    for (CDObjectiveCProcessor *processor in self.objcProcessors) {
        [processor registerTypesWithObject:self.typeController phase:0];
    }
    [self.typeController endPhase:0];

    [self.typeController workSomeMagic];
}

- (void)showHeader;
{
    if ([self.machOFiles count] > 0) {
        [[[self.machOFiles lastObject] headerString:YES] print];
    }
}

- (void)showLoadCommands;
{
    if ([self.machOFiles count] > 0) {
        [[[self.machOFiles lastObject] loadCommandString:YES] print];
    }
}

@end
