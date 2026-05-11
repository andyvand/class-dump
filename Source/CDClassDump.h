// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDFile.h" // For CDArch

#define CLASS_DUMP_BASE_VERSION "3.5 (64 bit)"

#ifdef DEBUG
#define CLASS_DUMP_VERSION CLASS_DUMP_BASE_VERSION " (Debug version compiled " __DATE__ " " __TIME__ ")"
#else
#define CLASS_DUMP_VERSION CLASS_DUMP_BASE_VERSION
#endif

@class CDFile;
@class CDTypeController;
@class CDVisitor;
@class CDSearchPathState;
@class CDDyldCache;

@interface CDClassDump : NSObject

@property (readonly) CDSearchPathState *searchPathState;

@property (assign) BOOL shouldProcessRecursively;
@property (assign) BOOL shouldSortClasses;
@property (assign) BOOL shouldSortClassesByInheritance;
@property (assign) BOOL shouldSortMethods;
@property (assign) BOOL shouldShowIvarOffsets;
@property (assign) BOOL shouldShowMethodAddresses;
@property (assign) BOOL shouldShowHeader;

@property (strong) NSRegularExpression *regularExpression;
- (BOOL)shouldShowName:(NSString *)name;

@property (strong) NSString *sdkRoot;

// Optional dyld_shared_cache used as a fallback when resolving addresses
// from cache-extracted dylibs (selectors, type strings, class refs that
// point into the cache's shared pools).
@property (strong) CDDyldCache *backingCache;

@property (readonly) NSArray *machOFiles;
@property (readonly) NSArray *objcProcessors;

@property (assign) CDArch targetArch;

@property (nonatomic, readonly) BOOL containsObjectiveCData;
@property (nonatomic, readonly) BOOL hasEncryptedFiles;
@property (nonatomic, readonly) BOOL hasObjectiveCRuntimeInfo;

@property (readonly) CDTypeController *typeController;

- (BOOL)loadFile:(CDFile *)file error:(NSError **)error;

// Loads `file` like -loadFile: but marks every Mach-O image it adds
// (including dylibs picked up via the recursive loader) as a "type pool"
// source: its Objective-C type encodings still feed CDTypeController so
// struct/union definitions get merged across binaries, but its classes,
// categories, and protocols are skipped by -recursivelyVisit: and so are
// not emitted to output.
- (BOOL)loadFileAsTypePoolSource:(CDFile *)file error:(NSError **)error;

// Walks `directoryPath` recursively, opening every regular file that
// looks like a Mach-O (or fat archive) and loading it as a type pool
// source. Paths whose standardized form equals `excludedPath` are
// skipped (use this to avoid re-loading the primary binary).
// Best architecture per-file is chosen via -bestMatchForLocalArch:.
// Returns the number of files successfully loaded as pool sources.
- (NSUInteger)scanDirectoryForTypePool:(NSString *)directoryPath
                              excluding:(NSString *)excludedPath
                                  error:(NSError **)error;

- (void)processObjectiveCData;

- (void)recursivelyVisit:(CDVisitor *)visitor;

- (void)appendHeaderToString:(NSMutableString *)resultString;

- (void)registerTypes;

- (void)showHeader;
- (void)showLoadCommands;

@end

extern NSString *CDErrorDomain_ClassDump;
extern NSString *CDErrorKey_Exception;


