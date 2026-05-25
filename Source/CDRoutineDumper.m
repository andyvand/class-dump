// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDRoutineDumper.h"

#import "CDClassDump.h"
#import "CDMachOFile.h"
#import "CDLCSegment.h"
#import "CDSection.h"
#import "CDLCSymbolTable.h"
#import "CDLCFunctionStarts.h"
#import "CDLoadCommand.h"
#import "CDSymbol.h"
#import "CDVisitor.h"
#import "CDOCClass.h"
#import "CDOCCategory.h"
#import "CDOCMethod.h"
#import "CDOCProtocol.h"
#import "CDObjectiveCProcessor.h"
#import "CDSwiftDemangler.h"
#import "CDCPlusPlusDumper.h"
#import "CDDyldCache.h"

#include <mach-o/loader.h>
#include <mach-o/stab.h>

// -- ObjC method address collector ------------------------------------------
//
// Walks every class/category/protocol the CDClassDump has loaded and
// records each method's IMP address along with a printable
// `-[Class method:]` / `+[Class(Cat) method:]` label.
@interface CDRoutineObjCCollectorVisitor : CDVisitor
@property (nonatomic, readonly) NSMutableDictionary<NSNumber *, NSString *> *bindings;
@end

@implementation CDRoutineObjCCollectorVisitor
{
    NSMutableDictionary<NSNumber *, NSString *> *_bindings;
    NSString *_currentScope;   // e.g. "Foo" or "Foo(Bar)"
    BOOL _inProtocol;
}

- (instancetype)init
{
    if ((self = [super init])) {
        _bindings = [NSMutableDictionary dictionary];
        _currentScope = nil;
        _inProtocol = NO;
    }
    return self;
}

- (void)willVisitClass:(CDOCClass *)aClass
{
    _currentScope = aClass.name ?: @"?";
    _inProtocol = NO;
}

- (void)didVisitClass:(CDOCClass *)aClass
{
    _currentScope = nil;
}

- (void)willVisitCategory:(CDOCCategory *)category
{
    NSString *cls = category.className ?: @"?";
    NSString *catName = category.name ?: @"";
    _currentScope = [NSString stringWithFormat:@"%@(%@)", cls, catName];
    _inProtocol = NO;
}

- (void)didVisitCategory:(CDOCCategory *)category
{
    _currentScope = nil;
}

- (void)willVisitProtocol:(CDOCProtocol *)protocol
{
    // Protocols don't carry IMPs — track scope only so we don't accidentally
    // attribute a method to a stale class context.
    _currentScope = protocol.name ?: @"?";
    _inProtocol = YES;
}

- (void)didVisitProtocol:(CDOCProtocol *)protocol
{
    _currentScope = nil;
    _inProtocol = NO;
}

- (void)_recordMethod:(CDOCMethod *)m kind:(unichar)kind
{
    if (_inProtocol) return;
    if (_currentScope == nil) return;
    NSUInteger addr = m.address;
    if (addr == 0) return;
    NSString *label = [NSString stringWithFormat:@"%C[%@ %@]",
                       kind, _currentScope, m.name ?: @"?"];
    NSNumber *key = @(addr);
    NSString *existing = _bindings[key];
    if (existing == nil) {
        _bindings[key] = label;
    } else if (![existing containsString:label]) {
        _bindings[key] = [existing stringByAppendingFormat:@", %@", label];
    }
}

- (void)visitClassMethod:(CDOCMethod *)method
{
    [self _recordMethod:method kind:'+'];
}

- (void)visitInstanceMethod:(CDOCMethod *)method propertyState:(id)propertyState
{
    [self _recordMethod:method kind:'-'];
}

@end

#pragma mark -

@implementation CDRoutineDumper

// Return the segment,section name pair containing `addr`, or @"?,?".
static NSString *CDSegSectionName(CDMachOFile *mf, uint64_t addr)
{
    CDLCSegment *seg = [mf segmentContainingAddress:(NSUInteger)addr];
    if (seg == nil) return @"?,?";
    CDSection *sect = [seg sectionContainingAddress:(NSUInteger)addr];
    if (sect == nil) return [NSString stringWithFormat:@"%@,?", seg.name ?: @"?"];
    return [NSString stringWithFormat:@"%@,%@",
            sect.segmentName ?: @"?", sect.sectionName ?: @"?"];
}

// Apply C++/Swift demangling. Returns nil if `mangled` isn't recognized.
static NSString *CDDemangleSymbol(NSString *mangled)
{
    if (mangled == nil) return nil;
    if ([CDSwiftDemangler isMangledSwiftName:mangled]) {
        NSString *s = [CDSwiftDemangler demangle:mangled];
        if (s != nil && ![s isEqualToString:mangled]) return s;
    }
    NSString *c = [CDCPlusPlusDumper demangle:mangled];
    if (c != nil && ![c isEqualToString:mangled]) return c;
    return nil;
}

// Classify a routine.
typedef NS_ENUM(NSUInteger, CDRoutineKind) {
    CDRoutineKindSub   = 0, // no symbol
    CDRoutineKindFunc  = 1, // ordinary C symbol
    CDRoutineKindObjC  = 2, // matches an ObjC IMP
    CDRoutineKindCxx   = 3, // Itanium-mangled C++
    CDRoutineKindSwift = 4, // Swift-mangled
};

static NSString *CDRoutineKindName(CDRoutineKind k)
{
    switch (k) {
        case CDRoutineKindSub:   return @"sub";
        case CDRoutineKindFunc:  return @"func";
        case CDRoutineKindObjC:  return @"objc";
        case CDRoutineKindCxx:   return @"cxx";
        case CDRoutineKindSwift: return @"swift";
    }
    return @"?";
}

// Strip Mach-O underscore prefix from a "C-style" symbol so the printed name
// matches the source-level identifier. `__Z…` / `__T…` keep their underscores
// because the demangler needs them.
static NSString *CDDisplayNameForSymbol(NSString *raw)
{
    if (raw == nil) return @"";
    if ([raw hasPrefix:@"__Z"]) return raw; // C++
    if ([raw hasPrefix:@"_$s"] || [raw hasPrefix:@"_$S"] ||
        [raw hasPrefix:@"__T"] || [raw hasPrefix:@"_T0"]) {
        return [raw substringFromIndex:1]; // Swift: drop one underscore
    }
    if ([raw hasPrefix:@"_"]) return [raw substringFromIndex:1];
    return raw;
}

+ (BOOL)writeRoutinesForMachOFile:(CDMachOFile *)mf
                        classDump:(CDClassDump *)cd
                      toDirectory:(NSString *)outDir
                            error:(NSError **)error
{
    if (mf == nil) return YES;

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:outDir]) {
        if (![fm createDirectoryAtPath:outDir
           withIntermediateDirectories:YES
                            attributes:nil
                                 error:error]) return NO;
    }

    // -- Resolve __TEXT base address ---------------------------------------
    CDLCSegment *textSeg = [mf segmentWithName:@"__TEXT"];
    uint64_t textBase = textSeg ? (uint64_t)textSeg.vmaddr : 0;

    // -- Gather function-start vmaddrs (deduped) ---------------------------
    NSMutableSet<NSNumber *> *funcStartSet = [NSMutableSet set];
    NSMutableArray<NSNumber *> *funcStartList = [NSMutableArray array];
    CDLCFunctionStarts *fs = nil;
    for (CDLoadCommand *lc in mf.loadCommands) {
        if ([lc isKindOfClass:[CDLCFunctionStarts class]]) {
            fs = (CDLCFunctionStarts *)lc;
            break;
        }
    }
    if (fs) {
        for (NSNumber *off in fs.functionStarts) {
            uint64_t va = textBase + [off unsignedLongLongValue];
            NSNumber *key = @(va);
            if (![funcStartSet containsObject:key]) {
                [funcStartSet addObject:key];
                [funcStartList addObject:key];
            }
        }
    }

    // -- Gather LC_SYMTAB symbols that look like routines ------------------
    // Build value → array-of-symbol-names. Any defined symbol that lives in
    // __TEXT and looks like code goes in. We accept stab N_FUN entries too
    // because the DSC unmapped-locals table re-emits them as N_FUN.
    NSMutableDictionary<NSNumber *, NSMutableArray<NSString *> *> *symbolsByAddr =
        [NSMutableDictionary dictionary];

    // -- DSC unmapped local symbols ---------------------------------------
    // dsc_extractor strips most LC_SYMTAB locals out of extracted dylibs;
    // recover them from the cache's `.symbols` sidecar.
    NSDictionary<NSNumber *, NSString *> *dscLocals = nil;
    if (cd.backingCache != nil && textBase != 0) {
        dscLocals = [cd.backingCache localSymbolsForImageAtAddress:textBase];
        for (NSNumber *k in dscLocals) {
            NSString *nm = dscLocals[k];
            if (nm == nil || [nm length] == 0) continue;
            NSMutableArray *list = symbolsByAddr[k];
            if (list == nil) {
                list = [NSMutableArray array];
                symbolsByAddr[k] = list;
            }
            if (![list containsObject:nm]) [list addObject:nm];
            if (![funcStartSet containsObject:k]) {
                [funcStartSet addObject:k];
                [funcStartList addObject:k];
            }
        }
    }

    CDLCSymbolTable *st = mf.symbolTable;
    if (st) {
        [st loadSymbols];
        for (CDSymbol *sym in st.symbols) {
            if (sym.value == 0) continue;
            // Accept N_SECT in __TEXT, or N_FUN stabs (debug-style local function symbols).
            BOOL isFunction = NO;
            if (sym.isInSection) {
                CDSection *sec = sym.section;
                if (sec && [sec.segmentName isEqualToString:@"__TEXT"]) {
                    // __text, __stubs, __auth_stubs, __stub_helper… all count
                    isFunction = YES;
                }
            } else if (sym.stab == N_FUN) {
                isFunction = YES;
            }
            if (!isFunction) continue;
            if (sym.name == nil || [sym.name length] == 0) continue;

            NSNumber *key = @(sym.value);
            NSMutableArray *list = symbolsByAddr[key];
            if (list == nil) {
                list = [NSMutableArray array];
                symbolsByAddr[key] = list;
            }
            if (![list containsObject:sym.name]) [list addObject:sym.name];

            // Symbols can sit at addresses LC_FUNCTION_STARTS missed (e.g.
            // exception thunks). Surface them anyway.
            if (![funcStartSet containsObject:key]) {
                [funcStartSet addObject:key];
                [funcStartList addObject:key];
            }
        }
    }

    // -- Collect ObjC IMP → method-binding string --------------------------
    NSDictionary<NSNumber *, NSString *> *objcBindings = @{};
    if (cd) {
        CDRoutineObjCCollectorVisitor *collector = [[CDRoutineObjCCollectorVisitor alloc] init];
        collector.classDump = cd;
        @try {
            [cd recursivelyVisit:collector];
        } @catch (NSException *e) {
            // Don't let a malformed image kill the routine listing.
        }
        objcBindings = [collector.bindings copy];

        // Make sure ObjC IMPs show up even if neither LC_FUNCTION_STARTS nor
        // LC_SYMTAB references them (common for cache-extracted dylibs).
        for (NSNumber *addr in objcBindings) {
            if (![funcStartSet containsObject:addr]) {
                [funcStartSet addObject:addr];
                [funcStartList addObject:addr];
            }
        }
    }

    // -- Sort routines by address ------------------------------------------
    [funcStartList sortUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
        uint64_t va = [a unsignedLongLongValue], vb = [b unsignedLongLongValue];
        return (va < vb) ? NSOrderedAscending : (va > vb) ? NSOrderedDescending : NSOrderedSame;
    }];

    BOOL is64 = mf.uses64BitABI;
    NSString *addrFmt = is64 ? @"0x%016llx" : @"0x%08llx";

    // -- Render -------------------------------------------------------------
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"//\n//     Generated by class-dump 3.5 (64 bit) — routine listing.\n//\n"];
    [out appendFormat:@"// image:   %@\n", mf.filename ?: @"?"];
    [out appendFormat:@"// arch:    %@\n", mf.archName ?: @"?"];
    NSUUID *u = mf.UUID;
    if (u) [out appendFormat:@"// uuid:    %@\n", [u UUIDString]];
    [out appendFormat:@"// text:    0x%016llx\n", textBase];
    [out appendFormat:@"// count:   %lu routines\n",
                      (unsigned long)[funcStartList count]];
    [out appendString:@"//\n"];
    [out appendString:@"// columns: addr  size  segment,section  kind  name [demangled] [objc-binding]\n"];
    [out appendString:@"//\n"];

    NSUInteger n = [funcStartList count];
    for (NSUInteger i = 0; i < n; i++) {
        uint64_t va = [funcStartList[i] unsignedLongLongValue];
        uint64_t next = (i + 1 < n) ? [funcStartList[i + 1] unsignedLongLongValue] : 0;
        uint64_t size = (next > va) ? (next - va) : 0;

        NSString *segSec = CDSegSectionName(mf, va);

        // Pick a representative symbol (first by insertion order — usually
        // external/global wins because LC_SYMTAB emits those first).
        NSMutableArray<NSString *> *syms = symbolsByAddr[@(va)];
        NSString *primary = [syms firstObject];
        NSString *display = CDDisplayNameForSymbol(primary);
        NSString *demangled = CDDemangleSymbol(primary);

        NSString *objcLabel = objcBindings[@(va)];

        CDRoutineKind kind;
        if (objcLabel != nil) kind = CDRoutineKindObjC;
        else if (primary == nil) kind = CDRoutineKindSub;
        else if ([CDSwiftDemangler isMangledSwiftName:primary]) kind = CDRoutineKindSwift;
        else if ([primary hasPrefix:@"__Z"]) kind = CDRoutineKindCxx;
        else kind = CDRoutineKindFunc;

        NSString *name;
        if (primary != nil) {
            name = display;
        } else if (objcLabel != nil) {
            // Use the ObjC method binding as the identifier itself when
            // LC_SYMTAB has nothing to say (typical for cache-stripped images).
            name = objcLabel;
        } else {
            name = [NSString stringWithFormat:@"sub_%llx", va];
        }

        [out appendFormat:addrFmt, va];
        [out appendFormat:@"  0x%08llx  %-22@  %-5@  %@",
                          size, segSec, CDRoutineKindName(kind), name];
        if (demangled) {
            [out appendFormat:@"  // %@", demangled];
        }
        if (objcLabel && primary != nil) {
            // Only emit the binding as a comment when the primary name was
            // the raw LC_SYMTAB symbol; otherwise it would just repeat `name`.
            [out appendFormat:@"  // %@", objcLabel];
        }
        if ([syms count] > 1) {
            NSMutableArray *aliases = [NSMutableArray array];
            for (NSUInteger k = 1; k < [syms count]; k++) {
                [aliases addObject:CDDisplayNameForSymbol(syms[k])];
            }
            [out appendFormat:@"  // aliases: %@",
                              [aliases componentsJoinedByString:@", "]];
        }
        [out appendString:@"\n"];
    }

    NSString *base = [(mf.filename ?: @"image") lastPathComponent];
    NSString *outPath = [outDir stringByAppendingPathComponent:
                         [base stringByAppendingPathExtension:@"routines.txt"]];
    return [out writeToFile:outPath atomically:YES encoding:NSUTF8StringEncoding error:error];
}

@end
