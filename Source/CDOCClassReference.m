// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDOCClassReference.h"
#import "CDOCClass.h"
#import "CDSymbol.h"
#import "CDSwiftDemangler.h"

@implementation CDOCClassReference

- (instancetype)initWithClassSymbol:(CDSymbol *)symbol;
{
    if ((self = [super init])) {
        _classSymbol = symbol;
    }

    return self;
}

- (instancetype)initWithClassObject:(CDOCClass *)classObject;
{
    if ((self = [super init])) {
        _classObject = classObject;
    }

    return self;
}

- (instancetype)initWithClassName:(NSString *)className;
{
    if ((self = [super init])) {
        _className = [className copy];
    }

    return self;
}

- (NSString *)className;
{
    NSString *name = nil;
    if (_className != nil)
        name = _className;
    else if (_classObject != nil)
        name = [_classObject name];
    else if (_classSymbol != nil) {
        // _OBJC_CLASS_$_<Foo> -> Foo when present, otherwise the symbol's
        // own (possibly Swift-mangled) name.
        NSString *symbolName = [_classSymbol name];
        NSString *stripped = [CDSymbol classNameFromSymbolName:symbolName];
        name = stripped != nil ? stripped : symbolName;
    }

    // Demangle Swift class symbols (e.g. `_$s11AppStoreKit11ArtworkViewCN`)
    // and normalize private-discriminator names so the dumped header and
    // filename use the human-readable form (`AppStoreKit.ArtworkView`,
    // `Module.Foo__priv_HEX`) instead of the raw runtime form.
    return [CDSwiftDemangler cleanClassName:name];
}

- (BOOL)isExternalClass;
{
    return (!_classObject && (!_classSymbol || [_classSymbol isExternal]));
}

@end
