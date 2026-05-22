// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDOCCategory.h"

#import "CDClassDump.h"
#import "CDOCMethod.h"
#import "CDVisitor.h"
#import "CDVisitorPropertyState.h"
#import "CDOCClass.h"
#import "CDOCClassReference.h"

@implementation CDOCCategory

#pragma mark - Superclass overrides

- (NSString *)sortableName;
{
    return [NSString stringWithFormat:@"%@ (%@)", [self displayClassName], self.name];
}

#pragma mark -

- (NSString *)className
{
    return [_classRef className];
}

// `className` can be nil when the target class lives in another image of a
// fileset and none of the resolution paths could recover it. Use this when
// formatting headers or filenames so they read `UnknownClass (Category)`
// instead of `(null) (Category)`.
- (NSString *)displayClassName;
{
    NSString *name = [_classRef className];
    if ([name length] == 0)
        return @"UnknownClass";
    return name;
}

- (NSString *)methodSearchContext;
{
    NSMutableString *resultString = [NSMutableString string];

    [resultString appendFormat:@"@interface %@ (%@)", [self displayClassName], self.name];

    if ([self.protocols count] > 0)
        [resultString appendFormat:@" <%@>", self.protocolsString];

    return resultString;
}

- (void)recursivelyVisit:(CDVisitor *)visitor;
{
    if ([visitor.classDump shouldShowName:self.name]) {
        CDVisitorPropertyState *propertyState = [[CDVisitorPropertyState alloc] initWithProperties:self.properties];
        
        [visitor willVisitCategory:self];
        
        //[aVisitor willVisitPropertiesOfCategory:self];
        //[self visitProperties:aVisitor];
        //[aVisitor didVisitPropertiesOfCategory:self];
        
        [self visitMethods:visitor propertyState:propertyState];
        // This can happen when... the accessors are implemented on the main class.  Odd case, but we should still emit the remaining properties.
        // Should mostly be dynamic properties
        [visitor visitRemainingProperties:propertyState];
        [visitor didVisitCategory:self];
    }
}

#pragma mark - CDTopologicalSort protocol

- (NSString *)identifier;
{
    return self.sortableName;
}

- (NSArray *)dependancies;
{
    if (self.className == nil)
        return @[];

    return @[self.className];
}

@end
