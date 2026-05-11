// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDDecompiler.h"

#include <glob.h>
#include <string.h>

NSString *CDErrorDomain_Decompiler = @"CDErrorDomain_Decompiler";

// The Ghidra post-script. Kept here so the class-dump binary is
// self-contained and doesn't need to locate ThirdParty/CDDecompile.java
// at runtime. Keep in sync with ThirdParty/CDDecompile.java.
static NSString * const kCDDecompileScript = @
"import ghidra.app.script.GhidraScript;\n"
"import ghidra.app.decompiler.DecompInterface;\n"
"import ghidra.app.decompiler.DecompileOptions;\n"
"import ghidra.app.decompiler.DecompileResults;\n"
"import ghidra.app.decompiler.DecompiledFunction;\n"
"import ghidra.program.model.listing.Function;\n"
"import ghidra.program.model.listing.FunctionIterator;\n"
"import java.io.PrintWriter;\n"
"import java.io.FileOutputStream;\n"
"\n"
"public class CDDecompile extends GhidraScript {\n"
"    @Override\n"
"    protected void run() throws Exception {\n"
"        String[] args = getScriptArgs();\n"
"        if (args.length < 1) { println(\"CDDecompile: missing output path argument\"); return; }\n"
"        String outPath = args[0];\n"
"        DecompInterface di = new DecompInterface();\n"
"        DecompileOptions opts = new DecompileOptions();\n"
"        di.setOptions(opts);\n"
"        di.toggleCCode(true);\n"
"        di.toggleSyntaxTree(true);\n"
"        di.setSimplificationStyle(\"decompile\");\n"
"        if (!di.openProgram(currentProgram)) {\n"
"            println(\"CDDecompile: openProgram failed: \" + di.getLastMessage());\n"
"            return;\n"
"        }\n"
"        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));\n"
"        pw.println(\"// Decompiled by class-dump --decompile (Ghidra headless).\");\n"
"        pw.println(\"// Program: \" + currentProgram.getName());\n"
"        pw.println(\"// Language: \" + currentProgram.getLanguageID());\n"
"        pw.println();\n"
"        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);\n"
"        int total = 0, ok = 0;\n"
"        while (it.hasNext()) {\n"
"            if (monitor.isCancelled()) break;\n"
"            Function f = it.next();\n"
"            if (f.isThunk() || f.isExternal()) continue;\n"
"            total++;\n"
"            try {\n"
"                DecompileResults r = di.decompileFunction(f, 120, monitor);\n"
"                if (r != null && r.decompileCompleted()) {\n"
"                    DecompiledFunction df = r.getDecompiledFunction();\n"
"                    if (df != null) {\n"
"                        pw.println(\"// ---- \" + f.getName() + \" @ \" + f.getEntryPoint() + \" ----\");\n"
"                        pw.println(df.getC());\n"
"                        pw.println();\n"
"                        ok++;\n"
"                    }\n"
"                }\n"
"            } catch (Exception e) {\n"
"                pw.println(\"// !! decompile of \" + f.getName() + \" failed: \" + e.getMessage());\n"
"            }\n"
"        }\n"
"        pw.println(\"// \" + ok + \"/\" + total + \" functions decompiled.\");\n"
"        pw.close();\n"
"        di.dispose();\n"
"        println(\"CDDecompile: wrote \" + ok + \"/\" + total + \" functions to \" + outPath);\n"
"    }\n"
"}\n";

// Ordered list of likely Ghidra install locations probed when GHIDRA_HOME
// is unset. Each entry is treated as a glob (expanded via glob(3) and
// sorted descending so the newest version wins). The Ghidra install root
// is the directory that contains `support/analyzeHeadless`.
//
// Homebrew formula installs put that directory under libexec/; Cask
// installs and manual downloads use a flat ghidra_*_PUBLIC tree.
static NSArray<NSString *> *CDGhidraSearchGlobs(void)
{
    NSString *home = NSHomeDirectory();
    return @[
        // Homebrew formula (Apple Silicon and Intel)
        @"/opt/homebrew/Cellar/ghidra/*/libexec",
        @"/usr/local/Cellar/ghidra/*/libexec",
        // Homebrew Cask (older recipe layout)
        @"/opt/homebrew/Caskroom/ghidra/*/ghidra_*",
        @"/usr/local/Caskroom/ghidra/*/ghidra_*",
        // /Applications drops
        @"/Applications/ghidra",
        @"/Applications/Ghidra",
        @"/Applications/ghidra_*",
        @"/Applications/Ghidra_*",
        // Per-user installs
        [home stringByAppendingPathComponent:@"ghidra"],
        [home stringByAppendingPathComponent:@"ghidra_*"],
        // System-wide manual installs
        @"/opt/ghidra",
        @"/opt/ghidra_*",
        @"/usr/local/ghidra",
        @"/usr/local/ghidra_*",
    ];
}

// Fall back to following `ghidraRun` on $PATH: it's typically a shell
// wrapper that execs into <install>/support/launch.sh or
// <install>/ghidraRun, so the install root is two directories up from
// the resolved binary. Returns nil on any failure.
static NSString *CDFindGhidraFromPATH(void)
{
    NSTask *t = [[NSTask alloc] init];
    t.launchPath = @"/usr/bin/which";
    t.arguments = @[ @"ghidraRun" ];
    NSPipe *p = [NSPipe pipe];
    t.standardOutput = p;
    t.standardError = [NSPipe pipe];
    @try { [t launch]; } @catch (NSException *e) { return nil; }
    [t waitUntilExit];
    if ([t terminationStatus] != 0) return nil;
    NSData *d = [[p fileHandleForReading] readDataToEndOfFile];
    NSString *s = [[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding]
                   stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([s length] == 0) return nil;

    // Open the wrapper and look for an explicit /libexec/.../analyzeHeadless
    // or a literal install root reference. Homebrew's wrapper does:
    //   exec "/opt/homebrew/Cellar/ghidra/<ver>/libexec/ghidraRun" "$@"
    NSString *contents = [NSString stringWithContentsOfFile:s encoding:NSUTF8StringEncoding error:NULL];
    if (contents) {
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"\"(/[^\"\\s]+)/ghidraRun\""
                                                                            options:0 error:NULL];
        NSTextCheckingResult *m = [re firstMatchInString:contents options:0
                                                   range:NSMakeRange(0, [contents length])];
        if (m && [m numberOfRanges] >= 2) {
            NSString *root = [contents substringWithRange:[m rangeAtIndex:1]];
            NSString *probe = [root stringByAppendingPathComponent:@"support/analyzeHeadless"];
            if ([[NSFileManager defaultManager] isExecutableFileAtPath:probe]) return root;
        }
    }
    return nil;
}

static NSArray<NSString *> *CDExpandGlob(NSString *pattern)
{
    if ([pattern rangeOfString:@"*"].location == NSNotFound) {
        return @[ pattern ];
    }
    glob_t g;
    memset(&g, 0, sizeof(g));
    if (glob([pattern fileSystemRepresentation], 0, NULL, &g) != 0) {
        globfree(&g);
        return @[];
    }
    NSMutableArray *matches = [NSMutableArray array];
    for (size_t i = 0; i < g.gl_pathc; i++) {
        [matches addObject:[NSString stringWithUTF8String:g.gl_pathv[i]]];
    }
    globfree(&g);
    // Newest version first (lexicographic descending).
    [matches sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) { return [b compare:a]; }];
    return matches;
}

@implementation CDDecompiler

+ (NSString *)findGhidraHome
{
    NSDictionary *env = [[NSProcessInfo processInfo] environment];
    NSString *fromEnv = env[@"GHIDRA_HOME"];
    if ([fromEnv length] > 0) {
        NSString *probe = [fromEnv stringByAppendingPathComponent:@"support/analyzeHeadless"];
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:probe]) return fromEnv;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *pattern in CDGhidraSearchGlobs()) {
        for (NSString *candidate in CDExpandGlob(pattern)) {
            NSString *probe = [candidate stringByAppendingPathComponent:@"support/analyzeHeadless"];
            if ([fm isExecutableFileAtPath:probe]) return candidate;
        }
    }

    // Last resort: follow ghidraRun on $PATH back to its install root.
    NSString *fromPath = CDFindGhidraFromPATH();
    if (fromPath) return fromPath;

    return nil;
}

+ (NSString *)installHint
{
    return @"Install Ghidra (`brew install ghidra`, or download from "
           @"https://ghidra-sre.org), make sure `ghidraRun` is on $PATH or "
           @"set GHIDRA_HOME to the directory that contains "
           @"support/analyzeHeadless (e.g. "
           @"/opt/homebrew/Cellar/ghidra/<version>/libexec).";
}

+ (BOOL)decompileMachOAtPath:(NSString *)inputPath
                      toPath:(NSString *)outputCPath
                       error:(NSError *__autoreleasing *)error
{
    NSFileManager *fm = [NSFileManager defaultManager];

    if (![fm isReadableFileAtPath:inputPath]) {
        if (error) *error = [NSError errorWithDomain:CDErrorDomain_Decompiler code:1
                                            userInfo:@{ NSLocalizedFailureReasonErrorKey:
                                                            [NSString stringWithFormat:@"Input not readable: %@", inputPath] }];
        return NO;
    }

    NSString *ghidraHome = [self findGhidraHome];
    if (ghidraHome == nil) {
        if (error) *error = [NSError errorWithDomain:CDErrorDomain_Decompiler code:2
                                            userInfo:@{ NSLocalizedFailureReasonErrorKey:
                                                            [NSString stringWithFormat:@"Ghidra not found. %@", [self installHint]] }];
        return NO;
    }

    NSString *analyzeHeadless = [ghidraHome stringByAppendingPathComponent:@"support/analyzeHeadless"];

    // Per-invocation temp dir: holds the Ghidra project, the script, and
    // any working state. Cleaned up at the end regardless of outcome.
    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:
                     [@"class-dump-decompile-" stringByAppendingString:[[NSUUID UUID] UUIDString]]];
    if (![fm createDirectoryAtPath:tmp withIntermediateDirectories:YES attributes:nil error:NULL]) {
        if (error) *error = [NSError errorWithDomain:CDErrorDomain_Decompiler code:3
                                            userInfo:@{ NSLocalizedFailureReasonErrorKey:
                                                            [NSString stringWithFormat:@"Cannot create temp dir %@", tmp] }];
        return NO;
    }

    NSString *projectDir = [tmp stringByAppendingPathComponent:@"proj"];
    NSString *scriptDir  = [tmp stringByAppendingPathComponent:@"scripts"];
    [fm createDirectoryAtPath:projectDir withIntermediateDirectories:YES attributes:nil error:NULL];
    [fm createDirectoryAtPath:scriptDir  withIntermediateDirectories:YES attributes:nil error:NULL];

    NSString *scriptPath = [scriptDir stringByAppendingPathComponent:@"CDDecompile.java"];
    NSError *writeErr = nil;
    if (![kCDDecompileScript writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:&writeErr]) {
        if (error) *error = [NSError errorWithDomain:CDErrorDomain_Decompiler code:4
                                            userInfo:@{ NSLocalizedFailureReasonErrorKey:
                                                            [NSString stringWithFormat:@"Cannot write script: %@", [writeErr localizedDescription]] }];
        [fm removeItemAtPath:tmp error:NULL];
        return NO;
    }

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = analyzeHeadless;
    task.arguments = @[
        projectDir,
        @"CDDecompileProject",
        @"-import",     inputPath,
        @"-scriptPath", scriptDir,
        @"-postScript", @"CDDecompile.java", outputCPath,
        @"-deleteProject",
        @"-overwrite",
    ];
    NSPipe *outPipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    task.standardOutput = outPipe;
    task.standardError  = errPipe;

    NSError *launchErr = nil;
    BOOL launched = NO;
    if (@available(macOS 10.13, *)) {
        launched = [task launchAndReturnError:&launchErr];
    } else {
        @try { [task launch]; launched = YES; }
        @catch (NSException *e) { launchErr = [NSError errorWithDomain:CDErrorDomain_Decompiler code:5
                                                              userInfo:@{ NSLocalizedFailureReasonErrorKey: [e reason] ?: @"launch failed" }]; }
    }
    if (!launched) {
        if (error) *error = launchErr ?: [NSError errorWithDomain:CDErrorDomain_Decompiler code:5
                                                          userInfo:@{ NSLocalizedFailureReasonErrorKey: @"Failed to launch analyzeHeadless" }];
        [fm removeItemAtPath:tmp error:NULL];
        return NO;
    }

    [task waitUntilExit];

    // Drain pipes so the child doesn't block on a full buffer.
    NSData *stderrData = [[errPipe fileHandleForReading] readDataToEndOfFile];
    (void)[[outPipe fileHandleForReading] readDataToEndOfFile];

    int rc = [task terminationStatus];
    [fm removeItemAtPath:tmp error:NULL];

    if (rc != 0 || ![fm fileExistsAtPath:outputCPath]) {
        NSString *stderrStr = [[NSString alloc] initWithData:stderrData encoding:NSUTF8StringEncoding] ?: @"";
        // Trim very long stderr to keep error messages bounded.
        if ([stderrStr length] > 4096) {
            stderrStr = [@"...\n" stringByAppendingString:[stderrStr substringFromIndex:[stderrStr length] - 4096]];
        }
        if (error) *error = [NSError errorWithDomain:CDErrorDomain_Decompiler code:6
                                            userInfo:@{ NSLocalizedFailureReasonErrorKey:
                                                            [NSString stringWithFormat:@"analyzeHeadless exit=%d (%@):\n%@",
                                                             rc, inputPath, stderrStr] }];
        return NO;
    }
    return YES;
}

@end
