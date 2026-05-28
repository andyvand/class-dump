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
//
// This script does NOT mutate the program (no applyTo); it just reads
// types Ghidra's auto-analysis already attached. Return-type recovery
// from mangled C++ names is the job of --decompile-cpp instead, which
// runs the demangler explicitly in a two-pass design that is safe to
// mutate during.
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
"                        String retType = (f.getReturnType() != null) ? f.getReturnType().getName() : \"void\";\n"
"                        pw.println(\"// ---- \" + retType + \" \" + f.getName() + \" @ \" + f.getEntryPoint() + \" ----\");\n"
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

// Swift-only post-script. Walks Swift-mangled functions, demangles each
// signature, decompiles the body, and emits Swift-shaped output: groups
// functions under their owning type as `class Module.Type { func ... }`
// and translates Ghidra pseudo-C bodies heuristically into Swift syntax
// (drops swift_retain/release etc, rewrites `->` to `.`, strips C casts).
// The result is not real, compilable Swift; it is a Swift-shaped sketch.
// Keep in sync with ThirdParty/CDDecompileSwift.java.
static NSString * const kCDDecompileSwiftScript = @
"// CDDecompileSwift.java\n"
"//\n"
"// Ghidra headless post-script invoked by class-dump's --decompile-swift flag.\n"
"// Walks every function with a Swift-mangled symbol ($s / _$s / $S / _$S),\n"
"// demangles via Ghidra's DemanglerUtil to get the Swift signature, decompiles\n"
"// the body, then post-processes the pseudo-C into Swift-shaped syntax: groups\n"
"// functions by their owning Swift type and emits\n"
"//\n"
"//     class Module.MyType {\n"
"//         func foo(x: Int) -> Bool { ... }\n"
"//         init(...) { ... }\n"
"//     }\n"
"//\n"
"// Bodies are translated heuristically: swift_retain/release/access calls are\n"
"// dropped, C casts are removed, `a->b` is rewritten as `a.b`. The output is\n"
"// not real, compilable Swift — it is a Swift-shaped sketch derived from the\n"
"// decompile. Keep in sync with the kCDDecompileSwiftScript string in\n"
"// Source/CDDecompiler.m.\n"
"\n"
"import ghidra.app.script.GhidraScript;\n"
"import ghidra.app.decompiler.DecompInterface;\n"
"import ghidra.app.decompiler.DecompileOptions;\n"
"import ghidra.app.decompiler.DecompileResults;\n"
"import ghidra.app.decompiler.DecompiledFunction;\n"
"import ghidra.app.util.demangler.DemangledObject;\n"
"import ghidra.app.util.demangler.DemanglerUtil;\n"
"import ghidra.program.model.listing.Function;\n"
"import ghidra.program.model.listing.FunctionIterator;\n"
"import ghidra.program.model.mem.MemoryBlock;\n"
"import ghidra.program.model.symbol.Symbol;\n"
"import ghidra.program.model.symbol.SymbolTable;\n"
"import java.io.PrintWriter;\n"
"import java.io.FileOutputStream;\n"
"import java.util.ArrayList;\n"
"import java.util.Arrays;\n"
"import java.util.LinkedHashMap;\n"
"import java.util.List;\n"
"import java.util.Map;\n"
"import java.util.regex.Matcher;\n"
"import java.util.regex.Pattern;\n"
"\n"
"public class CDDecompileSwift extends GhidraScript {\n"
"\n"
"    static class Sig {\n"
"        String container = \"\";\n"
"        String funcName = \"\";\n"
"        String paramList = \"\";\n"
"        String returnType = \"\";\n"
"        boolean isStatic = false;\n"
"        boolean isInit = false;\n"
"        boolean isDeinit = false;\n"
"        boolean isProperty = false;\n"
"        String propertyKind = \"\";\n"
"    }\n"
"\n"
"    private static Sig parseSwiftSig(String sig) {\n"
"        if (sig == null) return null;\n"
"        Sig s = new Sig();\n"
"        sig = sig.trim();\n"
"        if (sig.startsWith(\"static \")) { s.isStatic = true; sig = sig.substring(7).trim(); }\n"
"        int paren = sig.indexOf('(');\n"
"        if (paren < 0) {\n"
"            int colon = sig.indexOf(':');\n"
"            String head = colon >= 0 ? sig.substring(0, colon).trim() : sig.trim();\n"
"            String tail = colon >= 0 ? sig.substring(colon + 1).trim() : \"\";\n"
"            int lastDot = head.lastIndexOf('.');\n"
"            if (lastDot < 0) { s.funcName = head; return s; }\n"
"            String afterDot = head.substring(lastDot + 1);\n"
"            if (afterDot.equals(\"getter\") || afterDot.equals(\"setter\") || afterDot.equals(\"modify\") || afterDot.equals(\"read\")) {\n"
"                s.isProperty = true; s.propertyKind = afterDot;\n"
"                int prevDot = head.lastIndexOf('.', lastDot - 1);\n"
"                if (prevDot >= 0) {\n"
"                    s.container = head.substring(0, prevDot);\n"
"                    s.funcName = head.substring(prevDot + 1, lastDot);\n"
"                } else {\n"
"                    s.funcName = head.substring(0, lastDot);\n"
"                }\n"
"                s.returnType = tail.replace(\"Swift.\", \"\");\n"
"                return s;\n"
"            }\n"
"            s.container = lastDot >= 0 ? head.substring(0, lastDot) : \"\";\n"
"            s.funcName = head.substring(lastDot + 1);\n"
"            return s;\n"
"        }\n"
"        String head = sig.substring(0, paren);\n"
"        int lastDot = head.lastIndexOf('.');\n"
"        if (lastDot < 0) { s.funcName = head.trim(); }\n"
"        else { s.container = head.substring(0, lastDot); s.funcName = head.substring(lastDot + 1).trim(); }\n"
"        int depth = 0, close = -1;\n"
"        for (int i = paren; i < sig.length(); i++) {\n"
"            char c = sig.charAt(i);\n"
"            if (c == '(') depth++;\n"
"            else if (c == ')') { depth--; if (depth == 0) { close = i; break; } }\n"
"        }\n"
"        if (close < 0) close = sig.length() - 1;\n"
"        s.paramList = sig.substring(paren + 1, close).trim().replace(\"Swift.\", \"\");\n"
"        String rest = (close + 1 < sig.length()) ? sig.substring(close + 1).trim() : \"\";\n"
"        if (rest.startsWith(\"->\")) s.returnType = rest.substring(2).trim().replace(\"Swift.\", \"\");\n"
"        s.isInit = s.funcName.equals(\"init\") || s.funcName.startsWith(\"init(\");\n"
"        s.isDeinit = s.funcName.equals(\"deinit\") || s.funcName.startsWith(\"deinit\");\n"
"        return s;\n"
"    }\n"
"\n"
"    private static String stripParenSig(String funcName) {\n"
"        int p = funcName.indexOf('(');\n"
"        if (p < 0) return funcName;\n"
"        return funcName.substring(0, p);\n"
"    }\n"
"\n"
"    private static String swiftifyBody(String c) {\n"
"        if (c == null) return \"\";\n"
"        int firstBrace = c.indexOf('{');\n"
"        int lastBrace = c.lastIndexOf('}');\n"
"        if (firstBrace >= 0 && lastBrace > firstBrace) c = c.substring(firstBrace + 1, lastBrace);\n"
"        c = c.trim();\n"
"        String[] dropCalls = {\n"
"            \"swift_retain\",\"swift_release\",\"swift_bridgeObjectRetain\",\"swift_bridgeObjectRelease\",\n"
"            \"swift_unknownObjectRetain\",\"swift_unknownObjectRelease\",\n"
"            \"swift_beginAccess\",\"swift_endAccess\",\n"
"            \"swift_release_n\",\"swift_retain_n\"\n"
"        };\n"
"        for (String fn : dropCalls) {\n"
"            c = c.replaceAll(\"(?m)^\\\\s*_?\" + Pattern.quote(fn) + \"\\\\s*\\\\([^;]*\\\\);\\\\s*$\\\\n?\", \"\");\n"
"        }\n"
"        c = c.replaceAll(\"_?swift_allocObject\\\\s*\\\\(([^)]*)\\\\)\", \"alloc()\");\n"
"        c = c.replaceAll(\"\\\\(undefined8?\\\\s*\\\\*+\\\\)\", \"\");\n"
"        c = c.replaceAll(\"\\\\(longlong\\\\)\", \"Int(\");\n"
"        c = c.replaceAll(\"\\\\(ulonglong\\\\)\", \"UInt(\");\n"
"        c = c.replaceAll(\"\\\\(uint\\\\)\", \"UInt(\");\n"
"        c = c.replaceAll(\"\\\\(int\\\\)\", \"Int(\");\n"
"        c = c.replaceAll(\"([A-Za-z_][A-Za-z0-9_]*)->\", \"$1.\");\n"
"        c = c.replaceAll(\"(?m)^\\\\s+$\", \"\");\n"
"        c = c.replaceAll(\"\\\\n{3,}\", \"\\n\\n\");\n"
"        return c.trim();\n"
"    }\n"
"\n"
"    private static String emitFunc(Sig s, String body, String mangled, String addr) {\n"
"        StringBuilder sb = new StringBuilder();\n"
"        sb.append(\"    // \").append(addr).append(\"  \").append(mangled).append(\"\\n\");\n"
"        if (s.isProperty) {\n"
"            String ret = s.returnType.isEmpty() ? \"Any\" : s.returnType;\n"
"            sb.append(\"    var \").append(s.funcName).append(\": \").append(ret).append(\" { \");\n"
"            sb.append(s.propertyKind).append(\" {\\n\");\n"
"            for (String line : body.split(\"\\n\")) sb.append(\"        \").append(line).append(\"\\n\");\n"
"            sb.append(\"    } }\\n\");\n"
"            return sb.toString();\n"
"        }\n"
"        sb.append(\"    \");\n"
"        if (s.isStatic) sb.append(\"static \");\n"
"        if (s.isInit) {\n"
"            sb.append(\"init(\").append(s.paramList).append(\") {\\n\");\n"
"        } else if (s.isDeinit) {\n"
"            sb.append(\"deinit {\\n\");\n"
"        } else {\n"
"            sb.append(\"func \").append(stripParenSig(s.funcName));\n"
"            sb.append(\"(\").append(s.paramList).append(\")\");\n"
"            if (!s.returnType.isEmpty() && !s.returnType.equals(\"()\")) {\n"
"                sb.append(\" -> \").append(s.returnType);\n"
"            }\n"
"            sb.append(\" {\\n\");\n"
"        }\n"
"        for (String line : body.split(\"\\n\")) sb.append(\"        \").append(line).append(\"\\n\");\n"
"        sb.append(\"    }\\n\");\n"
"        return sb.toString();\n"
"    }\n"
"\n"
"    @Override\n"
"    protected void run() throws Exception {\n"
"        String[] args = getScriptArgs();\n"
"        if (args.length < 1) { println(\"CDDecompileSwift: missing output path argument\"); return; }\n"
"        String outPath = args[0];\n"
"\n"
"        DecompInterface di = new DecompInterface();\n"
"        DecompileOptions opts = new DecompileOptions();\n"
"        di.setOptions(opts);\n"
"        di.toggleCCode(true);\n"
"        di.toggleSyntaxTree(true);\n"
"        di.setSimplificationStyle(\"decompile\");\n"
"        if (!di.openProgram(currentProgram)) {\n"
"            println(\"CDDecompileSwift: openProgram failed: \" + di.getLastMessage()); return;\n"
"        }\n"
"\n"
"        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));\n"
"        pw.println(\"// Generated by class-dump --decompile-swift\");\n"
"        pw.println(\"// Program: \" + currentProgram.getName());\n"
"        pw.println(\"// Language: \" + currentProgram.getLanguageID());\n"
"        pw.println(\"// Bodies are heuristically translated from Ghidra pseudo-C; treat as a Swift-shaped sketch.\");\n"
"        pw.println();\n"
"\n"
"        boolean isSwiftBinary = false;\n"
"        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {\n"
"            String n = blk.getName();\n"
"            if (n != null && n.startsWith(\"__swift5\")) { isSwiftBinary = true; break; }\n"
"        }\n"
"        if (!isSwiftBinary) {\n"
"            pw.println(\"// (no __swift5_* sections; binary contains no Swift metadata)\");\n"
"            pw.close(); di.dispose();\n"
"            println(\"CDDecompileSwift: no Swift metadata in \" + currentProgram.getName());\n"
"            return;\n"
"        }\n"
"\n"
"        Map<String, StringBuilder> typeBodies = new LinkedHashMap<String, StringBuilder>();\n"
"        StringBuilder topLevel = new StringBuilder();\n"
"\n"
"        SymbolTable st = currentProgram.getSymbolTable();\n"
"        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);\n"
"        int total = 0, swift = 0, ok = 0;\n"
"        while (it.hasNext()) {\n"
"            if (monitor.isCancelled()) break;\n"
"            Function f = it.next();\n"
"            if (f.isThunk() || f.isExternal()) continue;\n"
"            total++;\n"
"            String mangled = null;\n"
"            for (Symbol sym : st.getSymbols(f.getEntryPoint())) {\n"
"                String n = sym.getName();\n"
"                if (n == null) continue;\n"
"                if (n.startsWith(\"$s\") || n.startsWith(\"_$s\")\n"
"                    || n.startsWith(\"$S\") || n.startsWith(\"_$S\")) { mangled = n; break; }\n"
"            }\n"
"            if (mangled == null) {\n"
"                String n = f.getName();\n"
"                if (n != null && (n.startsWith(\"$s\") || n.startsWith(\"_$s\")\n"
"                                  || n.startsWith(\"$S\") || n.startsWith(\"_$S\"))) mangled = n;\n"
"            }\n"
"            if (mangled == null) continue;\n"
"            swift++;\n"
"\n"
"            String sigText = mangled;\n"
"            try {\n"
"                List<DemangledObject> ds = DemanglerUtil.demangle(currentProgram, mangled, f.getEntryPoint());\n"
"                if (ds != null && !ds.isEmpty()) {\n"
"                    DemangledObject d = ds.get(0);\n"
"                    if (d != null) {\n"
"                        String s2 = d.getSignature(false);\n"
"                        if (s2 != null && s2.length() > 0) sigText = s2;\n"
"                    }\n"
"                }\n"
"            } catch (Exception e) { /* keep mangled */ }\n"
"\n"
"            Sig s = parseSwiftSig(sigText);\n"
"            if (s == null) { s = new Sig(); s.funcName = sigText; }\n"
"\n"
"            String body = \"// (decompile failed)\";\n"
"            try {\n"
"                DecompileResults r = di.decompileFunction(f, 120, monitor);\n"
"                if (r != null && r.decompileCompleted()) {\n"
"                    DecompiledFunction df = r.getDecompiledFunction();\n"
"                    if (df != null) {\n"
"                        body = swiftifyBody(df.getC());\n"
"                        ok++;\n"
"                    }\n"
"                }\n"
"            } catch (Exception e) {\n"
"                body = \"// !! decompile failed: \" + e.getMessage();\n"
"            }\n"
"\n"
"            String emit = emitFunc(s, body, mangled, f.getEntryPoint().toString());\n"
"            if (s.container == null || s.container.isEmpty()) {\n"
"                topLevel.append(emit.replaceAll(\"(?m)^    \", \"\")).append(\"\\n\");\n"
"            } else {\n"
"                StringBuilder b = typeBodies.get(s.container);\n"
"                if (b == null) { b = new StringBuilder(); typeBodies.put(s.container, b); }\n"
"                b.append(emit).append(\"\\n\");\n"
"            }\n"
"        }\n"
"\n"
"        for (Map.Entry<String, StringBuilder> e : typeBodies.entrySet()) {\n"
"            String containerPath = e.getKey();\n"
"            int dot = containerPath.lastIndexOf('.');\n"
"            String mod = (dot >= 0) ? containerPath.substring(0, dot) : \"\";\n"
"            String typeName = (dot >= 0) ? containerPath.substring(dot + 1) : containerPath;\n"
"            pw.println(\"// \" + containerPath);\n"
"            if (!mod.isEmpty()) pw.println(\"// import \" + mod);\n"
"            pw.println(\"class \" + typeName + \" {\");\n"
"            pw.println(e.getValue().toString());\n"
"            pw.println(\"}\");\n"
"            pw.println();\n"
"        }\n"
"\n"
"        if (topLevel.length() > 0) {\n"
"            pw.println(\"// MARK: - Free functions\");\n"
"            pw.println(topLevel.toString());\n"
"        }\n"
"\n"
"        pw.println(\"// \" + ok + \"/\" + total + \" functions decompiled; \" + swift + \" were Swift.\");\n"
"        pw.close();\n"
"        di.dispose();\n"
"        println(\"CDDecompileSwift: wrote \" + ok + \"/\" + total + \" functions (\" + swift + \" Swift) to \" + outPath);\n"
"    }\n"
"}\n";


// C++-only post-script. Filters functions to Itanium-mangled C++ names
// (_Z / __Z) and emits pseudo-C with demangled signatures. Two passes:
//   (1) iterate functions once, collect the C++-mangled ones, then close
//       the iterator;
//   (2) walk the collected list, demangle + applyTo() each, then
//       decompile each.
// Splitting the apply-types step out of the FunctionIterator walk avoids
// hangs that show up when applyTo() mutates the program in the middle
// of iteration. Keep in sync with ThirdParty/CDDecompileCpp.java.
static NSString * const kCDDecompileCppScript = @
"import ghidra.app.script.GhidraScript;\n"
"import ghidra.app.decompiler.DecompInterface;\n"
"import ghidra.app.decompiler.DecompileOptions;\n"
"import ghidra.app.decompiler.DecompileResults;\n"
"import ghidra.app.decompiler.DecompiledFunction;\n"
"import ghidra.app.util.demangler.DemangledObject;\n"
"import ghidra.app.util.demangler.DemanglerOptions;\n"
"import ghidra.app.util.demangler.DemanglerUtil;\n"
"import ghidra.program.model.address.Address;\n"
"import ghidra.program.model.listing.Function;\n"
"import ghidra.program.model.listing.FunctionIterator;\n"
"import ghidra.program.model.listing.FunctionManager;\n"
"import ghidra.program.model.symbol.Symbol;\n"
"import ghidra.program.model.symbol.SymbolTable;\n"
"import java.io.PrintWriter;\n"
"import java.io.FileOutputStream;\n"
"import java.util.ArrayList;\n"
"import java.util.List;\n"
"\n"
"public class CDDecompileCpp extends GhidraScript {\n"
"    private static boolean isCppMangled(String n) {\n"
"        return n != null && (n.startsWith(\"_Z\") || n.startsWith(\"__Z\"));\n"
"    }\n"
"    private static class Hit {\n"
"        Address addr;\n"
"        String mangled;\n"
"        Hit(Address a, String m) { addr = a; mangled = m; }\n"
"    }\n"
"    @Override\n"
"    protected void run() throws Exception {\n"
"        String[] args = getScriptArgs();\n"
"        if (args.length < 1) { println(\"CDDecompileCpp: missing output path argument\"); return; }\n"
"        String outPath = args[0];\n"
"        DecompInterface di = new DecompInterface();\n"
"        DecompileOptions opts = new DecompileOptions();\n"
"        di.setOptions(opts);\n"
"        di.toggleCCode(true);\n"
"        di.toggleSyntaxTree(true);\n"
"        di.setSimplificationStyle(\"decompile\");\n"
"        if (!di.openProgram(currentProgram)) {\n"
"            println(\"CDDecompileCpp: openProgram failed: \" + di.getLastMessage()); return;\n"
"        }\n"
"        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));\n"
"        pw.println(\"// Decompiled by class-dump --decompile-cpp (Ghidra headless + Itanium demangler).\");\n"
"        pw.println(\"// Program: \" + currentProgram.getName());\n"
"        pw.println(\"// Language: \" + currentProgram.getLanguageID());\n"
"        pw.println(\"// Return types and parameter types are applied from the C++ mangle before decompile.\");\n"
"        pw.println();\n"
"\n"
"        // Pass 1: scan functions, record the C++-mangled ones. We snapshot\n"
"        // (address, mangled-name) pairs here so subsequent applyTo() calls\n"
"        // cannot invalidate the FunctionIterator.\n"
"        SymbolTable st = currentProgram.getSymbolTable();\n"
"        FunctionManager fm = currentProgram.getFunctionManager();\n"
"        int total = 0;\n"
"        List<Hit> hits = new ArrayList<Hit>();\n"
"        {\n"
"            FunctionIterator it = fm.getFunctions(true);\n"
"            while (it.hasNext()) {\n"
"                if (monitor.isCancelled()) break;\n"
"                Function f = it.next();\n"
"                if (f.isThunk() || f.isExternal()) continue;\n"
"                total++;\n"
"                String mangled = null;\n"
"                for (Symbol s : st.getSymbols(f.getEntryPoint())) {\n"
"                    String n = s.getName();\n"
"                    if (isCppMangled(n)) { mangled = n; break; }\n"
"                }\n"
"                if (mangled == null && isCppMangled(f.getName())) mangled = f.getName();\n"
"                if (mangled != null) hits.add(new Hit(f.getEntryPoint(), mangled));\n"
"            }\n"
"        }\n"
"\n"
"        // Pass 2: apply the demangled signature, then decompile.\n"
"        int ok = 0;\n"
"        for (Hit h : hits) {\n"
"            if (monitor.isCancelled()) break;\n"
"            Function f = fm.getFunctionAt(h.addr);\n"
"            if (f == null) continue;\n"
"            String displayName = h.mangled;\n"
"            try {\n"
"                List<DemangledObject> ds = DemanglerUtil.demangle(currentProgram, h.mangled, h.addr);\n"
"                if (ds != null && !ds.isEmpty()) {\n"
"                    DemangledObject d = ds.get(0);\n"
"                    if (d != null) {\n"
"                        String sig = d.getSignature(false);\n"
"                        if (sig != null && sig.length() > 0) displayName = sig;\n"
"                        try {\n"
"                            DemanglerOptions opts2 = new DemanglerOptions();\n"
"                            opts2.setApplySignature(true);\n"
"                            d.applyTo(currentProgram, h.addr, opts2, monitor);\n"
"                        } catch (Exception e2) { /* best-effort */ }\n"
"                    }\n"
"                }\n"
"            } catch (Exception e) { /* keep mangled */ }\n"
"            // Re-fetch f in case applyTo replaced it.\n"
"            f = fm.getFunctionAt(h.addr);\n"
"            if (f == null) continue;\n"
"            try {\n"
"                DecompileResults r = di.decompileFunction(f, 120, monitor);\n"
"                if (r != null && r.decompileCompleted()) {\n"
"                    DecompiledFunction df = r.getDecompiledFunction();\n"
"                    if (df != null) {\n"
"                        String retType = (f.getReturnType() != null) ? f.getReturnType().getName() : \"void\";\n"
"                        pw.println(\"// ---- \" + displayName + \" ----\");\n"
"                        pw.println(\"// address: \" + h.addr);\n"
"                        pw.println(\"// return type: \" + retType);\n"
"                        pw.println(\"// mangled: \" + h.mangled);\n"
"                        pw.println(df.getC());\n"
"                        pw.println();\n"
"                        ok++;\n"
"                    }\n"
"                }\n"
"            } catch (Exception e) {\n"
"                pw.println(\"// !! decompile of \" + displayName + \" failed: \" + e.getMessage());\n"
"            }\n"
"        }\n"
"        pw.println(\"// \" + ok + \"/\" + hits.size() + \" C++ functions decompiled (of \" + total + \" total).\");\n"
"        pw.close();\n"
"        di.dispose();\n"
"        println(\"CDDecompileCpp: wrote \" + ok + \"/\" + hits.size() + \" C++ functions to \" + outPath);\n"
"    }\n"
"}\n";

// Obj-C-only post-script. Walks functions whose name is `-[Class sel]` /
// `+[Class sel]` (Ghidra's labels for ObjC method IMPs), groups them by
// class, decompiles each body, and emits ObjC-shaped output:
//
//     @implementation Class
//     - (id)foo:(id)arg0 { /* translated body */ }
//     @end
//
// Bodies are heuristically rewritten: objc_msgSend(recv,"sel",args...) ->
// [recv sel:args], ARC retain/release/autorelease calls are dropped,
// objc_storeStrong(&dst,src) -> dst = src, _OBJC_CLASS_$_Foo -> [Foo class].
// The result is not real, compilable Obj-C; it is an ObjC-shaped sketch.
// Keep in sync with ThirdParty/CDDecompileObjc.java.
static NSString * const kCDDecompileObjcScript = @
"// CDDecompileObjc.java\n"
"//\n"
"// Ghidra headless post-script invoked by class-dump's --decompile-objc flag.\n"
"// Filters functions whose Ghidra-assigned name matches `-[Class sel]` or\n"
"// `+[Class sel]` (the labels Ghidra's Objective-C analyzer emits from the\n"
"// __objc_classlist / __objc_methlist metadata), groups them by class, and\n"
"// for each method emits an Objective-C-shaped `@implementation` block:\n"
"//\n"
"//     @implementation MyClass\n"
"//     - (id)doThing:(id)arg0 withFoo:(id)arg1 {\n"
"//         /* translated body */\n"
"//     }\n"
"//     @end\n"
"//\n"
"// Bodies are translated heuristically: objc_msgSend(recv, \"sel\", args...) is\n"
"// rewritten as `[recv sel:args]`, ARC retain/release/autorelease calls are\n"
"// dropped, `objc_storeStrong(&dst, src)` becomes `dst = src`, and\n"
"// `_OBJC_CLASS_$_Foo` is rewritten as `[Foo class]`. The output is not real,\n"
"// compilable Objective-C — it is an ObjC-shaped sketch derived from the\n"
"// decompile. Keep in sync with the kCDDecompileObjcScript string in\n"
"// Source/CDDecompiler.m.\n"
"\n"
"import ghidra.app.script.GhidraScript;\n"
"import ghidra.app.decompiler.DecompInterface;\n"
"import ghidra.app.decompiler.DecompileOptions;\n"
"import ghidra.app.decompiler.DecompileResults;\n"
"import ghidra.app.decompiler.DecompiledFunction;\n"
"import ghidra.program.model.listing.Function;\n"
"import ghidra.program.model.listing.FunctionIterator;\n"
"import ghidra.program.model.mem.MemoryBlock;\n"
"import ghidra.program.model.symbol.Symbol;\n"
"import ghidra.program.model.symbol.SymbolTable;\n"
"import java.io.PrintWriter;\n"
"import java.io.FileOutputStream;\n"
"import java.util.Arrays;\n"
"import java.util.LinkedHashMap;\n"
"import java.util.Map;\n"
"import java.util.regex.Matcher;\n"
"import java.util.regex.Pattern;\n"
"\n"
"public class CDDecompileObjc extends GhidraScript {\n"
"\n"
"    static class MethodId {\n"
"        boolean instance;\n"
"        String className;\n"
"        String selector;\n"
"        String[] parts;\n"
"        int argCount;\n"
"    }\n"
"\n"
"    private static MethodId parseObjcName(String name) {\n"
"        if (name == null) return null;\n"
"        if (name.startsWith(\"_\")) name = name.substring(1);\n"
"        if (name.length() < 4) return null;\n"
"        char k = name.charAt(0);\n"
"        if (k != '-' && k != '+') return null;\n"
"        if (name.charAt(1) != '[') return null;\n"
"        int rb = name.lastIndexOf(']');\n"
"        if (rb < 0) return null;\n"
"        String inside = name.substring(2, rb);\n"
"        int sp = inside.indexOf(' ');\n"
"        if (sp < 0) return null;\n"
"        MethodId m = new MethodId();\n"
"        m.instance = (k == '-');\n"
"        m.className = inside.substring(0, sp);\n"
"        m.selector = inside.substring(sp + 1);\n"
"        int colons = 0;\n"
"        for (int i = 0; i < m.selector.length(); i++) if (m.selector.charAt(i) == ':') colons++;\n"
"        m.argCount = colons;\n"
"        if (colons == 0) {\n"
"            m.parts = new String[]{ m.selector };\n"
"        } else {\n"
"            m.parts = m.selector.split(\":\", -1);\n"
"            if (m.parts.length > 0 && m.parts[m.parts.length - 1].isEmpty()) {\n"
"                m.parts = Arrays.copyOf(m.parts, m.parts.length - 1);\n"
"            }\n"
"        }\n"
"        return m;\n"
"    }\n"
"\n"
"    private static String objcType(String cType) {\n"
"        if (cType == null) return \"id\";\n"
"        String t = cType.trim();\n"
"        if (t.equals(\"void\")) return \"void\";\n"
"        if (t.equals(\"BOOL\") || t.equals(\"bool\")) return \"BOOL\";\n"
"        if (t.startsWith(\"char\") && t.contains(\"*\")) return \"char *\";\n"
"        if (t.equals(\"int\") || t.equals(\"long\") || t.equals(\"longlong\")) return \"NSInteger\";\n"
"        if (t.equals(\"uint\") || t.equals(\"ulong\") || t.equals(\"ulonglong\")) return \"NSUInteger\";\n"
"        if (t.equals(\"float\")) return \"float\";\n"
"        if (t.equals(\"double\")) return \"double\";\n"
"        if (t.contains(\"*\") || t.equals(\"undefined8\") || t.equals(\"ID\") || t.equals(\"Class\")) return \"id\";\n"
"        return t;\n"
"    }\n"
"\n"
"    private static String objcifyBody(String c) {\n"
"        if (c == null) return \"\";\n"
"        int firstBrace = c.indexOf('{');\n"
"        int lastBrace = c.lastIndexOf('}');\n"
"        if (firstBrace >= 0 && lastBrace > firstBrace) c = c.substring(firstBrace + 1, lastBrace);\n"
"        c = c.trim();\n"
"\n"
"        String[] drop = {\n"
"            \"objc_retain\",\"objc_release\",\"objc_autorelease\",\"objc_retainAutoreleasedReturnValue\",\n"
"            \"objc_autoreleaseReturnValue\",\"objc_retainAutorelease\",\"objc_retainBlock\"\n"
"        };\n"
"        for (String fn : drop) {\n"
"            c = c.replaceAll(\"(?m)^\\\\s*_?\" + Pattern.quote(fn) + \"\\\\s*\\\\([^;]*\\\\);\\\\s*$\\\\n?\", \"\");\n"
"        }\n"
"\n"
"        c = c.replaceAll(\"_?objc_storeStrong\\\\s*\\\\(\\\\s*&([^,\\\\s]+)\\\\s*,\\\\s*([^\\\\)]+)\\\\)\", \"$1 = $2\");\n"
"\n"
"        Pattern msg = Pattern.compile(\"_?objc_msgSend(?:Super2?)?\\\\s*\\\\(\\\\s*([^,\\\\)]+)\\\\s*,\\\\s*\\\"([^\\\"]+)\\\"((?:\\\\s*,\\\\s*[^,\\\\)]+)*)\\\\)\");\n"
"        Matcher mm = msg.matcher(c);\n"
"        StringBuffer sb = new StringBuffer();\n"
"        while (mm.find()) {\n"
"            String recv = mm.group(1).trim();\n"
"            String sel = mm.group(2);\n"
"            String rest = mm.group(3);\n"
"            String[] args;\n"
"            if (rest == null || rest.isEmpty()) {\n"
"                args = new String[0];\n"
"            } else {\n"
"                args = rest.replaceFirst(\"^\\\\s*,\\\\s*\", \"\").split(\"\\\\s*,\\\\s*\");\n"
"            }\n"
"            String[] parts;\n"
"            if (sel.contains(\":\")) {\n"
"                parts = sel.split(\":\", -1);\n"
"                if (parts.length > 0 && parts[parts.length - 1].isEmpty()) {\n"
"                    parts = Arrays.copyOf(parts, parts.length - 1);\n"
"                }\n"
"            } else {\n"
"                parts = new String[]{ sel };\n"
"            }\n"
"            StringBuilder call = new StringBuilder(\"[\").append(recv).append(' ');\n"
"            if (parts.length == 1 && !sel.contains(\":\")) {\n"
"                call.append(parts[0]);\n"
"            } else {\n"
"                for (int i = 0; i < parts.length; i++) {\n"
"                    if (i > 0) call.append(' ');\n"
"                    call.append(parts[i]).append(':');\n"
"                    if (i < args.length) call.append(args[i].trim()); else call.append(\"nil\");\n"
"                }\n"
"            }\n"
"            call.append(\"]\");\n"
"            mm.appendReplacement(sb, Matcher.quoteReplacement(call.toString()));\n"
"        }\n"
"        mm.appendTail(sb);\n"
"        c = sb.toString();\n"
"\n"
"        c = c.replaceAll(\"_?OBJC_CLASS_\\\\$_([A-Za-z_][A-Za-z0-9_]*)\", \"[$1 class]\");\n"
"        c = c.replaceAll(\"\\\\(undefined8?\\\\s*\\\\*+\\\\)\", \"\");\n"
"        c = c.replaceAll(\"(?m)^\\\\s+$\", \"\");\n"
"        c = c.replaceAll(\"\\\\n{3,}\", \"\\n\\n\");\n"
"        return c.trim();\n"
"    }\n"
"\n"
"    @Override\n"
"    protected void run() throws Exception {\n"
"        String[] args = getScriptArgs();\n"
"        if (args.length < 1) { println(\"CDDecompileObjc: missing output path argument\"); return; }\n"
"        String outPath = args[0];\n"
"\n"
"        DecompInterface di = new DecompInterface();\n"
"        DecompileOptions opts = new DecompileOptions();\n"
"        di.setOptions(opts);\n"
"        di.toggleCCode(true);\n"
"        di.toggleSyntaxTree(true);\n"
"        di.setSimplificationStyle(\"decompile\");\n"
"        if (!di.openProgram(currentProgram)) {\n"
"            println(\"CDDecompileObjc: openProgram failed: \" + di.getLastMessage()); return;\n"
"        }\n"
"\n"
"        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));\n"
"        pw.println(\"// Generated by class-dump --decompile-objc\");\n"
"        pw.println(\"// Program: \" + currentProgram.getName());\n"
"        pw.println(\"// Language: \" + currentProgram.getLanguageID());\n"
"        pw.println(\"// Bodies are heuristically translated from Ghidra pseudo-C; treat as an ObjC-shaped sketch.\");\n"
"        pw.println();\n"
"\n"
"        boolean isObjcBinary = false;\n"
"        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {\n"
"            String n = blk.getName();\n"
"            if (n != null && (n.startsWith(\"__objc_\") || n.equals(\"__objc\"))) { isObjcBinary = true; break; }\n"
"        }\n"
"        if (!isObjcBinary) {\n"
"            pw.println(\"// (no __objc_* sections; binary contains no Objective-C metadata)\");\n"
"            pw.close(); di.dispose();\n"
"            println(\"CDDecompileObjc: no Obj-C metadata in \" + currentProgram.getName());\n"
"            return;\n"
"        }\n"
"\n"
"        Map<String, StringBuilder> byClass = new LinkedHashMap<String, StringBuilder>();\n"
"        SymbolTable st = currentProgram.getSymbolTable();\n"
"        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);\n"
"        int total = 0, objc = 0, ok = 0;\n"
"        while (it.hasNext()) {\n"
"            if (monitor.isCancelled()) break;\n"
"            Function f = it.next();\n"
"            if (f.isThunk() || f.isExternal()) continue;\n"
"            total++;\n"
"            String name = f.getName();\n"
"            MethodId mid = parseObjcName(name);\n"
"            if (mid == null) {\n"
"                for (Symbol s : st.getSymbols(f.getEntryPoint())) {\n"
"                    MethodId m2 = parseObjcName(s.getName());\n"
"                    if (m2 != null) { mid = m2; break; }\n"
"                }\n"
"            }\n"
"            if (mid == null) continue;\n"
"            objc++;\n"
"\n"
"            String retType = \"id\";\n"
"            try {\n"
"                if (f.getReturnType() != null) retType = objcType(f.getReturnType().getName());\n"
"            } catch (Exception e) {}\n"
"\n"
"            String body = \"// (decompile failed)\";\n"
"            try {\n"
"                DecompileResults r = di.decompileFunction(f, 120, monitor);\n"
"                if (r != null && r.decompileCompleted()) {\n"
"                    DecompiledFunction df = r.getDecompiledFunction();\n"
"                    if (df != null) {\n"
"                        body = objcifyBody(df.getC());\n"
"                        ok++;\n"
"                    }\n"
"                }\n"
"            } catch (Exception e) {\n"
"                body = \"// !! decompile failed: \" + e.getMessage();\n"
"            }\n"
"\n"
"            StringBuilder sb = byClass.get(mid.className);\n"
"            if (sb == null) { sb = new StringBuilder(); byClass.put(mid.className, sb); }\n"
"            sb.append(\"// \").append(f.getEntryPoint()).append(\"  \").append(name).append(\"\\n\");\n"
"            sb.append(mid.instance ? \"- \" : \"+ \").append(\"(\").append(retType).append(\")\");\n"
"            if (mid.argCount == 0) {\n"
"                sb.append(mid.selector);\n"
"            } else {\n"
"                for (int i = 0; i < mid.parts.length; i++) {\n"
"                    if (i > 0) sb.append(' ');\n"
"                    sb.append(mid.parts[i]).append(\":(id)arg\").append(i);\n"
"                }\n"
"            }\n"
"            sb.append(\" {\\n\");\n"
"            for (String line : body.split(\"\\n\")) sb.append(\"    \").append(line).append(\"\\n\");\n"
"            sb.append(\"}\\n\\n\");\n"
"        }\n"
"\n"
"        for (Map.Entry<String, StringBuilder> e : byClass.entrySet()) {\n"
"            pw.println(\"@implementation \" + e.getKey());\n"
"            pw.println();\n"
"            pw.println(e.getValue().toString());\n"
"            pw.println(\"@end\");\n"
"            pw.println();\n"
"        }\n"
"\n"
"        pw.println(\"// \" + ok + \"/\" + total + \" functions decompiled; \" + objc + \" were Obj-C IMPs.\");\n"
"        pw.close();\n"
"        di.dispose();\n"
"        println(\"CDDecompileObjc: wrote \" + ok + \"/\" + total + \" functions (\" + objc + \" Obj-C) to \" + outPath);\n"
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

// Shared driver: spawns analyzeHeadless with the supplied embedded
// script, captures stderr, cleans up. Used by both the C and Swift
// entry points.
+ (BOOL)_runHeadlessWithInput:(NSString *)inputPath
                   outputPath:(NSString *)outputPath
                   scriptName:(NSString *)scriptName
                 scriptSource:(NSString *)scriptSource
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

    NSString *scriptPath = [scriptDir stringByAppendingPathComponent:scriptName];
    NSError *writeErr = nil;
    if (![scriptSource writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:&writeErr]) {
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
        @"-postScript", scriptName, outputPath,
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

    if (rc != 0 || ![fm fileExistsAtPath:outputPath]) {
        NSString *stderrStr = [[NSString alloc] initWithData:stderrData encoding:NSUTF8StringEncoding] ?: @"";
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

+ (BOOL)decompileMachOAtPath:(NSString *)inputPath
                      toPath:(NSString *)outputCPath
                       error:(NSError *__autoreleasing *)error
{
    return [self _runHeadlessWithInput:inputPath
                            outputPath:outputCPath
                            scriptName:@"CDDecompile.java"
                          scriptSource:kCDDecompileScript
                                 error:error];
}

+ (BOOL)decompileSwiftMachOAtPath:(NSString *)inputPath
                           toPath:(NSString *)outputSwiftPath
                            error:(NSError *__autoreleasing *)error
{
    BOOL ok = [self _runHeadlessWithInput:inputPath
                               outputPath:outputSwiftPath
                               scriptName:@"CDDecompileSwift.java"
                             scriptSource:kCDDecompileSwiftScript
                                    error:error];
    if (!ok) return NO;

    // Drop the output file if the binary had no Swift functions: a
    // header-only .swift file is just noise. The new Swift script emits
    // either a `class ` block per type or a `// MARK: - Free functions`
    // section; absence of both means the binary had no Swift code.
    NSString *contents = [NSString stringWithContentsOfFile:outputSwiftPath
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
    if (contents
        && [contents rangeOfString:@"\nclass "].location == NSNotFound
        && [contents rangeOfString:@"// MARK: - Free functions"].location == NSNotFound) {
        [[NSFileManager defaultManager] removeItemAtPath:outputSwiftPath error:NULL];
    }
    return YES;
}

+ (BOOL)decompileObjcMachOAtPath:(NSString *)inputPath
                          toPath:(NSString *)outputObjcPath
                           error:(NSError *__autoreleasing *)error
{
    BOOL ok = [self _runHeadlessWithInput:inputPath
                               outputPath:outputObjcPath
                               scriptName:@"CDDecompileObjc.java"
                             scriptSource:kCDDecompileObjcScript
                                    error:error];
    if (!ok) return NO;

    // Drop the output file if the binary had no Obj-C method IMPs: a
    // header-only .m file is just noise. The Obj-C script emits an
    // `@implementation ` line per class; absence means nothing matched.
    NSString *contents = [NSString stringWithContentsOfFile:outputObjcPath
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
    if (contents && [contents rangeOfString:@"\n@implementation "].location == NSNotFound) {
        [[NSFileManager defaultManager] removeItemAtPath:outputObjcPath error:NULL];
    }
    return YES;
}

+ (BOOL)decompileCppMachOAtPath:(NSString *)inputPath
                         toPath:(NSString *)outputCppPath
                          error:(NSError *__autoreleasing *)error
{
    BOOL ok = [self _runHeadlessWithInput:inputPath
                               outputPath:outputCppPath
                               scriptName:@"CDDecompileCpp.java"
                             scriptSource:kCDDecompileCppScript
                                    error:error];
    if (!ok) return NO;

    // Same trick as the Swift path: a header-only .cpp file (no C++
    // mangled symbols in the binary) is noise, so delete it.
    NSString *contents = [NSString stringWithContentsOfFile:outputCppPath
                                                   encoding:NSUTF8StringEncoding
                                                      error:NULL];
    if (contents && [contents rangeOfString:@"\n// ---- "].location == NSNotFound) {
        [[NSFileManager defaultManager] removeItemAtPath:outputCppPath error:NULL];
    }
    return YES;
}

@end
