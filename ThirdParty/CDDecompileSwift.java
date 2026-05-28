// CDDecompileSwift.java
//
// Ghidra headless post-script invoked by class-dump's --decompile-swift flag.
// Walks every function with a Swift-mangled symbol ($s / _$s / $S / _$S),
// demangles via Ghidra's DemanglerUtil to get the Swift signature, decompiles
// the body, then post-processes the pseudo-C into Swift-shaped syntax: groups
// functions by their owning Swift type and emits
//
//     class Module.MyType {
//         func foo(x: Int) -> Bool { ... }
//         init(...) { ... }
//     }
//
// Bodies are translated heuristically: swift_retain/release/access calls are
// dropped, C casts are removed, `a->b` is rewritten as `a.b`. The output is
// not real, compilable Swift — it is a Swift-shaped sketch derived from the
// decompile. Keep in sync with the kCDDecompileSwiftScript string in
// Source/CDDecompiler.m.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CDDecompileSwift extends GhidraScript {

    static class Sig {
        String container = "";
        String funcName = "";
        String paramList = "";
        String returnType = "";
        boolean isStatic = false;
        boolean isInit = false;
        boolean isDeinit = false;
        boolean isProperty = false;
        String propertyKind = "";
    }

    private static Sig parseSwiftSig(String sig) {
        if (sig == null) return null;
        Sig s = new Sig();
        sig = sig.trim();
        if (sig.startsWith("static ")) { s.isStatic = true; sig = sig.substring(7).trim(); }
        int paren = sig.indexOf('(');
        if (paren < 0) {
            int colon = sig.indexOf(':');
            String head = colon >= 0 ? sig.substring(0, colon).trim() : sig.trim();
            String tail = colon >= 0 ? sig.substring(colon + 1).trim() : "";
            int lastDot = head.lastIndexOf('.');
            if (lastDot < 0) { s.funcName = head; return s; }
            String afterDot = head.substring(lastDot + 1);
            if (afterDot.equals("getter") || afterDot.equals("setter") || afterDot.equals("modify") || afterDot.equals("read")) {
                s.isProperty = true; s.propertyKind = afterDot;
                int prevDot = head.lastIndexOf('.', lastDot - 1);
                if (prevDot >= 0) {
                    s.container = head.substring(0, prevDot);
                    s.funcName = head.substring(prevDot + 1, lastDot);
                } else {
                    s.funcName = head.substring(0, lastDot);
                }
                s.returnType = tail.replace("Swift.", "");
                return s;
            }
            s.container = lastDot >= 0 ? head.substring(0, lastDot) : "";
            s.funcName = head.substring(lastDot + 1);
            return s;
        }
        String head = sig.substring(0, paren);
        int lastDot = head.lastIndexOf('.');
        if (lastDot < 0) { s.funcName = head.trim(); }
        else { s.container = head.substring(0, lastDot); s.funcName = head.substring(lastDot + 1).trim(); }
        int depth = 0, close = -1;
        for (int i = paren; i < sig.length(); i++) {
            char c = sig.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') { depth--; if (depth == 0) { close = i; break; } }
        }
        if (close < 0) close = sig.length() - 1;
        s.paramList = sig.substring(paren + 1, close).trim().replace("Swift.", "");
        String rest = (close + 1 < sig.length()) ? sig.substring(close + 1).trim() : "";
        if (rest.startsWith("->")) s.returnType = rest.substring(2).trim().replace("Swift.", "");
        s.isInit = s.funcName.equals("init") || s.funcName.startsWith("init(");
        s.isDeinit = s.funcName.equals("deinit") || s.funcName.startsWith("deinit");
        return s;
    }

    private static String stripParenSig(String funcName) {
        int p = funcName.indexOf('(');
        if (p < 0) return funcName;
        return funcName.substring(0, p);
    }

    private static String swiftifyBody(String c) {
        if (c == null) return "";
        int firstBrace = c.indexOf('{');
        int lastBrace = c.lastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace) c = c.substring(firstBrace + 1, lastBrace);
        c = c.trim();
        String[] dropCalls = {
            "swift_retain","swift_release","swift_bridgeObjectRetain","swift_bridgeObjectRelease",
            "swift_unknownObjectRetain","swift_unknownObjectRelease",
            "swift_beginAccess","swift_endAccess",
            "swift_release_n","swift_retain_n"
        };
        for (String fn : dropCalls) {
            c = c.replaceAll("(?m)^\\s*_?" + Pattern.quote(fn) + "\\s*\\([^;]*\\);\\s*$\\n?", "");
        }
        c = c.replaceAll("_?swift_allocObject\\s*\\(([^)]*)\\)", "alloc()");
        c = c.replaceAll("\\(undefined8?\\s*\\*+\\)", "");
        c = c.replaceAll("\\(longlong\\)", "Int(");
        c = c.replaceAll("\\(ulonglong\\)", "UInt(");
        c = c.replaceAll("\\(uint\\)", "UInt(");
        c = c.replaceAll("\\(int\\)", "Int(");
        c = c.replaceAll("([A-Za-z_][A-Za-z0-9_]*)->", "$1.");
        c = c.replaceAll("(?m)^\\s+$", "");
        c = c.replaceAll("\\n{3,}", "\n\n");
        return c.trim();
    }

    private static String emitFunc(Sig s, String body, String mangled, String addr) {
        StringBuilder sb = new StringBuilder();
        sb.append("    // ").append(addr).append("  ").append(mangled).append("\n");
        if (s.isProperty) {
            String ret = s.returnType.isEmpty() ? "Any" : s.returnType;
            sb.append("    var ").append(s.funcName).append(": ").append(ret).append(" { ");
            sb.append(s.propertyKind).append(" {\n");
            for (String line : body.split("\n")) sb.append("        ").append(line).append("\n");
            sb.append("    } }\n");
            return sb.toString();
        }
        sb.append("    ");
        if (s.isStatic) sb.append("static ");
        if (s.isInit) {
            sb.append("init(").append(s.paramList).append(") {\n");
        } else if (s.isDeinit) {
            sb.append("deinit {\n");
        } else {
            sb.append("func ").append(stripParenSig(s.funcName));
            sb.append("(").append(s.paramList).append(")");
            if (!s.returnType.isEmpty() && !s.returnType.equals("()")) {
                sb.append(" -> ").append(s.returnType);
            }
            sb.append(" {\n");
        }
        for (String line : body.split("\n")) sb.append("        ").append(line).append("\n");
        sb.append("    }\n");
        return sb.toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("CDDecompileSwift: missing output path argument"); return; }
        String outPath = args[0];

        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        di.setSimplificationStyle("decompile");
        if (!di.openProgram(currentProgram)) {
            println("CDDecompileSwift: openProgram failed: " + di.getLastMessage()); return;
        }

        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));
        pw.println("// Generated by class-dump --decompile-swift");
        pw.println("// Program: " + currentProgram.getName());
        pw.println("// Language: " + currentProgram.getLanguageID());
        pw.println("// Bodies are heuristically translated from Ghidra pseudo-C; treat as a Swift-shaped sketch.");
        pw.println();

        boolean isSwiftBinary = false;
        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
            String n = blk.getName();
            if (n != null && n.startsWith("__swift5")) { isSwiftBinary = true; break; }
        }
        if (!isSwiftBinary) {
            pw.println("// (no __swift5_* sections; binary contains no Swift metadata)");
            pw.close(); di.dispose();
            println("CDDecompileSwift: no Swift metadata in " + currentProgram.getName());
            return;
        }

        Map<String, StringBuilder> typeBodies = new LinkedHashMap<String, StringBuilder>();
        StringBuilder topLevel = new StringBuilder();

        SymbolTable st = currentProgram.getSymbolTable();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0, swift = 0, ok = 0;
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            total++;
            String mangled = null;
            for (Symbol sym : st.getSymbols(f.getEntryPoint())) {
                String n = sym.getName();
                if (n == null) continue;
                if (n.startsWith("$s") || n.startsWith("_$s")
                    || n.startsWith("$S") || n.startsWith("_$S")) { mangled = n; break; }
            }
            if (mangled == null) {
                String n = f.getName();
                if (n != null && (n.startsWith("$s") || n.startsWith("_$s")
                                  || n.startsWith("$S") || n.startsWith("_$S"))) mangled = n;
            }
            if (mangled == null) continue;
            swift++;

            String sigText = mangled;
            try {
                List<DemangledObject> ds = DemanglerUtil.demangle(currentProgram, mangled, f.getEntryPoint());
                if (ds != null && !ds.isEmpty()) {
                    DemangledObject d = ds.get(0);
                    if (d != null) {
                        String s2 = d.getSignature(false);
                        if (s2 != null && s2.length() > 0) sigText = s2;
                    }
                }
            } catch (Exception e) { /* keep mangled */ }

            Sig s = parseSwiftSig(sigText);
            if (s == null) { s = new Sig(); s.funcName = sigText; }

            String body = "// (decompile failed)";
            try {
                DecompileResults r = di.decompileFunction(f, 120, monitor);
                if (r != null && r.decompileCompleted()) {
                    DecompiledFunction df = r.getDecompiledFunction();
                    if (df != null) {
                        body = swiftifyBody(df.getC());
                        ok++;
                    }
                }
            } catch (Exception e) {
                body = "// !! decompile failed: " + e.getMessage();
            }

            String emit = emitFunc(s, body, mangled, f.getEntryPoint().toString());
            if (s.container == null || s.container.isEmpty()) {
                topLevel.append(emit.replaceAll("(?m)^    ", "")).append("\n");
            } else {
                StringBuilder b = typeBodies.get(s.container);
                if (b == null) { b = new StringBuilder(); typeBodies.put(s.container, b); }
                b.append(emit).append("\n");
            }
        }

        for (Map.Entry<String, StringBuilder> e : typeBodies.entrySet()) {
            String containerPath = e.getKey();
            int dot = containerPath.lastIndexOf('.');
            String mod = (dot >= 0) ? containerPath.substring(0, dot) : "";
            String typeName = (dot >= 0) ? containerPath.substring(dot + 1) : containerPath;
            pw.println("// " + containerPath);
            if (!mod.isEmpty()) pw.println("// import " + mod);
            pw.println("class " + typeName + " {");
            pw.println(e.getValue().toString());
            pw.println("}");
            pw.println();
        }

        if (topLevel.length() > 0) {
            pw.println("// MARK: - Free functions");
            pw.println(topLevel.toString());
        }

        pw.println("// " + ok + "/" + total + " functions decompiled; " + swift + " were Swift.");
        pw.close();
        di.dispose();
        println("CDDecompileSwift: wrote " + ok + "/" + total + " functions (" + swift + " Swift) to " + outPath);
    }
}
