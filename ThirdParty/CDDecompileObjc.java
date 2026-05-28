// CDDecompileObjc.java
//
// Ghidra headless post-script invoked by class-dump's --decompile-objc flag.
// Filters functions whose Ghidra-assigned name matches `-[Class sel]` or
// `+[Class sel]` (the labels Ghidra's Objective-C analyzer emits from the
// __objc_classlist / __objc_methlist metadata), groups them by class, and
// for each method emits an Objective-C-shaped `@implementation` block:
//
//     @implementation MyClass
//     - (id)doThing:(id)arg0 withFoo:(id)arg1 {
//         /* translated body */
//     }
//     @end
//
// Bodies are translated heuristically: objc_msgSend(recv, "sel", args...) is
// rewritten as `[recv sel:args]`, ARC retain/release/autorelease calls are
// dropped, `objc_storeStrong(&dst, src)` becomes `dst = src`, and
// `_OBJC_CLASS_$_Foo` is rewritten as `[Foo class]`. The output is not real,
// compilable Objective-C — it is an ObjC-shaped sketch derived from the
// decompile. Keep in sync with the kCDDecompileObjcScript string in
// Source/CDDecompiler.m.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CDDecompileObjc extends GhidraScript {

    static class MethodId {
        boolean instance;
        String className;
        String selector;
        String[] parts;
        int argCount;
    }

    private static MethodId parseObjcName(String name) {
        if (name == null) return null;
        if (name.startsWith("_")) name = name.substring(1);
        if (name.length() < 4) return null;
        char k = name.charAt(0);
        if (k != '-' && k != '+') return null;
        if (name.charAt(1) != '[') return null;
        int rb = name.lastIndexOf(']');
        if (rb < 0) return null;
        String inside = name.substring(2, rb);
        int sp = inside.indexOf(' ');
        if (sp < 0) return null;
        MethodId m = new MethodId();
        m.instance = (k == '-');
        m.className = inside.substring(0, sp);
        m.selector = inside.substring(sp + 1);
        int colons = 0;
        for (int i = 0; i < m.selector.length(); i++) if (m.selector.charAt(i) == ':') colons++;
        m.argCount = colons;
        if (colons == 0) {
            m.parts = new String[]{ m.selector };
        } else {
            m.parts = m.selector.split(":", -1);
            if (m.parts.length > 0 && m.parts[m.parts.length - 1].isEmpty()) {
                m.parts = Arrays.copyOf(m.parts, m.parts.length - 1);
            }
        }
        return m;
    }

    private static String objcType(String cType) {
        if (cType == null) return "id";
        String t = cType.trim();
        if (t.equals("void")) return "void";
        if (t.equals("BOOL") || t.equals("bool")) return "BOOL";
        if (t.startsWith("char") && t.contains("*")) return "char *";
        if (t.equals("int") || t.equals("long") || t.equals("longlong")) return "NSInteger";
        if (t.equals("uint") || t.equals("ulong") || t.equals("ulonglong")) return "NSUInteger";
        if (t.equals("float")) return "float";
        if (t.equals("double")) return "double";
        if (t.contains("*") || t.equals("undefined8") || t.equals("ID") || t.equals("Class")) return "id";
        return t;
    }

    private static String objcifyBody(String c) {
        if (c == null) return "";
        int firstBrace = c.indexOf('{');
        int lastBrace = c.lastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace) c = c.substring(firstBrace + 1, lastBrace);
        c = c.trim();

        String[] drop = {
            "objc_retain","objc_release","objc_autorelease","objc_retainAutoreleasedReturnValue",
            "objc_autoreleaseReturnValue","objc_retainAutorelease","objc_retainBlock"
        };
        for (String fn : drop) {
            c = c.replaceAll("(?m)^\\s*_?" + Pattern.quote(fn) + "\\s*\\([^;]*\\);\\s*$\\n?", "");
        }

        c = c.replaceAll("_?objc_storeStrong\\s*\\(\\s*&([^,\\s]+)\\s*,\\s*([^\\)]+)\\)", "$1 = $2");

        Pattern msg = Pattern.compile("_?objc_msgSend(?:Super2?)?\\s*\\(\\s*([^,\\)]+)\\s*,\\s*\"([^\"]+)\"((?:\\s*,\\s*[^,\\)]+)*)\\)");
        Matcher mm = msg.matcher(c);
        StringBuffer sb = new StringBuffer();
        while (mm.find()) {
            String recv = mm.group(1).trim();
            String sel = mm.group(2);
            String rest = mm.group(3);
            String[] args;
            if (rest == null || rest.isEmpty()) {
                args = new String[0];
            } else {
                args = rest.replaceFirst("^\\s*,\\s*", "").split("\\s*,\\s*");
            }
            String[] parts;
            if (sel.contains(":")) {
                parts = sel.split(":", -1);
                if (parts.length > 0 && parts[parts.length - 1].isEmpty()) {
                    parts = Arrays.copyOf(parts, parts.length - 1);
                }
            } else {
                parts = new String[]{ sel };
            }
            StringBuilder call = new StringBuilder("[").append(recv).append(' ');
            if (parts.length == 1 && !sel.contains(":")) {
                call.append(parts[0]);
            } else {
                for (int i = 0; i < parts.length; i++) {
                    if (i > 0) call.append(' ');
                    call.append(parts[i]).append(':');
                    if (i < args.length) call.append(args[i].trim()); else call.append("nil");
                }
            }
            call.append("]");
            mm.appendReplacement(sb, Matcher.quoteReplacement(call.toString()));
        }
        mm.appendTail(sb);
        c = sb.toString();

        c = c.replaceAll("_?OBJC_CLASS_\\$_([A-Za-z_][A-Za-z0-9_]*)", "[$1 class]");
        c = c.replaceAll("\\(undefined8?\\s*\\*+\\)", "");
        c = c.replaceAll("(?m)^\\s+$", "");
        c = c.replaceAll("\\n{3,}", "\n\n");
        return c.trim();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("CDDecompileObjc: missing output path argument"); return; }
        String outPath = args[0];

        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        di.setSimplificationStyle("decompile");
        if (!di.openProgram(currentProgram)) {
            println("CDDecompileObjc: openProgram failed: " + di.getLastMessage()); return;
        }

        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));
        pw.println("// Generated by class-dump --decompile-objc");
        pw.println("// Program: " + currentProgram.getName());
        pw.println("// Language: " + currentProgram.getLanguageID());
        pw.println("// Bodies are heuristically translated from Ghidra pseudo-C; treat as an ObjC-shaped sketch.");
        pw.println();

        boolean isObjcBinary = false;
        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
            String n = blk.getName();
            if (n != null && (n.startsWith("__objc_") || n.equals("__objc"))) { isObjcBinary = true; break; }
        }
        if (!isObjcBinary) {
            pw.println("// (no __objc_* sections; binary contains no Objective-C metadata)");
            pw.close(); di.dispose();
            println("CDDecompileObjc: no Obj-C metadata in " + currentProgram.getName());
            return;
        }

        Map<String, StringBuilder> byClass = new LinkedHashMap<String, StringBuilder>();
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0, objc = 0, ok = 0;
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            total++;
            String name = f.getName();
            MethodId mid = parseObjcName(name);
            if (mid == null) {
                for (Symbol s : st.getSymbols(f.getEntryPoint())) {
                    MethodId m2 = parseObjcName(s.getName());
                    if (m2 != null) { mid = m2; break; }
                }
            }
            if (mid == null) continue;
            objc++;

            String retType = "id";
            try {
                if (f.getReturnType() != null) retType = objcType(f.getReturnType().getName());
            } catch (Exception e) {}

            String body = "// (decompile failed)";
            try {
                DecompileResults r = di.decompileFunction(f, 120, monitor);
                if (r != null && r.decompileCompleted()) {
                    DecompiledFunction df = r.getDecompiledFunction();
                    if (df != null) {
                        body = objcifyBody(df.getC());
                        ok++;
                    }
                }
            } catch (Exception e) {
                body = "// !! decompile failed: " + e.getMessage();
            }

            StringBuilder sb = byClass.get(mid.className);
            if (sb == null) { sb = new StringBuilder(); byClass.put(mid.className, sb); }
            sb.append("// ").append(f.getEntryPoint()).append("  ").append(name).append("\n");
            sb.append(mid.instance ? "- " : "+ ").append("(").append(retType).append(")");
            if (mid.argCount == 0) {
                sb.append(mid.selector);
            } else {
                for (int i = 0; i < mid.parts.length; i++) {
                    if (i > 0) sb.append(' ');
                    sb.append(mid.parts[i]).append(":(id)arg").append(i);
                }
            }
            sb.append(" {\n");
            for (String line : body.split("\n")) sb.append("    ").append(line).append("\n");
            sb.append("}\n\n");
        }

        for (Map.Entry<String, StringBuilder> e : byClass.entrySet()) {
            pw.println("@implementation " + e.getKey());
            pw.println();
            pw.println(e.getValue().toString());
            pw.println("@end");
            pw.println();
        }

        pw.println("// " + ok + "/" + total + " functions decompiled; " + objc + " were Obj-C IMPs.");
        pw.close();
        di.dispose();
        println("CDDecompileObjc: wrote " + ok + "/" + total + " functions (" + objc + " Obj-C) to " + outPath);
    }
}
