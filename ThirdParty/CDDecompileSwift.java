// CDDecompileSwift.java
//
// Ghidra headless post-script invoked by class-dump's --decompile-swift flag.
// Iterates Swift-mangled functions (names prefixed with $s / _$s / $S / _$S),
// demangles them via Ghidra's DemanglerUtil, runs DecompInterface, and writes
// the pseudo-C output (with demangled Swift symbols) to the path passed as
// the first script argument.
//
// NOTE: Ghidra emits pseudo-C, not real Swift source. The .swift extension
// is for downstream tooling convenience; the contents are C-shaped pseudo-
// code annotated with the original Swift signatures.
//
// Invoked by CDDecompiler.m via:
//   $GHIDRA_HOME/support/analyzeHeadless <projDir> <projName>
//       -import <binary>
//       -scriptPath <thisDir>
//       -postScript CDDecompileSwift.java <outputSwiftPath>
//       -deleteProject -overwrite

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
import java.util.List;

public class CDDecompileSwift extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("CDDecompileSwift: missing output path argument");
            return;
        }
        String outPath = args[0];

        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        di.setSimplificationStyle("decompile");
        if (!di.openProgram(currentProgram)) {
            println("CDDecompileSwift: openProgram failed: " + di.getLastMessage());
            return;
        }

        // Always create the output file so the class-dump driver doesn't
        // mistake "no Swift content" for "Ghidra failed". The driver
        // post-processes and deletes files that contain no "// ---- "
        // function blocks.
        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));
        pw.println("// Decompiled by class-dump --decompile-swift (Ghidra headless + Swift demangler).");
        pw.println("// Program: " + currentProgram.getName());
        pw.println("// Language: " + currentProgram.getLanguageID());
        pw.println("// NOTE: Ghidra emits pseudo-C; this is not real Swift source.");
        pw.println("//       Function signatures shown are demangled Swift names where available.");
        pw.println();

        // Detect Swift binaries by their well-known section names. If
        // there's no Swift metadata present, the file we just wrote will
        // be deleted by the driver because it has no "// ---- " blocks.
        boolean isSwiftBinary = false;
        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
            String n = blk.getName();
            if (n != null && n.startsWith("__swift5")) { isSwiftBinary = true; break; }
        }
        if (!isSwiftBinary) {
            pw.println("// (no __swift5_* sections; binary contains no Swift metadata)");
            pw.close();
            di.dispose();
            println("CDDecompileSwift: no Swift metadata in " + currentProgram.getName());
            return;
        }

        SymbolTable st = currentProgram.getSymbolTable();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0, swift = 0, ok = 0;
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            total++;

            // Find the function's mangled Swift symbol by scanning all
            // symbols at its entry point: Ghidra's auto-analysis demangles
            // and renames the primary symbol, but typically keeps the
            // original mangled name as a secondary symbol.
            String mangled = null;
            for (Symbol s : st.getSymbols(f.getEntryPoint())) {
                String n = s.getName();
                if (n == null) continue;
                if (n.startsWith("$s") || n.startsWith("_$s")
                    || n.startsWith("$S") || n.startsWith("_$S")) {
                    mangled = n;
                    break;
                }
            }
            // Fall back: if the function's own name is still mangled
            // (analyzer didn't run, or this is a binary without those
            // symbols preserved), accept that too.
            if (mangled == null) {
                String n = f.getName();
                if (n != null && (n.startsWith("$s") || n.startsWith("_$s")
                                  || n.startsWith("$S") || n.startsWith("_$S"))) {
                    mangled = n;
                }
            }

            String displayName;
            boolean isSwiftFn;
            if (mangled != null) {
                isSwiftFn = true;
                swift++;
                displayName = mangled;
                try {
                    List<DemangledObject> ds = DemanglerUtil.demangle(currentProgram, mangled, f.getEntryPoint());
                    if (ds != null && !ds.isEmpty()) {
                        DemangledObject d = ds.get(0);
                        if (d != null) {
                            String sig = d.getSignature(false);
                            if (sig != null && sig.length() > 0) displayName = sig;
                        }
                    }
                } catch (Exception e) { /* keep mangled */ }
            } else {
                // Non-Swift function inside a Swift binary (e.g. C glue,
                // ObjC bridges). Include it but mark it.
                isSwiftFn = false;
                displayName = f.getName();
            }

            try {
                DecompileResults r = di.decompileFunction(f, 120, monitor);
                if (r != null && r.decompileCompleted()) {
                    DecompiledFunction df = r.getDecompiledFunction();
                    if (df != null) {
                        pw.println("// ---- " + displayName + " ----");
                        pw.println("// address: " + f.getEntryPoint());
                        if (isSwiftFn) pw.println("// mangled: " + mangled);
                        else           pw.println("// (non-Swift function in a Swift binary)");
                        pw.println(df.getC());
                        pw.println();
                        ok++;
                    }
                }
            } catch (Exception e) {
                pw.println("// !! decompile of " + displayName + " failed: " + e.getMessage());
            }
        }
        pw.println("// " + ok + "/" + total + " functions decompiled; " + swift + " were Swift-mangled.");
        pw.close();
        di.dispose();
        println("CDDecompileSwift: wrote " + ok + "/" + total + " functions (" + swift + " Swift) to " + outPath);
    }
}
