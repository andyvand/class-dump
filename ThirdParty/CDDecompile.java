// CDDecompile.java
//
// Ghidra headless post-script invoked by class-dump's --decompile flag.
// Iterates every function in `currentProgram`, runs Ghidra's DecompInterface,
// and writes one .c file containing all decompiled functions to the path
// passed as the first script argument.
//
// Invoked by CDDecompiler.m via:
//   $GHIDRA_HOME/support/analyzeHeadless <projDir> <projName>
//       -import <binary>
//       -scriptPath <thisDir>
//       -postScript CDDecompile.java <outputCPath>
//       -deleteProject -overwrite

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;
import java.io.FileOutputStream;

public class CDDecompile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("CDDecompile: missing output path argument");
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
            println("CDDecompile: openProgram failed: " + di.getLastMessage());
            return;
        }

        PrintWriter pw = new PrintWriter(new FileOutputStream(outPath));
        pw.println("// Decompiled by class-dump --decompile (Ghidra headless).");
        pw.println("// Program: " + currentProgram.getName());
        pw.println("// Language: " + currentProgram.getLanguageID());
        pw.println();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0, ok = 0;
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            total++;
            try {
                DecompileResults r = di.decompileFunction(f, 120, monitor);
                if (r != null && r.decompileCompleted()) {
                    DecompiledFunction df = r.getDecompiledFunction();
                    if (df != null) {
                        String retType = (f.getReturnType() != null) ? f.getReturnType().getName() : "void";
                        pw.println("// ---- " + retType + " " + f.getName() + " @ " + f.getEntryPoint() + " ----");
                        pw.println(df.getC());
                        pw.println();
                        ok++;
                    }
                }
            } catch (Exception e) {
                pw.println("// !! decompile of " + f.getName() + " failed: " + e.getMessage());
            }
        }
        pw.println("// " + ok + "/" + total + " functions decompiled.");
        pw.close();
        di.dispose();
        println("CDDecompile: wrote " + ok + "/" + total + " functions to " + outPath);
    }
}
