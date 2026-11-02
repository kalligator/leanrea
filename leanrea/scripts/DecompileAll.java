// DecompileAll.java - Headless Ghidra script to decompile all non-thunk functions into C pseudocode.
// Usage: analyzeHeadless <projdir> proj -import <bin> -loader-libraryLoadDepth 0 -scriptPath <path-to-scripts> -postScript DecompileAll.java <out.c> -deleteProject

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args.length > 0 ? args[0] : currentProgram.getName() + ".c");
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        int count = 0;
        try (PrintWriter writer = new PrintWriter(new FileWriter(out))) {
            writer.println("// Decompiled with Ghidra headless: " + currentProgram.getName());
            writer.println("// Architecture: " + currentProgram.getLanguage().getLanguageDescription().getDescription());
            writer.println();
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (f.isThunk()) {
                    continue;
                }
                DecompileResults results = ifc.decompileFunction(f, 60, monitor);
                writer.println("// ============================================================================");
                writer.println("// Function: " + f.getName() + " @ " + f.getEntryPoint());
                writer.println("// ============================================================================");
                if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                    writer.println(results.getDecompiledFunction().getC());
                } else {
                    writer.println("// Decompilation failed: " + results.getErrorMessage());
                }
                writer.println();
                count++;
            }
        } finally {
            ifc.dispose();
        }
        println("Successfully decompiled " + count + " functions to " + out.getAbsolutePath());
    }
}
