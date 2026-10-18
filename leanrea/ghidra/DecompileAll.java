// Usage: analyzeHeadless <projdir> p -import <bin> -loader-libraryLoadDepth 0 -scriptPath <this dir> -postScript DecompileAll.java <out.c> -deleteProject
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
        int n = 0;
        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                if (f.isThunk()) continue;
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                w.println("// " + f.getName() + " @ " + f.getEntryPoint());
                w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed: " + r.getErrorMessage());
                n++;
            }
        } finally {
            ifc.dispose();
        }
        println("decompiled " + n + " functions to " + out.getAbsolutePath());
    }
}
