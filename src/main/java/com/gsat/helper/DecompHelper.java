package com.gsat.helper;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;

import java.util.*;

import com.gsat.utils.ColoredPrint;

public class DecompHelper {
    private Map<Long,HighFunction> cachedHigh;
    private FlatProgramAPI flatApi;
    protected DecompInterface decomplib;

    public DecompHelper(FlatProgramAPI flatApi) throws Exception {
        this.flatApi = flatApi;  
        this.cachedHigh = new HashMap<>();
        this.decomplib = setUpDecompiler(); 
        if (this.decomplib == null) {
            throw new Exception("Init DecompInterface Failed. ");
        }
    }

    private DecompInterface setUpDecompiler() {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();

        decompInterface.setOptions(options);

        decompInterface.toggleCCode(false);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        boolean succ = decompInterface.openProgram(flatApi.getCurrentProgram());
        if (! succ) {
            ColoredPrint.error("DecompHelper: Open program failed. %s. ", decomplib.getLastMessage());
            return null;
        }

        return decompInterface;
    }
    
    public HighFunction decompileFunction(Function f) {
        return decompileFunction(f, false);
    }

    public HighFunction decompileFunction(Function f, boolean disableCache) {
        HighFunction hfunction = null;
        DecompileResults dRes = null;

        Long offset = f.getEntryPoint().getOffset();
        if (!disableCache && cachedHigh.containsKey(offset)) {
            HighFunction tmp = cachedHigh.get(offset);
            if (tmp != null) {
                return tmp;
            }
        }
        try {
            dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), this.flatApi.getMonitor());
            hfunction = dRes.getHighFunction();
        }
        catch (Exception exc) {
            ColoredPrint.error("Decompile Function at 0x%x Failed. ", offset);
            exc.printStackTrace();
        }
        if (hfunction != null) {
            cachedHigh.put(offset, hfunction);
        }
        return hfunction;
    }


}
