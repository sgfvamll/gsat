package com.gsat.taint;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import com.gsat.helper.DecompHelper;
import com.gsat.taint.TaintSink.TaintSinkType;
import com.gsat.utils.ColoredPrint;

import generic.stl.Pair;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.RefType;

public class TaintSinkIdentifier {
    private Program program;
    private DecompHelper decompHelper;

    /// https://gitlab.com/libtiff/libtiff/-/commit/227500897dfb07fb7d27f7aa570050e62617e3be

    static private List<Pair<String, Integer[]>> defaultSinkSymbols = Arrays.asList(
            new Pair<String, Integer[]>("read", new Integer[] { 2 }),
            new Pair<String, Integer[]>("assert", new Integer[] { 0 }),
            new Pair<String, Integer[]>("alloc", new Integer[] { 0, 1 }),
            new Pair<String, Integer[]>("malloc", new Integer[] { 0 }),
            new Pair<String, Integer[]>("realloc", new Integer[] { 1 }),
            new Pair<String, Integer[]>("calloc", new Integer[] { 0, 1 }),
            new Pair<String, Integer[]>("fseek", new Integer[] { 1 }),
            new Pair<String, Integer[]>("memset", new Integer[] { 0 }),
            new Pair<String, Integer[]>("memcpy", new Integer[] { 0, 1, 2 }),
            new Pair<String, Integer[]>("memmove", new Integer[] { 0, 1, 2 }),
            new Pair<String, Integer[]>("_TIFFrealloc", new Integer[] { 1 }),
            new Pair<String, Integer[]>("_TIFFReadEncodedStripAndAllocBuffer", new Integer[] { 3 }),
            new Pair<String, Integer[]>("_TIFFmalloc", new Integer[] { 0 }),
            new Pair<String, Integer[]>("png_malloc_warn", new Integer[] { 1 }),
            new Pair<String, Integer[]>("xmlMallocAtomic", new Integer[] { 0 }));
    // {
    // // "png_malloc_warn",
    // };

    // static {
    // defaultSinkSymbols = new Pair<String, Integer[]>[] {

    // };
    // }

    TaintSinkIdentifier(Program program, DecompHelper decompHelper) {
        this.program = program;
        this.decompHelper = decompHelper;
    }

    List<TaintSink> getCallToSymbols(String[] additionalSymbols) {
        List<TaintSink> results = new ArrayList<TaintSink>();
        var symbolTable = program.getSymbolTable();
        for (var sinkInfo : defaultSinkSymbols) {
            var symbols = symbolTable.getSymbols(sinkInfo.first);
            for (var symbol : symbols) {
                if (!(symbol instanceof FunctionSymbol))
                    continue;
                for (var symbolRef : symbol.getReferences()) {
                    int numCallRef = 0;
                    Address callAddr = null;
                    Address thunkFuncAddress = symbolRef.getFromAddress();
                    /// Traverse all references and step out if there is a thunk function for this function. 
                    for (var ref : program.getReferenceManager().getReferencesTo(thunkFuncAddress)) {
                        if (ref.getReferenceType() == RefType.THUNK) {
                            thunkFuncAddress = ref.getFromAddress();
                            numCallRef = 0;
                            break;
                        } else if (ref.getReferenceType().isCall()) {
                            callAddr = ref.getFromAddress();
                            numCallRef += 1;
                        }
                    }
                    /// Manually recognize thunk functions.
                    if (numCallRef == 1) {
                        var func = program.getFunctionManager().getFunctionContaining(callAddr);
                        var callInstrMaxAddr = program.getListing().getInstructionAt(callAddr).getMaxAddress();
                        /// If the function body is less than 5 * PointerSize and a tail call is found. Regard it as a thunk function. 
                        if (func.getBody().getNumAddresses() <= 5 * func.getBody().getMinAddress().getPointerSize() &&
                                func.getBody().getMaxAddress().equals(callInstrMaxAddr)) {
                            thunkFuncAddress = func.getEntryPoint();
                        }
                    }
                    for (var ref : program.getReferenceManager().getReferencesTo(thunkFuncAddress)) {
                        if (!ref.getReferenceType().isCall()) {
                            continue;
                        }
                        // ColoredPrint.info("Ref of %s from %x. ", symbolName,
                        // ref.getFromAddress().getOffset());
                        var refFromAddress = ref.getFromAddress();
                        var function = program.getFunctionManager().getFunctionContaining(refFromAddress);
                        var hfunc = decompHelper.decompileFunction(function);
                        if (hfunc == null)
                            continue;

                        var iter = hfunc.getPcodeOps(refFromAddress);
                        while (iter.hasNext()) {
                            var pcodeOpAST = iter.next();
                            if (pcodeOpAST.getOpcode() == PcodeOp.CALL ||
                                    pcodeOpAST.getOpcode() == PcodeOp.CALLIND ||
                                    pcodeOpAST.getOpcode() == PcodeOp.CALLOTHER) {
                                for (var criticalIndex : sinkInfo.second) {
                                    /// The zero-th input is the called address. 
                                    var varnodeAST = (VarnodeAST) pcodeOpAST.getInput(criticalIndex+1);
                                    results.add(new TaintSink(varnodeAST, refFromAddress, TaintSinkType.Default));
                                    ColoredPrint.info("%s with c idx (%d) called at 0x%x", sinkInfo.first, criticalIndex, refFromAddress.getOffset());
                                }
                            }
                        }
                    }
                }
            }
        }
        return results;
    }

    
}
