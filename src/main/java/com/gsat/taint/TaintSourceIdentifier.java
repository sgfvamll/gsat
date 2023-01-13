package com.gsat.taint;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import com.gsat.helper.DecompHelper;
import com.gsat.taint.sources.TaintSource;
import com.gsat.taint.sources.TaintSource.StorageType;
import com.gsat.utils.ColoredPrint;

import generic.stl.Pair;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;

public class TaintSourceIdentifier {
    private Program program;
    private DecompHelper decompHelper;
    
    // "gets", "scanf", "fgets", "recv", "recvfrom", "recvmsg", "getc", "fread", "read", "getenv", "GetUrlValue", "fprintf", "accept",
    static private List<Pair<String, Integer[]>> defaultSourceSymbols = Arrays.asList(
            /// 0 -> return value
            /// -2 -> vararg starts from 2
            new Pair<String, Integer[]>("gets", new Integer[] { 0, 1 }),
            new Pair<String, Integer[]>("scanf", new Integer[] { -2 }),
            new Pair<String, Integer[]>("fgets", new Integer[] { 0, 1 }),
            new Pair<String, Integer[]>("recv", new Integer[] { 2 }),
            new Pair<String, Integer[]>("recvfrom", new Integer[] { 2 }),
            new Pair<String, Integer[]>("recvmsg", new Integer[] { 2 }),
            new Pair<String, Integer[]>("getc", new Integer[] { 0 }),
            new Pair<String, Integer[]>("fread", new Integer[] { 1 }),
            new Pair<String, Integer[]>("read", new Integer[] { 2 }),
            new Pair<String, Integer[]>("getenv", new Integer[] { 0 }),
            new Pair<String, Integer[]>("GetUrlValue", new Integer[] { 0 }),// TODO
            new Pair<String, Integer[]>("fprintf", new Integer[] { -2 }),
            new Pair<String, Integer[]>("accept", new Integer[] { 2, 3 }));

    TaintSourceIdentifier(Program program, DecompHelper decompHelper) {
        this.program = program;
        this.decompHelper = decompHelper;
    }

    List<TaintSource> getExportedFunctionParams() {
        var symbolTable = program.getSymbolTable();
        var funcManager = program.getFunctionManager();
        List<TaintSource> results = new ArrayList<TaintSource>();
		AddressIterator iterator = symbolTable.getExternalEntryPointIterator();
		while (iterator.hasNext()) {
			Symbol symbol = symbolTable.getPrimarySymbol(iterator.next());
			if (symbol == null) continue;
            var func = funcManager.getFunctionAt(symbol.getAddress());
            if (func == null) continue;
            HighFunction hfunc = decompHelper.decompileFunction(func);
            if (hfunc == null) continue;
            for (Parameter param: hfunc.getFunction().getParameters()) {
                for (var varNode: param.getVariableStorage().getVarnodes()) {
                    var iter = hfunc.getVarnodes(varNode.getAddress());
                    while (iter.hasNext()) {
                        var varNodeAST = iter.next();
                        if (varNodeAST.getDef() == null) {
                            StorageType storage = StorageType.PointerOrValue;
                            if(param.getDataType() instanceof Pointer) {
                                storage = StorageType.Pointer;
                            }
                            results.add(new TaintSource(varNodeAST, func.getEntryPoint(), TaintSource.SourceType.Default, storage));
                            ColoredPrint.info("Add source: %s at %s. ", varNodeAST.toString(), symbol.getName());
                        }
                    }
                }
            //     /// Implementation Option2 -- Error: param.getFirstUseOffset() always returns zero. 
            //     // var useAddress = hfunc.getFunction().getEntryPoint().add(param.getFirstUseOffset());
            //     // var iter = hfunc.getPcodeOps(useAddress);
            //     // while (iter.hasNext()) {
            //     //     var opCodeAST = iter.next();
            //     //     for (var varNode: iter.next().getInputs()) {
            //     //         if (varNode.equals(param.getFirstStorageVarnode()) &&
            //     //         varNode.getSize() == param.getFirstStorageVarnode().getSize()) {
            //     //             results.add(new TaintSource((VarnodeAST)varNode, TaintSource.TaintSourceType.Parameters));
            //     //         }
            //     //     }
            //     // }
            //     //// Implementation Option3 -- Just record a VarNode (rather than VarNodeAST) in the TaintSource. Left for futher analysis. 
            //     // for (var varNode: param.getVariableStorage().getVarnodes()) {
            //     //     var virtualVarNodeAST = new VarnodeAST(varNode.getAddress(), varNode.getSize(), 0);
            //     //     results.add(new TaintSource(virtualVarNodeAST, TaintSource.TaintSourceType.Parameters));
            //     // }
            // }

            //// Implementation Option4 -- uninitialized register or stack variables are regarded as params
            // for (var addrSpaceName: Arrays.asList("register", "stack")) {
            //     var addrSpace = hfunc.getAddressFactory().getAddressSpace(addrSpaceName);
            //     var iter = hfunc.getVarnodes(addrSpace);
            //     while (iter.hasNext()) {
            //         var varnodeAST = iter.next();
            //         if (varnodeAST.getDef() != null) continue;
            //         if (addrSpaceName == "stack" && varnodeAST.getOffset() < 0) {
            //             continue;
            //         }
            //         results.add(new TaintSource(varnodeAST, func.getEntryPoint(), SourceType.Default, StorageType.PointerOrValue));
            //     }
            }
		}
		return results;
    }

    List<TaintSource> getCallToSymbols(String[] additionalSymbols) {
        List<TaintSource> results = new ArrayList<TaintSource>();
        var symbolTable = program.getSymbolTable();
        for (var sinkInfo : defaultSourceSymbols) {
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
                                    if (criticalIndex < 0) {
                                        criticalIndex = -criticalIndex;
                                        for (int i=0;i<pcodeOpAST.getNumInputs();i++) {
                                            VarnodeAST varnodeAST = (VarnodeAST) pcodeOpAST.getInput(i);
                                            results.add(new TaintSource(varnodeAST, refFromAddress, TaintSource.SourceType.Global, TaintSource.StorageType.PointerOrValue));
                                        }
                                    } else {
                                        VarnodeAST varnodeAST;
                                        if (criticalIndex == 0) {
                                            varnodeAST = (VarnodeAST) pcodeOpAST.getOutput();
                                        } else {
                                            varnodeAST = (VarnodeAST) pcodeOpAST.getInput(criticalIndex);
                                        }
                                        if (varnodeAST == null) continue; 
                                        results.add(new TaintSource(varnodeAST, refFromAddress, TaintSource.SourceType.Global, TaintSource.StorageType.PointerOrValue));
                                    }
                                    ColoredPrint.info("Add Source: %s with c idx (%d) called at 0x%x", sinkInfo.first, criticalIndex, refFromAddress.getOffset());
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

