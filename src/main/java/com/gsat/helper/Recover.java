package com.gsat.helper;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import com.gsat.core.FlowNode;
import com.gsat.utils.ColoredPrint;

import me.tongfei.progressbar.ProgressBar;

import java.util.*;

public class Recover {
    private Program program;
    private FlatProgramAPI flatApi;
    private DecompHelper decompHelper;
    private Map<Long,HashSet<String>> results;

    public Map<Long, HashSet<String>> getResults() {
        return results;
    }

    public Recover(Program program) throws Exception {
        this.program = program;
        this.flatApi = new FlatProgramAPI(program);
        decompHelper = new DecompHelper(flatApi);
        this.results = new HashMap<>();
    }

    protected List<Function> getAllCallingFunctionTo(Function func) {
        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(func.getEntryPoint());
        List<Function> functionsCallingSinkFunction = new ArrayList<>();
        HashSet<Long> offsets = new HashSet<>();
        int numRers = 0;
        while (refIter.hasNext()) {
            numRers += 1;
            Reference currentSinkFunctionReference = refIter.next();
            Function callingFunction = this.flatApi.getFunctionContaining(currentSinkFunctionReference.getFromAddress());

            if (callingFunction == null || callingFunction.isThunk()) {
                continue;
            }
            if (!callingFunction.getName().startsWith("FUN_")) {
                continue;
            }
            if (!offsets.contains(callingFunction.getEntryPoint().getOffset())) {
                offsets.add(callingFunction.getEntryPoint().getOffset());
                functionsCallingSinkFunction.add(callingFunction);
            }
        }
        ColoredPrint.info("Found %d xrefs and %d calling functions for %s. ", numRers, offsets.size(), func.getName());
        return functionsCallingSinkFunction;
    }


    public ArrayList<PcodeOpAST> getFunctionCallSitePCodeOps(Function f, Long logFuncAddr){

        ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();

        HighFunction hfunction = decompHelper.decompileFunction(f);
        if(hfunction == null) {
            return null;
        }
        Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();

        //iterate over all p-code ops in the function
        while (ops.hasNext() && !this.flatApi.getMonitor().isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {

                //current p-code op is a CALL
                //get the address CALL-ed
                Varnode calledVarnode = pcodeOpAST.getInput(0);

                if (calledVarnode == null || !calledVarnode.isAddress()) {
                    continue;
                }
                //if the CALL is to our function, save this callsite
                Function calledFunc = this.flatApi.getFunctionAt(calledVarnode.getAddress());
                if (calledFunc == null) {
                    continue;
                }
                if(calledFunc.getEntryPoint().getOffset() ==  logFuncAddr) {
                    pcodeOpCallSites.add(pcodeOpAST);
                }
            }
        }
        return pcodeOpCallSites;
    }

    public boolean addrInMemBlock(Address address, String name) {
        MemoryBlock block = program.getMemory().getBlock(name);
        if (block == null) {
            return false;
        }
        return block.contains(address);
    }

    private Data tryCreateAsciiAt(Address destAddr) {
        int txId = program.startTransaction("createAscii");
        try {
            Data data = this.flatApi.createAsciiString(destAddr);
            program.endTransaction(txId, true);
            return data;
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return null;
        }
    }

    private String getAddrString(Address destAddr, Boolean allowIndirect) {
        if (!addrInMemBlock(destAddr, ".data") && !addrInMemBlock(destAddr, ".rodata")
                && !(program.getMemory().getBlock(".rodata") == null && program.getMemory().contains(destAddr))) {
            /// Not a known const
            return null;
        }
        Data data = this.flatApi.getDataAt(destAddr);
        if (data == null) {
            data = tryCreateAsciiAt(destAddr);
        } else if (allowIndirect && data.isPointer()){
            Address indirectAddr = (Address) data.getValue();
            data = this.flatApi.getDataAt(indirectAddr);
            if (data == null) {
                data = tryCreateAsciiAt(indirectAddr);
            }
        }
        String constPtrValue = null;
        if (data != null && data.hasStringValue()) {
            constPtrValue = data.getDefaultValueRepresentation();
            if (constPtrValue.length() == 0){   constPtrValue = null;   }
        } 

        return constPtrValue;
    }

    private String extractFunctionName(String funcName) {
        if (funcName == null) return null;
        char[] name = funcName.toCharArray();
        int startIdx = 0, endIdx = name.length-1;
        while (startIdx <= endIdx && "'\" *\\".indexOf(name[startIdx]) != -1) {
            startIdx += 1;
        }
        while (startIdx <= endIdx && "'\" *\\".indexOf(name[endIdx]) != -1) {
            endIdx -= 1;
        }
        if (startIdx > endIdx) return null;
        if (!((name[startIdx]=='_')||Character.isUpperCase(name[startIdx])||Character.isLowerCase(name[startIdx]))) {
            return null;
        }
        for(int i=startIdx+1;i<endIdx;i+=1) {
            char c = name[i];
            if (!Character.isJavaIdentifierPart(c) || c == '$') {
                return null;
            }
        }
        return String.copyValueOf(name, startIdx, endIdx-startIdx+1);
    }

    public void doRecover(Long logFuncAddr,int paramIdx) {
        
        Function logFunc = flatApi.getFunctionAt(flatApi.toAddr(logFuncAddr));
        if (logFunc == null) {
            System.out.println("Can't find function on addr.");
            System.exit(0);
        }

        List<Function> functionsCallingSinkFunction = getAllCallingFunctionTo(logFunc);

        try (ProgressBar pb = new ProgressBar("Recovering", functionsCallingSinkFunction.size())) {
            for (Function currentFunction : functionsCallingSinkFunction) {
                pb.step();
                ArrayList<PcodeOpAST> callSites = getFunctionCallSitePCodeOps(currentFunction, logFuncAddr);
                if (callSites == null) {    continue;   }

                Long currentFuncOffset = currentFunction.getEntryPoint().getOffset();
                for (PcodeOpAST callSite : callSites) {
                    if (paramIdx + 1 > callSite.getNumInputs()) {
                        continue;
                    }
                    Varnode functionNode = callSite.getInput(paramIdx);
                    String funcName = null;
                    if (functionNode.isAddress()) {
                        funcName = getAddrString(functionNode.getAddress(), true);
                    } else {
                        Long val = new FlowNode(functionNode,program).getValue();
                        if (val != null) {
                            funcName = getAddrString(flatApi.toAddr(val), true);
                        }
                    }
                    funcName = extractFunctionName(funcName);
                    if (funcName == null) { continue; }
                    if (!results.containsKey(currentFuncOffset)) {
                        results.put(currentFuncOffset, new HashSet<>());
                    }
                    results.get(currentFuncOffset).add(funcName);
                }
            }
        }
    }
}
