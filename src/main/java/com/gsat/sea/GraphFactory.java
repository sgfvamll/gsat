package com.gsat.sea;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import org.apache.commons.lang3.ObjectUtils.Null;
import org.json.JSONArray;
import org.json.JSONObject;

import com.gsat.helper.AnalysisHelper;
import com.gsat.sea.analysis.DAGGraph;
import com.gsat.sea.analysis.DAGNode;
import com.gsat.utils.ColoredPrint;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class GraphFactory {
    static int nDefaultArgs = 4;
    static AddressSpace storeSpace = new GenericAddressSpace(
            "STORE", 32, AddressSpace.TYPE_UNIQUE, 0x328);

    AddressSpace newUniqueSpace = new GenericAddressSpace(
            "NewUnique", 32, AddressSpace.TYPE_UNIQUE, 0x329);
    Program program;
    AddressSpace constantSpace;
    AddressSpace stackBaseSpace;
    // AddressSpace memorySpace;
    long uniqueOffset = 0;

    Varnode[] possibleReturnVarnodes;
    Varnode[] possibleCallArgVarnodes;

    /// When inserting RETURN op (e.g. handling tail call), use this as the return
    /// address.
    Varnode defaultReturnAddress;
    // Varnode defaultMemoryVarnode;

    Varnode stackPointer;

    DecompInterface decompInterface1 = null;
    DecompInterface decompInterface2 = null;

    public GraphFactory(Program program) {
        this.program = program;
        constantSpace = program.getAddressFactory().getConstantSpace();

        PrototypeModel defaultCC = program.getCompilerSpec().getDefaultCallingConvention();

        Register spReg = program.getCompilerSpec().getStackPointer();
        stackPointer = new Varnode(spReg.getAddress(), spReg.getNumBytes());
        stackBaseSpace = program.getCompilerSpec().getStackBaseSpace();
        // memorySpace = program.getAddressFactory().getDefaultAddressSpace();
        // defaultMemoryVarnode = new
        // Varnode(storeSpace.getAddress(memorySpace.getSpaceID()), 1);

        /// Determine default varnodes where call args are placed.
        List<Varnode> possibleCallArgList = new ArrayList<>();
        for (var storage : defaultCC.getPotentialInputRegisterStorage(program))
            for (Varnode varnode : storage.getVarnodes())
                possibleCallArgList.add(varnode);
        long stackOffset = defaultCC.getStackParameterOffset();
        int pointerSize = program.getDefaultPointerSize();
        AddressSpace stkAddrSpace = program.getAddressFactory().getStackSpace();
        for (int i = 0; i < nDefaultArgs - possibleCallArgList.size(); i++)
            possibleCallArgList.add(new Varnode(stkAddrSpace.getAddress(stackOffset), pointerSize));
        possibleCallArgVarnodes = possibleCallArgList.toArray(new Varnode[0]);

        /// Need customized ghidra build to provide `getPotentialOutputRegisterStorage`
        /// api.
        List<Varnode> possibleReturnValueList = new ArrayList<>();
        for (var storage : defaultCC.getPotentialOutputRegisterStorage(program))
            for (Varnode varnode : storage.getVarnodes())
                possibleReturnValueList.add(varnode);
        possibleReturnVarnodes = possibleReturnValueList.toArray(new Varnode[0]);
        if (possibleReturnVarnodes.length == 0) {
            /// Determine default varnodes where return values are placed.
            DataTypeManager dtmanager = program.getDataTypeManager();
            DataType undefinedPtr = dtmanager.getPointer(dtmanager.getDataType(0));
            possibleReturnVarnodes = defaultCC.getReturnLocation(undefinedPtr, program).getVarnodes();
        }

        /// Determine default varnodes where return address is placed.
        Varnode[] returnAddresses = defaultCC.getReturnAddress();
        if (returnAddresses.length >= 1) {
            assert returnAddresses.length == 1; // Assert for debug.
            defaultReturnAddress = returnAddresses[0];
        } else {
            String languageId = program.getLanguageID().getIdAsString();
            String returnAddrName = null;
            if (languageId.startsWith("MIPS"))
                returnAddrName = "ra";
            else if (languageId.startsWith("AARCH64"))
                returnAddrName = "x30"; // lr
            else if (languageId.startsWith("ARM"))
                returnAddrName = "lr";
            assert returnAddrName != null;
            Register retReg = program.getLanguage().getRegister(returnAddrName);
            defaultReturnAddress = new Varnode(retReg.getAddress(), retReg.getNumBytes());
        }
    }

    public void clearState() {
        uniqueOffset = 0;
    }

    public Varnode[] getPossibleReturnVarnodes() {
        return possibleReturnVarnodes;
    }

    public Varnode[] getPossibleCallArgVarnodes() {
        return possibleCallArgVarnodes;
    }

    public Function getFunctionAt(Address address) {
        return program.getFunctionManager().getFunctionAt(address);
    }

    public static AddressSpace getStoreSpace() {
        return storeSpace;
    }

    public AddressSpace getUniqueSpace() {
        return newUniqueSpace;
    }

    public Varnode newUnique(int size) {
        Varnode res = new Varnode(newUniqueSpace.getAddress(uniqueOffset), size);
        uniqueOffset += size;
        return res;
    }

    /// Store is the output of STORE op, representing a memory snapshot.
    public Varnode newStore(int spaceId) {
        Address addr = storeSpace.getAddress(spaceId);
        return new Varnode(addr, 0);
    }

    public Varnode newConstant(long value) {
        return newConstant(value, program.getDefaultPointerSize());
    }

    public Varnode newConstant(long value, int size) {
        return new Varnode(constantSpace.getAddress(value), size);
    }

    public Varnode newStackStore() {
        int spaceId = program.getAddressFactory().getStackSpace().getSpaceID();
        return newStore(spaceId);
    }

    public PcodeOp newNop(Address address) {
        Varnode inout = newUnique(program.getDefaultPointerSize());
        return new PcodeOp(address, 0, PcodeOp.COPY, new Varnode[] { inout }, inout);
    }

    public CFGFunction constructCfgProgramFromCFGSummary(JSONObject cfgInfo) {
        if (cfgInfo.has("nodes"))
            return constructCfgProgramFromCFGSummaryV2(cfgInfo);
        else
            return constructCfgProgramFromCFGSummaryV1(cfgInfo);
    }

    public CFGFunction constructCfgProgramFromCFGSummaryV1(JSONObject cfgInfo) {
        AddressFactory addressFactory = program.getAddressFactory();
        Address startEa = addressFactory.getAddress(cfgInfo.getString("start_ea"));
        Address endEa = addressFactory.getAddress(cfgInfo.getString("end_ea"));
        Address maxEa = endEa.subtract(1);
        AddressSet body = addressFactory.getAddressSet(startEa, maxEa);
        if (decompInterface1 == null) {
            decompInterface1 = setUpDecompiler("normalize");
            decompInterface2 = setUpDecompiler("firstpass");
        }
        HighFunction hfunc = checkedGetHFuncContaining(body, decompInterface1);
        if (hfunc == null) {
            // Give another try with different settings. 
            // Pcode generated using 'firstpass' style still has MULTIEQUAL. 
            // That is, not in raw pcode form. 
            hfunc = checkedGetHFuncContaining(body, decompInterface2);
            if (hfunc == null)
                return null;
        }
        HashMap<SequenceNumber, CFGBlock> blockMap = new HashMap<>();
        Function function = hfunc.getFunction();
        CFGFunctionBuilder builder = new CFGFunctionBuilder(startEa, function);
        ArrayList<PcodeBlockBasic> pCodeBBs = hfunc.getBasicBlocks();
        for (var bb : pCodeBBs) {
            SequenceNumber start = CFGBlock.getPcodeBlockStart(bb);
            CFGBlock cfgBlock = new CFGBlock(start, 10);
            builder.append(cfgBlock);
            blockMap.put(start, cfgBlock);
            var pcodeIter = bb.getIterator();
            while (pcodeIter.hasNext()) 
                adaptOp(pcodeIter.next(), cfgBlock, function);
        }
        for (var bb : pCodeBBs) {
            SequenceNumber start = CFGBlock.getPcodeBlockStart(bb);
            CFGBlock frbl = blockMap.get(start);
            frbl.initFlowFromPcodeBlock(blockMap, bb);
        }
        // builder.fixFlow();
        builder.fixMultipleHeads();
        builder.fixNoReturn();
        builder.resolveTailBranches(this);
        return builder.finalizeFuncion(false);
    }

    /// Does not handle indirected branch. 
    public CFGFunction constructCfgProgramFromCFGSummaryV1_fallback(JSONObject cfgInfo) {
        AddressFactory addressFactory = program.getAddressFactory();
        Address fva = addressFactory.getAddress(cfgInfo.getString("start_ea"));
        Address endva = addressFactory.getAddress(cfgInfo.getString("end_ea"));
        Address maxva = endva.subtract(1);
        AddressSet body = addressFactory.getAddressSet(fva, maxva);

        Function function = getFunctionAt(fva);
        AnalysisHelper.disasmBody(program, body, false);

        CFGFunctionBuilder builder = new CFGFunctionBuilder(fva, function);
        CFGBlock cfgBlock = new CFGBlock(fva, (int) body.getNumAddresses());
        builder.append(cfgBlock);

        Instruction inst = program.getListing().getInstructionAt(fva);
        if (inst == null) {
            ColoredPrint.warning("Disasm inst at %x failed. NOP filled. ", fva.getOffset());
            adaptOp(newNop(fva), cfgBlock, function);
            inst = program.getListing().getInstructionAfter(fva);
        }
        Address instAddr = inst != null ? inst.getAddress() : null;
        while (inst != null && body.contains(instAddr)) {
            /// inst.getPcode() will not only get the corresponding pcode ops of this instruction 
            ///     but also merge the pcodes of instuctions resided in its delay slots. 
            /// Example: 00402e94 - bne xxx; 00402e98 - sb xxx.
            /// inst = `bne xxx`; inst.getPcode() will return the pcodes corresponding to `sb xxx; bne xxx;`. 
            /// And inst.getFallThrough() will return 00402e9C.
            PcodeOp[] oplist = inst.getPcode();
            for (PcodeOp op : oplist) {
                adaptOp(op, cfgBlock, function);
            }
            if (oplist.length == 0) { // Placeholder to fill gaps. Gaps inside a block may confuse further analysis.
                adaptOp(newNop(instAddr), cfgBlock, function);
            }
            inst = program.getListing().getInstructionAfter(instAddr);
            if (inst != null)
                instAddr = inst.getAddress();
        }

        builder.fixFlow();
        builder.resolveTailBranches(this);
        return builder.finalizeFuncion(true);
    }

    public CFGFunction constructCfgProgramFromCFGSummaryV2(JSONObject cfgInfo) {
        AddressFactory addressFactory = program.getAddressFactory();
        Address fva = addressFactory.getAddress(cfgInfo.getString("start_ea"));
        JSONArray nodes = cfgInfo.getJSONArray("nodes");
        JSONArray edges = cfgInfo.getJSONArray("edges");

        Function function = getFunctionAt(fva);

        // Step 1: Disasm and build BBs.
        HashMap<Long, CFGBlock> blockMap = new HashMap<>();
        CFGFunctionBuilder builder = new CFGFunctionBuilder(fva, function);
        for (Object nodeInfoObj : nodes) {
            JSONArray nodeInfo = (JSONArray) nodeInfoObj;
            Address nodeStartEa = addressFactory.getAddress(nodeInfo.getString(0));
            long nodeSize = nodeInfo.getLong(1);
            CFGBlock cfgBlock = new CFGBlock(nodeStartEa, (int) nodeSize / 2);
            builder.append(cfgBlock);
            blockMap.put(nodeStartEa.getOffset(), cfgBlock);
            if (nodeSize == 0)
                continue;
            /// Disasm and insert pcodes.
            Address nodeMaxEa = nodeStartEa.add(nodeSize - 1);
            AddressSet body = addressFactory.getAddressSet(nodeStartEa, nodeMaxEa);
            AnalysisHelper.disasmBody(program, body, false);
            Instruction inst = program.getListing().getInstructionAt(nodeStartEa);
            if (inst == null) {
                ColoredPrint.warning("Disasm inst at %x failed. NOP filled. ", nodeStartEa.getOffset());
                adaptOp(newNop(nodeStartEa), cfgBlock, function);
                inst = program.getListing().getInstructionAfter(nodeStartEa);
            }
            Address instAddr = inst != null ? inst.getAddress() : null;
            while (inst != null && body.contains(instAddr)) {
                /// inst.getPcode() will not only get the corresponding pcode ops of this instruction 
                ///     but also merge the pcodes of instuctions resided in its delay slots. 
                /// Example: 00402e94 - bne xxx; 00402e98 - sb xxx.
                /// inst = `bne xxx`; inst.getPcode() will return the pcodes corresponding to `sb xxx; bne xxx;`. 
                /// And inst.getFallThrough() will return 00402e9C.
                PcodeOp[] oplist = inst.getPcode();
                for (PcodeOp op : oplist) {
                    adaptOp(op, cfgBlock, function);
                }
                if (oplist.length == 0) { // Placeholder to fill gaps. Gaps inside a block may confuse further analysis.
                    adaptOp(newNop(instAddr), cfgBlock, function);
                }
                instAddr = inst.getFallThrough();
                inst = instAddr != null ? program.getListing().getInstructionAt(instAddr) : null;
            }
        }
        // Step 2: Process edges.
        // TODO Ensure edge orders satisfy the branch semantics?
        for (Object edgeInfoObj : edges) {
            JSONArray edgeInfo = (JSONArray) edgeInfoObj;
            long from = edgeInfo.getLong(0), to = edgeInfo.getLong(1);
            CFGBlock fromBl = blockMap.get(from), toBl = blockMap.get(to);
            fromBl.linkOut(toBl);
        }
        builder.fixFlow();
        builder.resolveTailBranches(this);
        return builder.finalizeFuncion(true);
    }

    public SoNGraph constructSeaOfNodes(CFGFunction cfgFunction) {
        SoNNode.clearIdCount();
        SoNGraphBuilder builder = new SoNGraphBuilder(cfgFunction, this);
        return builder.build();
    }

    public <T extends DAGNode<T>> JSONObject dumpGraph(DAGGraph<T> graph, int verb_level) {
        JSONObject funcOut = new JSONObject();
        ArrayList<Integer> nodes = new ArrayList<Integer>();
        ArrayList<Integer[]> edges = new ArrayList<Integer[]>();
        JSONObject nodesVerb = new JSONObject();
        Stack<T> worklist = new Stack<>();
        Set<T> nodeSet = new HashSet<>();
        String featKey = (verb_level == 0) ? "node_mnems" : "node_asms";
        worklist.push(graph.root());
        while (!worklist.isEmpty()) {
            T node = worklist.pop();
            nodes.add(node.id());
            int slot = 0;
            for (T succ : node.getSuccessors()) {
                edges.add(new Integer[] { node.id(), succ.id(), node.getEdgeType(slot++) });
                if (!nodeSet.contains(succ)) {
                    worklist.push(succ);
                    nodeSet.add(succ);
                }
            }
            JSONObject nodeOut = new JSONObject();
            String[] nodeMnems = node.getFeatureStrs(verb_level);
            nodeOut.put(featKey, nodeMnems);
            nodesVerb.put(String.format("%d", node.id()), nodeOut);
        }
        /// It's unlikely that a selected function is so small...
        // assert nodes.size() >= 5;
        funcOut.put("nodes", nodes);
        funcOut.put("edges", edges);
        funcOut.put("nodes_verbs", nodesVerb);
        return funcOut;
    }

    public String debugCfgFunction(CFGFunction cfgFunction) {
        String result = String.format("[=] fva: 0x%x\n", cfgFunction.getAddress().getOffset());
        for (CFGBlock bl : cfgFunction.getBlocks()) {
            result += String.format("ID: %d. ADDR: 0x%x\n", bl.id(), bl.getAddress().getOffset());
            result += "Preds: ";
            for (CFGBlock pred : bl.getPredecessors())
                result += String.format("%d, ", pred.id());
            result += "\nSuccs: ";
            for (CFGBlock succ : bl.getSuccessors())
                result += String.format("%d, ", succ.id());
            result += "\n";
            for (PcodeOp op : bl.getPcodeOps()) {
                result += String.format("%s:\t%s\n", op.getSeqnum().toString(), op.toString());
            }
            result += "\n";
        }
        return result;
    }

    Varnode[] getReturnVarnodes(Function function) {
        if (function == null || function.getReturn() == null)
            return new Varnode[0];
        Parameter outParam = function.getReturn();
        return outParam.getVariableStorage().getVarnodes();
    }

    /// TODO Maybe allow varnodes that have intersection.
    Varnode newProjsToDisjointVarnodes(Varnode[] outnodes, SequenceNumber seqnum, CFGBlock bl) {
        if (outnodes.length == 0)
            return null;
        if (outnodes.length == 1)
            return outnodes[0];
        int allSize = 0, offset = 0;
        /// New UNIQUE that represents the tuple of all these varnodes
        for (var varnode : possibleReturnVarnodes) {
            allSize += varnode.getSize();
        }
        Varnode retVarnode = newUnique(allSize);
        /// Project this unique by SUBPIECE-s
        for (var varnode : possibleReturnVarnodes) {
            PcodeOp subPiece = new PcodeOp(seqnum, PcodeOp.SUBPIECE, 2, varnode);
            Varnode constantNode = newConstant(offset);
            subPiece.setInput(retVarnode, 0);
            subPiece.setInput(constantNode, 1);
            bl.append(subPiece);
            offset += varnode.getSize();
        }
        return retVarnode;
    }

    /// Data uses of stack / memory storage should be loadded first.
    Varnode adaptVarnode(Varnode varnode, SequenceNumber seqnum, CFGBlock bl) {
        Address addr = varnode.getAddress();
        if (addr.isMemoryAddress()) {
            /// New Load PcodeOp
            Varnode space = newStore(varnode.getSpace());
            Varnode ptr = newConstant(varnode.getOffset(), varnode.getSize());
            Varnode out = newUnique(varnode.getSize());
            bl.append(new PcodeOp(seqnum, PcodeOp.LOAD, new Varnode[] { space, ptr }, out));
            varnode = out;
        } else if (addr.isStackAddress()) {
            Varnode space = newStore(stackBaseSpace.getSpaceID());
            Varnode ptr, out = newUnique(varnode.getSize());
            if (varnode.getOffset() != 0) {
                Varnode offset = newConstant(varnode.getOffset(), stackPointer.getSize());
                ptr = newUnique(stackPointer.getSize());
                bl.append(new PcodeOp(seqnum, PcodeOp.INT_ADD, new Varnode[] { stackPointer, offset }, ptr));
            } else {
                ptr = stackPointer;
            }
            bl.append(new PcodeOp(seqnum, PcodeOp.LOAD, new Varnode[] { space, ptr }, out));
            varnode = out;
        }
        return varnode;
    }

    void adaptCall(PcodeOp callOp, CFGBlock bl) {
        SequenceNumber seqnum = callOp.getSeqnum();
        int opc = callOp.getOpcode();
        /// Identify call args first by decompiled parameters.
        boolean succ = false;
        List<Varnode> args = new ArrayList<>(4);
        Varnode[] outNodes = null;
        _1_linkByCalleeParams: if (opc == PcodeOp.CALL) {
            var callee = getFunctionAt(callOp.getInput(0).getAddress());
            if (callee == null)
                break _1_linkByCalleeParams;
            var parameters = callee.getParameters();
            if (parameters == null)
                break _1_linkByCalleeParams;
            succ = true;
            for (var param : parameters) {
                for (Varnode varnode : param.getVariableStorage().getVarnodes()) {
                    args.add(adaptVarnode(varnode, seqnum, bl));
                }
            }
            if (callee.getReturn() != null)
                outNodes = callee.getReturn().getVariableStorage().getVarnodes();
        }
        if (!succ) {
            /// Identify call args then by the default calling convension.
            for (var varnode : getPossibleCallArgVarnodes()) {
                args.add(adaptVarnode(varnode, seqnum, bl));
            }
        }
        if (outNodes == null)
            outNodes = possibleReturnVarnodes;
        for (int idx = args.size() - 1; idx >= 0; idx--) {
            callOp.setInput(args.get(idx), idx + 1);
        }
        bl.append(callOp);
        callOp.setOutput(newProjsToDisjointVarnodes(outNodes, seqnum, bl));
    }

    void adaptReturn(PcodeOp op, CFGBlock bl, Function function) {
        SequenceNumber seqnum = op.getSeqnum();
        int orgNumInputs = op.getNumInputs();
        if (orgNumInputs >= 2) {
            bl.append(op);
            return;
        }
        if (orgNumInputs == 0)
            op.setInput(adaptVarnode(defaultReturnAddress, seqnum, bl), 0);
        Varnode[] outNodes;
        if (function != null && function.getReturn() != null) {
            /// Get possible return nodes by decompiled parameters.
            outNodes = function.getReturn().getVariableStorage().getVarnodes();
        } else {
            /// Get possible return nodes by the calling convension.
            outNodes = getPossibleReturnVarnodes();
        }
        for (int i = outNodes.length - 1; i >= 0; i--) {
            op.setInput(adaptVarnode(outNodes[i], seqnum, bl), i + 1);
        }
        if (outNodes.length == 0) {
            /// Void return.
            op.setInput(newConstant(0), 1);
        }
        bl.append(op);
    }

    void adaptOp(PcodeOp op, CFGBlock bl, Function function) {
        /// new PcodeOp-s can be added here, but its seqnum should be set to null.
        int opc = op.getOpcode();
        if (opc == PcodeOp.STORE || opc == PcodeOp.LOAD) {
            /// Replace the address space of the space ID constants
            Varnode space = op.getInput(0);
            Varnode store = newStore((int) space.getOffset());
            op.setInput(store, 0);
            // if (opc == PcodeOp.STORE)
            //     op.setOutput(store);
            bl.append(op);
        } else if (SoNOp.isCall(opc)) {
            adaptCall(op, bl);
        } else if (opc == PcodeOp.RETURN) {
            adaptReturn(op, bl, function);
        } else {
            bl.append(op);
        }
    }

    private DecompInterface setUpDecompiler(String simplificationStyle) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();

        long suggestedMaxInsts = options.getMaxInstructions(); // 100000
        options.setMaxInstructions(Integer.MAX_VALUE);
        ColoredPrint.info("Changing max_instructions from 0x%x to 0x%x. ", suggestedMaxInsts, Integer.MAX_VALUE);

        decompInterface.setOptions(options);

        decompInterface.toggleCCode(false);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle(simplificationStyle);
        if (!decompInterface.openProgram(program)) {
            System.out.printf("Decompiler error: %s\n", decompInterface.getLastMessage());
        }
        return decompInterface;
    }

    private HighFunction checkedGetHFuncContaining(AddressSetView body, DecompInterface decompInterface) {
        Address startEa = body.getMinAddress();
        Address endEa = body.getMaxAddress();
        Function func = program.getFunctionManager().getFunctionAt(startEa);

        /// Check failed (1): Try disasmbling and re-create the function.
        if (func == null || !body.subtract(func.getBody()).isEmpty()) {
            /// Create function if not valid.
            int txId = program.startTransaction("CreateFunction");
            AddressSetView toBeDecompiled = body;
            while (true) {
                DisassembleCommand cmd = new DisassembleCommand(toBeDecompiled, toBeDecompiled,
                        false);
                cmd.applyTo(program, TaskMonitor.DUMMY);
                AddressSetView decompiled = cmd.getDisassembledAddressSet();
                toBeDecompiled = toBeDecompiled.subtract(decompiled);
                if (toBeDecompiled.isEmpty() || decompiled.isEmpty())
                    break;
            }
            CreateFunctionCmd fcmd = new CreateFunctionCmd(null, startEa, body, SourceType.DEFAULT, false, true);
            fcmd.applyTo(program, TaskMonitor.DUMMY);
            func = program.getListing().getFunctionAt(startEa);
            program.endTransaction(txId, true);

            if (func == null) {
                ColoredPrint.error(
                        "Create function failed (start: %x, end: %x) ",
                        startEa.getOffset(), endEa.getOffset());
                return null;
            }
        }

        /// Decompile first, decompling may fix some previous wrong analysis.
        /// decompInterface.getOptions().getDefaultTimeout() == 30
        // Linearly with the number of instructions
        int decompilingTimeSecs = Integer.max((int) body.getNumAddresses() / 100, 30);
        DecompileResults dresult = decompInterface
                .decompileFunction(func, decompilingTimeSecs, TaskMonitor.DUMMY);
        HighFunction hfunc = dresult.getHighFunction();

        if (hfunc == null) {
            ColoredPrint.error(
                    "Decompile function failed! Function (start: %x, end: %x, body: %s)",
                    startEa.getOffset(), endEa.getOffset(), func.getBody());
            ColoredPrint.error(dresult.getErrorMessage());
            return null;
        }
        return hfunc;
    }

}
