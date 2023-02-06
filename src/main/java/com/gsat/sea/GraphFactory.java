package com.gsat.sea;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import org.json.JSONArray;
import org.json.JSONObject;

import com.gsat.helper.AnalysisHelper;
import com.gsat.sea.analysis.DAGGraph;
import com.gsat.sea.analysis.DAGNode;
import com.gsat.utils.ColoredPrint;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class GraphFactory {
    Program program;
    static AddressSpace storeSpace = new GenericAddressSpace(
            "STORE", 16, AddressSpace.TYPE_UNIQUE, 0x328);
    AddressSpace newUniqueSpace = new GenericAddressSpace(
            "NewUnique", 16, AddressSpace.TYPE_UNIQUE, 0x329);
    AddressSpace constantSpace;
    long uniqueOffset = 0;
    Varnode[] possibleReturnVarnodes;
    Varnode[] possibleCallArgVarnodes;
    Varnode defaultReturnAddress;

    public GraphFactory(Program program) {
        this.program = program;
        constantSpace = program.getAddressFactory().getConstantSpace();
        DataTypeManager dtmanager = program.getDataTypeManager();
        DataType undefinedPtr = dtmanager.getPointer(dtmanager.getDataType(0));
        /// TODO Modify ghidra api to add all possible input varnodes and output varnodes
        PrototypeModel defaultCC = program.getCompilerSpec().getDefaultCallingConvention();
        List<Varnode> possibleCallArgList = new ArrayList<>();
        for (var storage : defaultCC.getPotentialInputRegisterStorage(program))
            for (Varnode varnode : storage.getVarnodes())
                possibleCallArgList.add(varnode);
        possibleCallArgVarnodes = possibleCallArgList.toArray(new Varnode[0]);
        possibleReturnVarnodes = defaultCC.getReturnLocation(undefinedPtr, program).getVarnodes();
        Varnode[] returnAddresses = defaultCC.getReturnAddress();
        assert returnAddresses.length == 1;
        defaultReturnAddress = returnAddresses[0];
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

    public CFGFunction constructCfgProgramFromJsonInfo(JSONObject cfgInfo) {
        AddressFactory addressFactory = program.getAddressFactory();
        Address fva = addressFactory.getAddress(cfgInfo.getString("start_ea"));
        JSONArray nodes = cfgInfo.getJSONArray("nodes");
        JSONArray edges = cfgInfo.getJSONArray("edges");

        Function function = getFunctionAt(fva);

        // Step 1: Disasm and build BBs. 
        HashMap<Long, CFGBlock> blockMap = new HashMap<>();
        CFGFunctionBuilder builder = new CFGFunctionBuilder(function);
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
                ColoredPrint.warning("Disasm inst at %x failed. ", nodeStartEa.getOffset());
                inst = program.getListing().getInstructionAfter(nodeStartEa);
            }
            Address instAddr = inst != null ? inst.getAddress() : null;
            while (inst != null && body.contains(instAddr)) {
                for (PcodeOp op : inst.getPcode()) {
                    adaptOp(op, cfgBlock, function);
                }
                instAddr = inst.getFallThrough();
                if (instAddr != null && instAddr.getOffset() < inst.getAddress().getOffset()
                        && body.contains(instAddr)) {
                    ColoredPrint.info("Delay slot?");
                }
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
        return builder.finalizeFuncion();
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
        worklist.push(graph.root());
        while (!worklist.isEmpty()) {
            T node = worklist.pop();
            nodes.add(node.id());
            for (T succ : node.getSuccessors()) {
                edges.add(new Integer[] { node.id(), succ.id() });
                if (!nodeSet.contains(succ)) {
                    worklist.push(succ);
                    nodeSet.add(succ);
                }
            }
            JSONObject nodeOut = new JSONObject();
            String[] nodeMnems = node.getFeatureStrs(verb_level);
            nodeOut.put("node_mnems", nodeMnems);
            nodesVerb.put(String.format("%d", node.id()), nodeOut);
        }
        /// It's unlikely that a selected function is so small...
        assert nodes.size() >= 10;
        funcOut.put("nodes", nodes);
        funcOut.put("edges", edges);
        funcOut.put("nodes_verbs", nodesVerb);
        return funcOut;
    }

    Varnode[] getReturnVarnodes(Function function) {
        if (function == null || function.getReturn() == null)
            return new Varnode[0];
        Parameter outParam = function.getReturn();
        return outParam.getVariableStorage().getVarnodes();
    }

    /// TODO Maybe allow varnodes that have intersection. 
    Varnode newProjsToDisjointVarnodes(Varnode[] outnodes, CFGBlock bl) {
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
            PcodeOp subPiece = new PcodeOp(null, PcodeOp.SUBPIECE, 2, varnode);
            Varnode constantNode = newConstant(offset);
            subPiece.setInput(retVarnode, 0);
            subPiece.setInput(constantNode, 1);
            bl.append(subPiece);
            offset += varnode.getSize();
        }
        return retVarnode;
    }

    /// Data uses of stack / memory storage should be loadded first. 
    Varnode adaptVarnode(Varnode varnode, CFGBlock bl) {
        Address addr = varnode.getAddress();
        if (addr.isStackAddress() || addr.isMemoryAddress()) {
            /// New Load PcodeOp
            Varnode spaceIdC = newStore(varnode.getSpace());
            PcodeOp load = new PcodeOp(null, PcodeOp.LOAD,
                    new Varnode[] { spaceIdC, varnode }, newUnique(varnode.getSize()));
            bl.append(load);
        }
        return varnode;
    }

    void adaptCall(PcodeOp callOp, CFGBlock bl) {
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
                    args.add(adaptVarnode(varnode, bl));
                }
            }
            if (callee.getReturn() != null)
                outNodes = callee.getReturn().getVariableStorage().getVarnodes();
        }
        if (!succ) {
            /// Identify call args then by the default calling convension. 
            for (var varnode : getPossibleCallArgVarnodes()) {
                args.add(adaptVarnode(varnode, bl));
            }
        }
        if (outNodes == null)
            outNodes = possibleReturnVarnodes;
        for (int idx = args.size() - 1; idx >= 0; idx--) {
            callOp.setInput(args.get(idx), idx + 1);
        }
        bl.append(callOp);
        callOp.setOutput(newProjsToDisjointVarnodes(outNodes, bl));
    }

    void adaptReturn(PcodeOp op, CFGBlock bl, Function function) {
        int orgNumInputs = op.getNumInputs();
        if (orgNumInputs >= 2) {
            bl.append(op);
            return;
        }
        if (orgNumInputs == 0)
            op.setInput(adaptVarnode(defaultReturnAddress, bl), 0);
        Varnode[] outNodes;
        if (function != null && function.getReturn() != null) {
            /// Get possible return nodes by decompiled parameters. 
            outNodes = function.getReturn().getVariableStorage().getVarnodes();
        } else {
            /// Get possible return nodes by the calling convension. 
            outNodes = getPossibleReturnVarnodes();
        }
        for (int i = outNodes.length - 1; i >= 0; i--) {
            op.setInput(outNodes[i], i + 1);
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
            if (opc == PcodeOp.STORE)
                op.setOutput(store);
            bl.append(op);
        } else if (SoNOp.isCall(opc)) {
            adaptCall(op, bl);
        } else if (opc == PcodeOp.RETURN) {
            adaptReturn(op, bl, function);
        } else {
            bl.append(op);
        }
    }

}
