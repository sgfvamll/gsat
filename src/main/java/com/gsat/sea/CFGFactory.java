package com.gsat.sea;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.function.Function;

import org.json.JSONArray;
import org.json.JSONObject;

import com.gsat.helper.AnalysisHelper;
import com.gsat.sea.SoNOp.ReturnRegion;
import com.gsat.sea.analysis.DAGGraph;
import com.gsat.sea.analysis.DAGNode;
import com.gsat.sea.analysis.LengauerTarjan;
import com.gsat.sea.analysis.DominatorFrontiers;
import com.gsat.utils.ColoredPrint;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.ParamList.WithSlotRec;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class CFGFactory {
    Program program;
    AddressSpace storeSpace = new GenericAddressSpace(
            "STORE", 16, AddressSpace.TYPE_UNIQUE, 0x328);
    AddressSpace newUniqueSpace = new GenericAddressSpace(
            "NewUnique", 16, AddressSpace.TYPE_UNIQUE, 0x329);
    AddressSpace constantSpace;
    long uniqueOffset = 0;
    Varnode[] possibleReturnVarnodes;

    public CFGFactory(Program program) {
        this.program = program;
        constantSpace = program.getAddressFactory().getConstantSpace();
        DataTypeManager dtmanager = program.getDataTypeManager();
        DataType undefinedPtr = dtmanager.getPointer(dtmanager.getDataType(0));
        /// TODO Modify ghidra api to add all possible input varnodes and output varnodes
        VariableStorage retStorage = program.getCompilerSpec().getDefaultCallingConvention()
                .getReturnLocation(undefinedPtr, program);
        possibleReturnVarnodes = retStorage.getVarnodes();
    }

    private Varnode newUnique(int size) {
        Varnode res = new Varnode(newUniqueSpace.getAddress(uniqueOffset), size);
        uniqueOffset += size;
        return res;
    }

    private Varnode newStore(int spaceId) {
        Address addr = storeSpace.getAddress(spaceId);
        return new Varnode(addr, 4);
    }

    private Varnode newConstant(long value) {
        return newConstant(value, program.getDefaultPointerSize());
    }

    private Varnode newConstant(long value, int size) {
        return new Varnode(constantSpace.getAddress(value), size);
    }

    /// TODO Maybe allow varnodes that have intersection. 
    private Varnode newProjsToDisjointVarnodes(Varnode[] outnodes, CFGBlock bl) {
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

    private void adaptOp(PcodeOp op, CFGBlock bl) {
        /// new PcodeOp-s can be added here, but its seqnum should be set to null. 
        int opc = op.getOpcode();
        bl.append(op);
        if (opc == PcodeOp.STORE || opc == PcodeOp.LOAD) {
            /// Replace the address space of the space ID constants 
            Varnode space = op.getInput(0);
            Varnode store = newStore((int) space.getOffset());
            op.setInput(store, 0);
            if (opc == PcodeOp.STORE)
                op.setOutput(store);
        } else if (SoNOp.isCall(opc)) {
            assert possibleReturnVarnodes.length > 0;
            op.setOutput(
                    newProjsToDisjointVarnodes(possibleReturnVarnodes, bl));
        }
    }

    public CFGFunction constructCfgProgramFromJsonInfo(JSONObject cfgInfo) {
        AddressFactory addressFactory = program.getAddressFactory();
        Address fva = addressFactory.getAddress(cfgInfo.getString("start_ea"));
        JSONArray nodes = cfgInfo.getJSONArray("nodes");
        JSONArray edges = cfgInfo.getJSONArray("edges");

        // Step 1: Disasm and build BBs. 
        HashMap<Long, CFGBlock> blockMap = new HashMap<>();
        CFGFunction cfgFunction = new CFGFunction(fva);
        for (Object nodeInfoObj : nodes) {
            JSONArray nodeInfo = (JSONArray) nodeInfoObj;
            Address nodeStartEa = addressFactory.getAddress(nodeInfo.getString(0));
            long nodeSize = nodeInfo.getLong(1);
            CFGBlock cfgBlock = new CFGBlock(nodeStartEa, (int) nodeSize / 2);
            cfgFunction.append(cfgBlock);
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
                    adaptOp(op, cfgBlock);
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
        cfgFunction.fixFlow();
        return cfgFunction;
    }

    public SoNNode newStorageOrConstant(Varnode varnode) {
        AddressSpace space = varnode.getAddress().getAddressSpace();
        if (space == storeSpace) {
            return SoNNode.newMemorySpace(varnode.getOffset());
        } else if (space.isConstantSpace()) {
            return SoNNode.newConstant(varnode.getOffset(), varnode.getSize());
        } else if (space.isRegisterSpace()) {
            return SoNNode.newRegisterStore(varnode.getOffset(), varnode.getSize());
        } else if (space.isMemorySpace()) {
            return SoNNode.newStackStore(varnode.getOffset(), varnode.getSize());
        }
        return SoNNode.newOtherStore(space.getSpaceID(), varnode.getOffset(), varnode.getSize());
    }

    public SoNGraph constructSeaOfNodes(CFGFunction cfgFunction) {
        SoNNode.clearIdCount();
        List<CFGBlock> nodes = cfgFunction.getBlocks();
        Address fva = cfgFunction.getAddress();

        PrototypeModel[] allCallingModels = program.getCompilerSpec().getCallingConventions();
        PrototypeModel[] callingModels = new PrototypeModel[allCallingModels.length];
        callingModels[0] = program.getCompilerSpec().getDefaultCallingConvention();
        int h = 1;
        for (PrototypeModel model : allCallingModels) {
            if (model != callingModels[0])
                callingModels[h++] = model;
        }
        var thisFunc = program.getFunctionManager().getFunctionAt(fva);
        // Varnode[] unaffectedNodes = callingModels[0].getUnaffectedList();
        // AddressSpace regSpace = program.getAddressFactory().getRegisterSpace();

        // Step 1. Get dominator frontiers
        LengauerTarjan<CFGBlock> helperAlg = new LengauerTarjan<>();
        int[] idom = helperAlg.getDominators(nodes);
        DominatorFrontiers<CFGBlock> df = new DominatorFrontiers<>(nodes, idom);
        List<Set<Integer>> domfrontsets = df.get();
        List<List<Integer>> childrenListInDT = df.getChildrenListInDT();

        // Step 2. Get all defsites. 
        HashMap<Varnode, Set<Integer>> defsites = new HashMap<>();
        Set<Varnode> defined = new HashSet<>();
        for (CFGBlock n : nodes) {
            for (PcodeOp op : n.getPcodeOps()) {
                Varnode out = op.getOutput();
                if (out == null || defined.contains(out))
                    continue;
                Set<Integer> defs = defsites.get(out);
                if (defs == null) {
                    defs = new HashSet<>();
                    defsites.put(out, defs);
                }
                defs.add(n.id());
                defined.add(out);
            }
            defined.clear();
        }

        // Step 3. Inserting PHI nodes
        List<HashMap<Varnode, SoNNode>> phiNodes = new ArrayList<>(nodes.size());
        List<SoNNode> regions = new ArrayList<>(nodes.size());
        for (CFGBlock n : nodes) {
            phiNodes.add(new HashMap<>());
            /// Init Region Nodes. 
            PcodeOp last = n.getLastOp();
            SoNNode controlNode = SoNNode.newRegionFromLastOp(last, n.getSuccessors().size() == 0);
            regions.add(controlNode);
        }
        for (Varnode a : defsites.keySet()) {
            Deque<Integer> worklist = new ArrayDeque<>(defsites.get(a));
            while (!worklist.isEmpty()) {
                Integer n = worklist.pop();
                for (Integer y : domfrontsets.get(n)) {
                    HashMap<Varnode, SoNNode> yPhiNodes = phiNodes.get(y);
                    if (yPhiNodes.containsKey(a))
                        continue;
                    int numPre = nodes.get(y).getPredecessors().size();
                    yPhiNodes.put(a, SoNNode.newPhi(regions.get(y), numPre));
                    if (!defsites.get(a).contains(y))
                        worklist.push(y);
                }
            }
        }

        // Step 4. Construct Sea of Nodes. 
        HashMap<Varnode, Stack<SoNNode>> state = new HashMap<>();
        Deque<CFGBlock> worklist = new ArrayDeque<>();
        Set<CFGBlock> processed = new HashSet<>();
        SoNNode end = SoNNode.newEnd();

        Function<Varnode, Stack<SoNNode>> getOrNewDefStack = (n) -> {
            Stack<SoNNode> defStack = state.get(n);
            if (defStack == null) {
                defStack = new Stack<>();
                state.put(n, defStack);
            }
            return defStack;
        };
        Function<Varnode, SoNNode> peekOrNewDef = (n) -> {
            Stack<SoNNode> defStack = getOrNewDefStack.apply(n);
            if (defStack.size() == 0) {
                defStack.push(newStorageOrConstant(n));
            }
            return defStack.peek();
        };

        /// TODO Handle defs and uses in different sizes 
        worklist.push(nodes.get(0));
        while (!worklist.isEmpty()) {
            CFGBlock bl = worklist.peek();
            int blId = bl.id();
            SoNNode blRegion = regions.get(blId);
            if (!processed.contains(bl)) {
                processed.add(bl);
                for (var entry : phiNodes.get(blId).entrySet()) {
                    getOrNewDefStack.apply(entry.getKey()).push(entry.getValue()); // Add phi defs
                }
                int opIdx = 0, numOps = bl.numOps();
                SoNNode lastEffectNode = null;
                for (PcodeOp op : bl.getPcodeOps()) {
                    opIdx += 1;
                    int opc = op.getOpcode(), dataUseStart = SoNOp.dataUseStart(opc);
                    if (opc == PcodeOp.COPY) {
                        /// Omit COPY
                        Varnode input = op.getInput(0);
                        Varnode out = op.getOutput();
                        Stack<SoNNode> outDefStack = getOrNewDefStack.apply(out);
                        outDefStack.push(peekOrNewDef.apply(input));
                        continue;
                    }
                    /// Assert that branches/return must be the last op. 
                    assert opIdx == numOps || !SoNOp.isBlockEndControl(opc);
                    /// Link data uses 
                    SoNNode soNNode = (opIdx == numOps && SoNOp.isBlockEndControl(opc)) ? blRegion
                            : new SoNNode(opc, SoNOp.numDataUseOfPcodeOp(op));
                    for (int i = dataUseStart; i < op.getNumInputs(); i++) {
                        Varnode input = op.getInput(i);
                        soNNode.setUse(i - dataUseStart, peekOrNewDef.apply(input));
                    }
                    linkCallUse: if (SoNOp.isCall(opc)) {
                        /// 1. By decompiled parameters. 
                        boolean succ = false;
                        _1_linkByCalleeParams: if (opc == PcodeOp.CALL) {
                            var callee = program.getFunctionManager().getFunctionAt(op.getInput(0).getAddress());
                            if (callee == null)
                                break _1_linkByCalleeParams;
                            var parameters = callee.getParameters();
                            if (parameters == null)
                                break _1_linkByCalleeParams;
                            succ = true;
                            boolean stackUsed = false;
                            for (var param : parameters) {
                                for (Varnode varnode : param.getVariableStorage().getVarnodes()) {
                                    /// TODO May fix STORE output and feed stack entry (rather than stack space) here
                                    boolean isStack = varnode.getAddress().isStackAddress();
                                    if (isStack && !stackUsed) {
                                        varnode = newStore(varnode.getSpace());
                                        stackUsed = true;
                                    } else if (isStack) {
                                        continue;
                                    }
                                    soNNode.addUse(peekOrNewDef.apply(varnode));
                                }
                            }
                        }
                        if (succ)
                            break linkCallUse;
                        /// 2. By the calling convension. 
                        for (var storage : callingModels[0].getPotentialInputRegisterStorage(program)) {
                            for (Varnode varnode : storage.getVarnodes()) {
                                var defStack = state.get(varnode);
                                if (defStack != null && defStack.size() != 0) {
                                    soNNode.addUse(defStack.peek());
                                }
                            }
                        }
                        /// Also add the StackStore as a use. 
                        Varnode stackStore = newStore(program.getAddressFactory().getStackSpace().getSpaceID());
                        soNNode.addUse(peekOrNewDef.apply(stackStore));
                    }
                    /// Link effect edges 
                    if (SoNOp.hasEffect(opc)) {
                        if (lastEffectNode != null) {
                            soNNode.addUse(lastEffectNode);
                        }
                        lastEffectNode = soNNode;
                    }
                    /// Push def
                    Varnode out = op.getOutput();
                    if (out != null) { // Every op has at most one output. 
                        Stack<SoNNode> defStack = getOrNewDefStack.apply(out);
                        defStack.push(soNNode);
                    }
                    for (var use : soNNode.uses) {
                        assert use != null || soNNode.op() instanceof ReturnRegion;
                    }
                }
                getReturnValue: if (bl.getSuccessors().size() == 0) {
                    /// Determine the return value. That is, link data uses of the ReturnRegion node. 
                    boolean first = true;
                    SoNNode soNNode = blRegion;
                    end.addUse(soNNode); /// Link RETURN-s to END
                    assert soNNode.op() instanceof ReturnRegion;
                    /// 1. By decompiled parameters. 
                    if (thisFunc != null && thisFunc.getReturn() != null) {
                        Parameter outParam = thisFunc.getReturn();
                        for (Varnode varnode : outParam.getVariableStorage().getVarnodes()) {
                            var defStack = state.get(varnode);
                            if (defStack == null || defStack.size() == 0)
                                continue;
                            if (first) {
                                first = false;
                                soNNode.setUse(0, defStack.peek());
                            } else
                                soNNode.addUse(defStack.peek());
                        }
                    }
                    if (!first)
                        break getReturnValue;
                    /// 2. By the calling convension. 
                    for (PrototypeModel model : callingModels) {
                        for (var entry : state.entrySet()) {
                            Varnode varnode = entry.getKey();
                            if (!varnode.isRegister() || entry.getValue().empty())
                                continue; // Return storage assumed to be a register storage. 
                            WithSlotRec rec = new WithSlotRec();
                            if (!model.possibleOutputParamWithSlot(varnode.getAddress(), varnode.getSize(), rec))
                                continue;
                            soNNode.setUse(0, entry.getValue().peek());
                            break getReturnValue;
                        }
                    }
                    /// 3. Void return
                    soNNode.setUse(0, newStorageOrConstant(newConstant(0)));
                }
                /// Process region control inputs
                for (CFGBlock pred : bl.getPredecessors()) {
                    blRegion.addUse(regions.get(pred.id()));
                }
                /// Lastly, add effect uses. 
                if (lastEffectNode != null) {
                    blRegion.addUse(lastEffectNode);
                }
                for (CFGBlock succ : bl.getSuccessors()) {
                    /// Process inputs of phi-s
                    int j = SoNOp.dataUseStart(PcodeOp.MULTIEQUAL);
                    for (CFGBlock succPred : succ.getPredecessors()) {
                        if (succPred == bl)
                            break;
                        j += 1;
                    }
                    for (var entry : phiNodes.get(succ.id()).entrySet()) {
                        Stack<SoNNode> defStack = getOrNewDefStack.apply(entry.getKey());
                        if (defStack.size() == 0) {
                            defStack.push(newStorageOrConstant(entry.getKey()));
                        }
                        entry.getValue().setUse(j, defStack.peek());
                    }
                }
                for (var childId : childrenListInDT.get(blId)) {
                    worklist.push(nodes.get(childId));
                }
            } else {
                /// backtrack 
                worklist.pop();
                /// Pop defs
                for (var varnode : phiNodes.get(blId).keySet()) {
                    state.get(varnode).pop();
                }
                for (PcodeOp op : bl.getPcodeOps()) {
                    Varnode out = op.getOutput();
                    if (out != null) {
                        state.get(out).pop();
                    }
                }
            }
        }
        SoNGraph result = new SoNGraph(end);
        return result;
    }

    public <T extends DAGNode<T>> JSONObject dumpGraph(DAGGraph<T> graph) {
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
            String[] nodeMnems = node.getFeatureStrs();
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

}
