package com.gsat.sea;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.Stack;
import java.util.TreeMap;
import java.util.function.Function;

import org.json.JSONArray;
import org.json.JSONObject;

import com.gsat.helper.AnalysisHelper;
import com.gsat.sea.Operations.ReturnRegion;
import com.gsat.sea.analysis.LengauerTarjan;
import com.gsat.sea.analysis.Utils.DominatorFrontiers;
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
import ghidra.program.model.pcode.Varnode;

public class CFGFactory {
    Program program;
    AddressSpace storeSpace = new GenericAddressSpace(
            "STORE", 16, AddressSpace.TYPE_UNIQUE, 0x328);
    AddressSpace newUniqueSpace = new GenericAddressSpace(
            "NewUnique", 16, AddressSpace.TYPE_UNIQUE, 0x329);
    long uniqueOffset = 0;

    private Varnode newUnique(int size) {
        Varnode res = new Varnode(newUniqueSpace.getAddress(uniqueOffset), size);
        uniqueOffset += size;
        return res;
    }

    private Varnode newStoreVarNode(int spaceId) {
        Address newStoreAddr = storeSpace.getAddress(spaceId);
        return new Varnode(newStoreAddr, 4);
    }

    public CFGFactory(Program program) {
        this.program = program;
    }

    public CFGFunction constructCfgProgramFromJsonInfo(JSONObject cfgInfo) {
        AddressFactory addressFactory = program.getAddressFactory();
        AddressSpace constantSpace = addressFactory.getConstantSpace();
        Address fva = addressFactory.getAddress(cfgInfo.getString("start_ea"));
        JSONArray nodes = cfgInfo.getJSONArray("nodes");
        JSONArray edges = cfgInfo.getJSONArray("edges");
        DataTypeManager dtmanager = program.getDataTypeManager();

        DataType undefinedPtr = dtmanager.getPointer(dtmanager.getDataType(0));
        VariableStorage retStorage = program.getCompilerSpec().getDefaultCallingConvention()
                .getReturnLocation(undefinedPtr, program);
        Varnode[] retVarnodes = retStorage.getVarnodes();

        // Step 1: Disasm and build BBs. 
        HashMap<Long, List<CFGBlock>> blockMap = new HashMap<>();
        CFGFunction cfgFunction = new CFGFunction(nodes.length());
        Iterator<Object> nodeInfoIter = nodes.iterator();
        while (nodeInfoIter.hasNext()) {
            JSONArray nodeInfo = (JSONArray) nodeInfoIter.next();
            Address nodeStartEa = addressFactory.getAddress(nodeInfo.getString(0));
            long nodeSize = nodeInfo.getLong(1);
            CFGBlock cfgBlock = new CFGBlock(nodeStartEa, (int) nodeSize / 2);
            if (nodeStartEa.equals(fva))
                cfgFunction.setRoot(cfgBlock);
            else
                cfgFunction.append(cfgBlock);
            ArrayList<CFGBlock> blockList = new ArrayList<CFGBlock>();
            blockMap.put(nodeStartEa.getOffset(), blockList);
            blockList.add(cfgBlock);
            if (nodeSize > 0) {
                /// Disasm and insert pcodes. 
                Address nodeMaxEa = nodeStartEa.add(nodeSize - 1);
                AddressSet body = addressFactory.getAddressSet(nodeStartEa, nodeMaxEa);
                AnalysisHelper.disasmBody(program, body, false);
                Instruction inst = program.getListing().getInstructionAt(nodeStartEa);
                if (inst == null) {
                    ColoredPrint.warning("Disasm inst at %x failed. ", nodeStartEa.getOffset());
                    inst = program.getListing().getInstructionAfter(nodeStartEa);
                }
                SortedMap<Integer, CFGBlock> splitBBs = new TreeMap<>();
                SortedMap<Address, CFGBlock> splitBBsByAddr = new TreeMap<>();
                PcodeOp lastCbranch = null;
                int opIdx = 0;
                Address instAddr = inst != null ? inst.getAddress() : null;
                /// TODO Maybe try resolving other in-block branches. 
                while (inst != null && body.contains(instAddr)) {
                    for (PcodeOp op : inst.getPcode()) {
                        boolean splitByAddr = !splitBBsByAddr.isEmpty() && instAddr == splitBBsByAddr.firstKey();
                        boolean splitByIdx = !splitBBs.isEmpty() && opIdx == splitBBs.firstKey();
                        if (splitByAddr || splitByIdx) {
                            assert !(splitByAddr && splitByIdx);
                            CFGBlock orgCfgBlock = cfgBlock;
                            if (splitByAddr)
                                cfgBlock = splitBBsByAddr.remove(instAddr);
                            else 
                                cfgBlock = splitBBs.remove(opIdx);
                            cfgBlock.address = instAddr;
                            orgCfgBlock.addOut(cfgBlock);
                            cfgBlock.addIn(orgCfgBlock);
                        }
                        splitCBr: if (lastCbranch != null) {
                            Address target = lastCbranch.getInput(0).getAddress();
                            lastCbranch = null;
                            CFGBlock orgCfgBlock = null, targetBlock = null;
                            if (target.isConstantAddress()) {
                                int splitOffset = (int) target.getOffset();
                                if (splitOffset <= 1) {
                                    break splitCBr;     // Failed to split
                                }
                                int splitIdx = opIdx + splitOffset - 1;
                                orgCfgBlock = cfgBlock;
                                targetBlock = new CFGBlock(nodeStartEa,
                                        Integer.max((int) nodeSize / 2 - splitIdx, 0));
                                cfgBlock = new CFGBlock(op.getSeqnum().getTarget(), splitOffset);
                                splitBBs.put(splitIdx, targetBlock);
                            } else if (target.isLoadedMemoryAddress()) {
                                orgCfgBlock = cfgBlock;
                                if (target.getOffset() <= instAddr.getOffset()) {
                                    break splitCBr;     // Failed to split
                                }
                                targetBlock = new CFGBlock(nodeStartEa, 0);
                                cfgBlock = new CFGBlock(op.getSeqnum().getTarget(), 0);
                                splitBBsByAddr.put(target, targetBlock);
                            }
                            orgCfgBlock.addOut(cfgBlock);
                            orgCfgBlock.addOut(targetBlock);
                            cfgBlock.addIn(orgCfgBlock);
                            targetBlock.addIn(orgCfgBlock);
                            blockList.add(cfgBlock);
                            blockList.add(targetBlock);
                            cfgFunction.append(cfgBlock);
                            cfgFunction.append(targetBlock);
                        }
                        if (op.getOpcode() == PcodeOp.STORE || op.getOpcode() == PcodeOp.LOAD) {
                            /// Replace the address space of the space ID constants 
                            Varnode space = op.getInput(0);
                            Varnode store = newStoreVarNode((int) space.getOffset());
                            op.setInput(store, 0);
                            op.setOutput(store);
                            cfgBlock.append(op);
                        } else if (SoNNode.isCall(op.getOpcode())) {
                            if (retVarnodes.length == 1) {
                                op.setOutput(retVarnodes[0]);
                                cfgBlock.append(op);
                            } else {
                                /// Projects the call results using subPiece
                                int allSize = 0, offset = 0;
                                for (var varnode : retVarnodes) {
                                    allSize += varnode.getSize();
                                }
                                Varnode retVarnode = newUnique(allSize);
                                op.setOutput(retVarnode);
                                cfgBlock.append(op);
                                for (var varnode : retVarnodes) {
                                    PcodeOp subPiece = new PcodeOp(null, PcodeOp.SUBPIECE, 2, varnode);
                                    Varnode constantNode = new Varnode(constantSpace.getAddress(offset),
                                            program.getDefaultPointerSize());
                                    subPiece.setInput(retVarnode, 0);
                                    subPiece.setInput(constantNode, 1);
                                    cfgBlock.append(subPiece);
                                    offset += varnode.getSize();
                                }
                            }
                        } else if (op.getOpcode() == PcodeOp.CBRANCH) {
                            lastCbranch = op;
                        } else
                            cfgBlock.append(op);
                        opIdx += 1;
                    }
                    instAddr = inst.getFallThrough();
                    inst = instAddr != null ? program.getListing().getInstructionAt(instAddr) : null;
                }
                assert splitBBs.isEmpty();
            }
        }
        // Step 2: Process edges. 
        // TODO Ensure edge orders satisfy the branch semantics? 
        Iterator<Object> edgeInfoIter = edges.iterator();
        while (edgeInfoIter.hasNext()) {
            JSONArray edgeInfo = (JSONArray) edgeInfoIter.next();
            long from = edgeInfo.getLong(0), to = edgeInfo.getLong(1);
            List<CFGBlock> fromBls = blockMap.get(from), toBls = blockMap.get(to);
            CFGBlock fromBl = fromBls.get(fromBls.size() - 1), toBl = toBls.get(0);
            fromBl.addOut(toBl);
            toBl.addIn(fromBl);
        }
        return cfgFunction;
    }

    public JSONObject dumpACFGFrom(CFGFunction cfgFunction) {
        JSONObject funcOut = new JSONObject();
        ArrayList<Long> nodes = new ArrayList<Long>();
        ArrayList<Long[]> edges = new ArrayList<Long[]>();
        JSONObject bbsOut = new JSONObject();
        for (CFGBlock bl : cfgFunction.getBlocks()) {
            long ea = bl.getAddress().getOffset();
            nodes.add(ea);
            for (CFGBlock outBl : bl.getSuccessors())
                edges.add(new Long[] { ea, outBl.getAddress().getOffset() });
            JSONObject bbOut = new JSONObject();
            ArrayList<String> bbMnems = new ArrayList<String>();
            for (PcodeOp pcode : bl.getPcodeOps()) {
                bbMnems.add(pcode.getMnemonic());
            }
            bbOut.put("bb_mnems", bbMnems);
            bbsOut.put(String.format("%d", ea), bbOut);
        }
        funcOut.put("nodes", nodes);
        funcOut.put("edges", edges);
        funcOut.put("basic_blocks", bbsOut);
        return funcOut;
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

        PrototypeModel[] allCallingModels = program.getCompilerSpec().getCallingConventions();
        PrototypeModel[] callingModels = new PrototypeModel[allCallingModels.length];
        callingModels[0] = program.getCompilerSpec().getDefaultCallingConvention();
        int h = 1;
        for (PrototypeModel model : allCallingModels) {
            if (model != callingModels[0])
                callingModels[h++] = model;
        }
        var thisFunc = program.getFunctionManager().getFunctionAt(nodes.get(0).getAddress());
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
            List<PcodeOp> pcodes = n.getPcodeOps();
            PcodeOp last = null;
            if (pcodes.size() > 0)
                last = pcodes.get(pcodes.size() - 1);
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
                int opIdx = 0, numOps = bl.getPcodeOps().size();
                SoNNode lastEffectNode = null;
                for (PcodeOp op : bl.getPcodeOps()) {
                    opIdx += 1;
                    int opc = op.getOpcode(), dataUseStart = SoNNode.dataUseStart(opc);
                    if (opc == PcodeOp.COPY) {
                        /// Omit COPY
                        Varnode input = op.getInput(0);
                        Varnode out = op.getOutput();
                        Stack<SoNNode> outDefStack = getOrNewDefStack.apply(out);
                        outDefStack.push(peekOrNewDef.apply(input));
                        continue;
                    }
                    /// Link data uses 
                    SoNNode soNNode = (opIdx == numOps && SoNNode.isBlockEndControl(opc)) ? blRegion
                            : new SoNNode(opc, SoNNode.numDataUseFromOp(op));
                    for (int i = dataUseStart; i < op.getNumInputs(); i++) {
                        Varnode input = op.getInput(i);
                        soNNode.setUse(i - dataUseStart, peekOrNewDef.apply(input));
                    }
                    linkCallUse: if (SoNNode.isCall(opc)) {
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
                                        varnode = newStoreVarNode(varnode.getSpace());
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
                        for (var storage: callingModels[0].getPotentialInputRegisterStorage(program)) {
                            for (Varnode varnode : storage.getVarnodes()) {
                                var defStack = state.get(varnode);
                                if (defStack != null && defStack.size() != 0) {
                                    soNNode.addUse(defStack.peek());
                                }
                            }
                        }
                        /// Also add the StackStore as a use. 
                        Varnode stackStore = newStoreVarNode(program.getAddressFactory().getStackSpace().getSpaceID());
                        soNNode.addUse(peekOrNewDef.apply(stackStore));
                    }
                    /// Link effect edges 
                    if (SoNNode.hasEffect(opc)) {
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
                    // for (var use : soNNode.uses) {
                    //     if (use == null && !(soNNode.op() instanceof ReturnRegion)) {
                    //         ColoredPrint.info("123");
                    //     }
                    // }
                }
                getReturnValue: if (bl.getSuccessors().size() == 0) {
                    /// Determine the return value. That is, link data uses of the ReturnRegion node. 
                    boolean first = true;
                    SoNNode soNNode = blRegion;
                    end.addUse(soNNode);    /// Link RETURN-s to END
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
                    AddressSpace constantSpace = program.getAddressFactory().getConstantSpace();
                    Address contantZero = constantSpace.getAddress(0);
                    Varnode zero = new Varnode(contantZero, program.getDefaultPointerSize());
                    soNNode.setUse(0, newStorageOrConstant(zero));
                }
                /// Process region control inputs
                for (CFGBlock pre : bl.getPredecessors()) {
                    blRegion.addUse(regions.get(pre.id()));
                }
                /// Lastly, add effect uses. 
                if (lastEffectNode != null) {
                    blRegion.addUse(lastEffectNode);
                }
                for (CFGBlock succ : bl.getSuccessors()) {
                    /// Process inputs of phi-s
                    int j = SoNNode.dataUseStart(PcodeOp.MULTIEQUAL);
                    for (CFGBlock succPre : succ.getPredecessors()) {
                        if (succPre == bl)
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

    public JSONObject dumpSeaOfNodes(SoNGraph graph) {
        JSONObject funcOut = new JSONObject();
        ArrayList<Long> nodes = new ArrayList<Long>();
        ArrayList<Long[]> edges = new ArrayList<Long[]>();
        JSONObject bbsOut = new JSONObject();
        Stack<SoNNode> worklist = new Stack<>();
        Set<SoNNode> nodeSet = new HashSet<>();
        worklist.push(graph.end);
        while (!worklist.isEmpty()) {
            SoNNode node = worklist.pop();
            nodes.add(node.id());
            String[] bbMnems = new String[] { node.mnemonic() };
            for (SoNNode use : node.getUses()) {
                edges.add(new Long[] { use.id(), node.id() });
                if (!nodeSet.contains(use)) {
                    worklist.push(use);
                    nodeSet.add(use);
                }
            }
            JSONObject bbOut = new JSONObject();
            bbOut.put("bb_mnems", bbMnems);
            bbsOut.put(String.format("%d", node.id()), bbOut);
        }
        assert nodes.size() >= 10;
        funcOut.put("nodes", nodes);
        funcOut.put("edges", edges);
        funcOut.put("basic_blocks", bbsOut);
        return funcOut;
    }

}
