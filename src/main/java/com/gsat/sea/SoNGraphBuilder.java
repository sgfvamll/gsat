package com.gsat.sea;

import java.util.*;

import com.gsat.sea.SoNOp.ReturnRegion;
import com.gsat.sea.analysis.DominatorFrontiers;
import com.gsat.sea.analysis.Dominators;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SoNGraphBuilder {
    HashMap<Varnode, Stack<SoNNode>> state = new HashMap<>();
    Deque<CFGBlock> worklist = new ArrayDeque<>();
    Set<CFGBlock> processed = new HashSet<>();
    SoNNode end = SoNNode.newEnd();
    List<SoNNode> regions;
    List<HashMap<Varnode, SoNNode>> phiNodes;

    GraphFactory graphFactory;
    CFGFunction cfgFunction;
    List<CFGBlock> nodes;

    SoNGraphBuilder(CFGFunction cfgFunction, GraphFactory graphFactory) {
        this.nodes = cfgFunction.getBlocks();
        this.cfgFunction = cfgFunction;
        this.graphFactory = graphFactory;
    }

    public SoNNode newStorageOrConstant(Varnode varnode) {
        AddressSpace space = varnode.getAddress().getAddressSpace();
        if (space == graphFactory.getStoreSpace()) {
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

    public SoNGraph build() {
        // Step 1. Get dominator frontiers
        int[] idom = new Dominators<CFGBlock>(nodes).get();
        DominatorFrontiers<CFGBlock> df = new DominatorFrontiers<>(nodes, idom);
        List<Set<Integer>> domfrontsets = df.get();
        List<List<Integer>> childrenListInDT = df.getChildrenListInDT();
        // Step 2. Construct regions and insert PHI nodes 
        buildRegions();
        insertPhiNodes(domfrontsets);
        // Step 3. Construct Sea of Nodes. 
        //      traversal in the order of dominator relations. 
        return build(childrenListInDT);
    }
 
    private void buildRegions() {
        regions = new ArrayList<>(nodes.size());
        phiNodes = new ArrayList<HashMap<Varnode, SoNNode>>(nodes.size());
        for (CFGBlock n : nodes) {
            phiNodes.add(new HashMap<>());
            /// Init Region Nodes. 
            PcodeOp last = n.getLastOp();
            SoNNode controlNode = SoNNode.newRegionFromLastOp(last, n.isReturnBlock());
            regions.add(controlNode);
        }
    }
   
    private void insertPhiNodes(List<Set<Integer>> domfrontsets) {
        /// Get all defsites, i.e. each varnode is defined on which basic blocks
        Map<Varnode, Set<Integer>> defsites = cfgFunction.generateDefsites();
        /// Inserting phi nodes 
        for (Varnode a : defsites.keySet()) {
            Deque<Integer> worklist = new ArrayDeque<>(defsites.get(a));
            while (!worklist.isEmpty()) {
                Integer n = worklist.pop();
                for (Integer y : domfrontsets.get(n)) {
                    Map<Varnode, SoNNode> blPhiNodes = phiNodes.get(y);
                    if (blPhiNodes.containsKey(a))
                        continue;
                    int numPre = nodes.get(y).getPredecessors().size();
                    blPhiNodes.put(a, SoNNode.newPhi(regions.get(y), numPre));
                    if (!defsites.get(a).contains(y))
                        worklist.push(y);
                }
            }
        }
    }

    private SoNGraph build(List<List<Integer>> bfsOrderTree) {
        worklist.push(nodes.get(0));
        while (!worklist.isEmpty()) {
            CFGBlock bl = worklist.peek();
            if (!processed.contains(bl)) {
                processed.add(bl); // Mark as processed. 
                buildOneBlock(bl);
                for (var childId : bfsOrderTree.get(bl.id())) {
                    worklist.push(nodes.get(childId));
                }
            } else {
                /// backtrack 
                restoreState(bl);
                worklist.pop();
            }
        }
        return new SoNGraph(end);
    }

    /// TODO Handle defs and uses in different sizes 
    private void buildOneBlock(CFGBlock bl) {
        int blId = bl.id();
        SoNNode blRegion = regions.get(blId);
        for (var entry : phiNodes.get(blId).entrySet()) {
            getOrNewDefStack(entry.getKey()).push(entry.getValue()); // Add phi defs
        }
        int opIdx = 0, numOps = bl.numOps();
        SoNNode lastEffectNode = null;
        for (PcodeOp op : bl.getPcodeOps()) {
            opIdx += 1;
            int opc = op.getOpcode(), dataUseStart = SoNOp.dataUseStart(opc);
            if (opc == PcodeOp.COPY) {
                /// Omit COPY
                Varnode input = op.getInput(0), out = op.getOutput();
                getOrNewDefStack(out).push(peekOrNewDef(input));
                continue;
            }
            /// Assert that branches/return must be the last op. 
            assert opIdx == numOps || !SoNOp.endsBlock(opc);
            /// Link data uses from opcode inputs
            SoNNode soNNode = SoNOp.endsBlock(opc) ? blRegion
                    : new SoNNode(opc, SoNOp.numDataUseOfPcodeOp(op));
            for (int i = dataUseStart; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                soNNode.setUse(i - dataUseStart, peekOrNewDef(input));
            }
            /// Link Call arguments 
            if (SoNOp.isCall(opc)) {
                for (SoNNode arg : getPotentialCallArgs(op)) {
                    soNNode.addUse(arg);
                }
            }
            /// Link effect edges 
            if (SoNOp.hasEffect(opc)) {
                if (lastEffectNode != null)
                    soNNode.addUse(lastEffectNode);
                lastEffectNode = soNNode;
            }
            /// Update def
            Varnode out = op.getOutput();
            if (out != null) { // Every op has at most one output. 
                getOrNewDefStack(out).push(soNNode);
            }
            /// Ensure uses are well linked. 
            for (var use : soNNode.uses) {
                assert use != null;
            }
        }
        /// Process the return block. 
        if (bl.isReturnBlock()) {
            assert blRegion.op() instanceof ReturnRegion;
            end.addUse(blRegion); /// Link RETURN-s to END
            /// Extract return values. 
            /// getPotentialReturnValues return at least one node. 
            for (SoNNode ret : getPotentialReturnValues()) {
                blRegion.addUse(ret);
            }
        }
        /// Process region control inputs
        for (CFGBlock pred : bl.getPredecessors()) {
            blRegion.addUse(regions.get(pred.id()));
        }
        /// Lastly, add effect uses to this region. 
        if (lastEffectNode != null) {
            blRegion.addUse(lastEffectNode);
        }
        /// Link succ's phi nodes
        for (CFGBlock succ : bl.getSuccessors()) {
            int j = SoNOp.dataUseStart(PcodeOp.MULTIEQUAL) + succ.getPredIdx(bl);
            for (var entry : phiNodes.get(succ.id()).entrySet()) {
                entry.getValue().setUse(j, peekOrNewDef(entry.getKey()));
            }
        }
    }

    private void restoreState(CFGBlock bl) {
        /// Pop defs
        for (var varnode : phiNodes.get(bl.id()).keySet()) {
            state.get(varnode).pop();
        }
        for (PcodeOp op : bl.getPcodeOps()) {
            Varnode out = op.getOutput();
            if (out != null) {
                state.get(out).pop();
            }
        }
    }

    /// ----------------------------------------------------
    /// Utils 
    /// ----------------------------------------------------

    private Stack<SoNNode> getOrNewDefStack(Varnode n) {
        return state.computeIfAbsent(n, k -> new Stack<>());
    }

    private SoNNode peekOrNewDef(Varnode n) {
        Stack<SoNNode> defStack = state.computeIfAbsent(n, k -> new Stack<>());
        if (defStack.size() == 0) {
            defStack.push(newStorageOrConstant(n));
        }
        return defStack.peek();
    }

    private List<SoNNode> getPotentialCallArgs(PcodeOp op) {
        List<SoNNode> callArgs = new ArrayList<>();
        int opc = op.getOpcode();
        /// 1. By decompiled parameters. 
        boolean succ = false;
        _1_linkByCalleeParams: if (opc == PcodeOp.CALL) {
            var callee = graphFactory.getFunctionAt(op.getInput(0).getAddress());
            if (callee == null)
                break _1_linkByCalleeParams;
            var parameters = callee.getParameters();
            if (parameters == null)
                break _1_linkByCalleeParams;
            succ = true;
            boolean stackUsed = false;
            for (var param : parameters) {
                for (Varnode varnode : param.getVariableStorage().getVarnodes()) {
                    /// TODO Maybe fix STORE output and feed stack entry (rather than stack space) 
                    boolean isStack = varnode.getAddress().isStackAddress();
                    if (isStack && !stackUsed) {
                        varnode = graphFactory.newStore(varnode.getSpace());
                        stackUsed = true;
                    } else if (isStack) {
                        continue;
                    }
                    callArgs.add(peekOrNewDef(varnode));
                }
            }
        }
        if (succ)
            return callArgs;
        /// 2. By the default calling convension. 
        for (var varnode : graphFactory.getPossibleCallArgVarnodes()) {
            var defStack = state.get(varnode);
            if (defStack == null || defStack.isEmpty()) 
                continue;
            callArgs.add(defStack.peek());
        }
        /// Also add the StackStore as a use. 
        Varnode stackStore = graphFactory.newStackStore();
        callArgs.add(peekOrNewDef(stackStore));
        return callArgs;
    }

    private List<SoNNode> getPotentialReturnValues() {
        /// Determine the return value. That is, link data uses of the ReturnRegion node. 
        List<SoNNode> returnValues = new ArrayList<>();
        /// 1. By decompiled parameters. 
        for (Varnode varnode : cfgFunction.getReturnVarnodes()) {
            var defStack = state.get(varnode);
            if (defStack == null || defStack.isEmpty())
                continue;
            returnValues.add(defStack.peek());
        }
        if (!returnValues.isEmpty())
            return returnValues;
        /// 2. By the calling convension. 
        for (Varnode ret : graphFactory.getPossibleReturnVarnodes()) {
            Stack<SoNNode> defStack = state.get(ret);
            if (defStack == null || defStack.empty())
                continue;
            returnValues.add(defStack.peek());
        }
        if (!returnValues.isEmpty())
            return returnValues;
        /// 3. Void return
        returnValues.add(newStorageOrConstant(graphFactory.newConstant(0)));
        return returnValues;
    }

}
