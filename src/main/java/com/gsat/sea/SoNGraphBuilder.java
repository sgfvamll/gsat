package com.gsat.sea;

import java.util.*;

import com.gsat.sea.SoNOp.ReturnRegion;
import com.gsat.sea.analysis.DominatorFrontiers;
import com.gsat.sea.analysis.Dominators;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SoNGraphBuilder {
    DefState state = new DefState();
    Deque<CFGBlock> worklist = new ArrayDeque<>();
    Set<CFGBlock> processed = new HashSet<>();
    SoNNode end = SoNNode.newEnd();
    List<SoNNode> regions;
    List<HashMap<Varnode, SoNNode>> phiNodes;

    GraphFactory graphFactory;
    CFGFunction cfgFunction;
    List<CFGBlock> nodes;

    public class DefState {
        /// Defs are orginized as no intersecting intervals (except 'defs' for constants, 
        ///     they are allowed to have intersrctions). 
        /// Every interval has its def stack which records nodes that define values on this interval. 
        /// A use may be pieced by several defs. 
        /// When new def overlap with old ones, old ones are cut. 
        TreeMap<AddressInterval, Stack<SoNNode>> state;
        Stack<Stack<Pair<AddressInterval, Stack<SoNNode>>>> actions;

        DefState() {
            state = new TreeMap<AddressInterval, Stack<SoNNode>>();
            actions = new Stack<>();
            commit();
        }

        private static AddressInterval addrIntervalFromVarnode(Varnode varnode) {
            return new AddressInterval(varnode.getAddress(), varnode.getSize());
        }

        private SoNNode putNoCheck(AddressInterval interval, SoNNode node) {
            assert interval.getLength() < 0x100;
            state.computeIfAbsent(interval, (k) -> new Stack<>()).push(node);
            return node;
        }

        private SoNNode constructAndPut(AddressInterval interval) {
            SoNNode node = newStorageOrConstant(interval);
            return putNoCheck(interval, node);
        }

        public void commit() {
            actions.push(new Stack<>());
        }

        public void revert() {
            assert actions.pop().empty();
            var actionStack = actions.peek();
            while (!actionStack.empty()) {
                var action = actionStack.pop();
                if (action.second == null) {
                    Stack<SoNNode> defStack = state.get(action.first);
                    defStack.pop();
                    if (defStack.empty())
                        state.remove(action.first);
                } else {
                    state.put(action.first, action.second);
                }
            }
        }

        public SoNNode peekOrNew(Varnode varnode) {
            SoNNode node = peek(varnode);
            AddressInterval requiredRange = addrIntervalFromVarnode(varnode);
            return node == null ? constructAndPut(requiredRange) : node;
        }

        public SoNNode peek(Varnode varnode) {
            AddressInterval requiredRange = addrIntervalFromVarnode(varnode);
            var sEntry = state.floorEntry(requiredRange);
            if (sEntry != null && sEntry.getKey().equals(requiredRange)) {
                return sEntry.getValue().peek(); /// defStack is ensured non-empty
            }
            if (requiredRange.getMinAddress().isConstantAddress()) {
                return constructAndPut(requiredRange);
            }
            boolean noDefOverlapped = true;
            /// Find all defs that are overlaped with this required use. 
            /// Subpiece those defs and finally piece the use. 
            boolean isIntersecting = sEntry != null && requiredRange.intersect(sEntry.getKey()) != null;
            AddressInterval iterStart = isIntersecting ? sEntry.getKey() : requiredRange;
            List<Pair<AddressInterval, SoNNode>> newDefs = new ArrayList<>();
            List<SoNNode> subPieces = new ArrayList<>();
            for (var entry : state.tailMap(iterStart).entrySet()) {
                AddressInterval intersected = requiredRange.intersect(entry.getKey());
                if (intersected == null)
                    break;
                noDefOverlapped = false;
                Address currentMinAddr = requiredRange.getMinAddress();
                Address intersectedMin = intersected.getMinAddress();
                if (!intersectedMin.equals(currentMinAddr)) {
                    int sizeUndefined = (int) (intersectedMin.getOffset()
                            - currentMinAddr.getOffset());
                    AddressInterval undefined = new AddressInterval(currentMinAddr, sizeUndefined);
                    SoNNode newStorage = newStorageOrConstant(undefined);
                    newDefs.add(new Pair<>(undefined, newStorage));
                    subPieces.add(newStorage);
                    requiredRange = requiredRange.removeFromStart(sizeUndefined);
                }
                long intersectedLen = intersected.getLength();
                long offset = intersectedMin.subtract(entry.getKey().getMinAddress());
                SoNNode project, input = entry.getValue().peek();
                if (intersectedLen != entry.getKey().getLength()) {
                    project = SoNNode.newProject((int) intersectedLen);
                    project.setUse(0, input);
                    project.setUse(1, SoNNode.newConstant(offset, 4));
                } else
                    project = input;
                subPieces.add(project);
                requiredRange = requiredRange.removeFromStart(intersectedLen);
                if (requiredRange == null)
                    break;
            }
            if (noDefOverlapped)
                return null;
            for (var pair : newDefs) {
                putNoCheck(pair.first, pair.second);
            }
            if (requiredRange != null) {
                SoNNode newStorage = constructAndPut(requiredRange);
                subPieces.add(newStorage);
            }
            SoNNode result;
            if (subPieces.size() == 1) {
                result = subPieces.get(0);
            } else {
                assert subPieces.size() > 1;
                result = SoNNode.newPiece(subPieces.size());
                int i = 0;
                for (SoNNode part : subPieces) {
                    result.setUse(i++, part);
                }
            }
            return result;
        }

        public SoNNode put(Varnode varnode, SoNNode node) {
            AddressInterval requiredRange = addrIntervalFromVarnode(varnode);
            var sEntry = state.floorEntry(requiredRange);
            if (sEntry != null && sEntry.getKey().equals(requiredRange)) {
                return sEntry.getValue().push(node);
            }
            if (requiredRange.getMinAddress().isConstantAddress()) {
                return constructAndPut(requiredRange);
            }
            /// Find all defined ranges that are covered / partly covered by this new define. And record that. 
            boolean isIntersecting = sEntry != null && requiredRange.intersect(sEntry.getKey()) != null;
            AddressInterval iterStart = isIntersecting ? sEntry.getKey() : requiredRange;
            List<Pair<AddressInterval, SoNNode>> newView = new ArrayList<>();
            List<AddressInterval> tobeRemoved = new ArrayList<>();
            for (var entry : state.tailMap(iterStart).entrySet()) {
                AddressInterval eKey = entry.getKey();
                AddressInterval intersected = requiredRange.intersect(eKey);
                if (intersected == null)
                    break;
                tobeRemoved.add(eKey);
                if (intersected.equals(eKey))
                    continue;
                for (AddressInterval remaining : eKey.substract(intersected)) {
                    long subPieceOffset = remaining.getMinAddress().subtract(eKey.getMinAddress());
                    int subPieceSize = (int) remaining.getLength();
                    SoNNode subPiece = SoNNode.newProject(subPieceSize);
                    subPiece.setUse(0, entry.getValue().peek());
                    subPiece.setUse(1, SoNNode.newConstant(subPieceOffset, 4));
                    newView.add(new Pair<>(remaining, subPiece));
                }
            }
            /// Remove all defs that overlap with this new def
            for (AddressInterval interval : tobeRemoved) {
                actions.peek().push(new Pair<>(interval, state.get(interval)));
                state.remove(interval);
            }
            /// Insert back remaining defs (not covered part of the removed defs). 
            for (var pair : newView) {
                actions.peek().push(new Pair<>(pair.first, null));
                putNoCheck(pair.first, pair.second);
            }
            /// Finally, insert the new def. 
            actions.peek().push(new Pair<>(requiredRange, null));
            return putNoCheck(requiredRange, node);
        }
    }

    SoNGraphBuilder(CFGFunction cfgFunction, GraphFactory graphFactory) {
        this.nodes = cfgFunction.getBlocks();
        this.cfgFunction = cfgFunction;
        this.graphFactory = graphFactory;
    }

    public SoNNode newStorageOrConstant(AddressSpace space, long offset, int size) {
        if (space == graphFactory.getStoreSpace()) {
            return SoNNode.newMemorySpace(offset);
        } else if (space.isConstantSpace()) {
            return SoNNode.newConstant(offset, size);
        } else if (space.isRegisterSpace()) {
            return SoNNode.newRegisterStore(offset, size);
        } else if (space.isMemorySpace()) {
            return SoNNode.newStackStore(offset, size);
        }
        return SoNNode.newOtherStore(space.getSpaceID(), offset, size);
    }

    public SoNNode newStorageOrConstant(Varnode varnode) {
        return newStorageOrConstant(varnode.getAddress().getAddressSpace(), varnode.getOffset(), varnode.getSize());
    }

    public SoNNode newStorageOrConstant(AddressInterval interval) {
        return newStorageOrConstant(interval.getMinAddress().getAddressSpace(), interval.getMinAddress().getOffset(),
                (int) interval.getLength());
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
                state.commit();
                for (var childId : bfsOrderTree.get(bl.id())) {
                    worklist.push(nodes.get(childId));
                }
            } else {
                /// backtrack 
                state.revert();
                worklist.pop();
            }
        }
        return new SoNGraph(end);
    }

    private void buildOneBlock(CFGBlock bl) {
        int blId = bl.id();
        SoNNode blRegion = regions.get(blId);
        for (var entry : phiNodes.get(blId).entrySet()) {
            state.put(entry.getKey(), entry.getValue()); // Add phi defs
        }
        int opIdx = 0, numOps = bl.numOps();
        SoNNode lastEffectNode = null;
        for (PcodeOp op : bl.getPcodeOps()) {
            opIdx += 1;
            int opc = op.getOpcode(), dataUseStart = SoNOp.dataUseStart(opc);
            if (opc == PcodeOp.COPY) {
                /// Omit COPY
                Varnode input = op.getInput(0), out = op.getOutput();
                state.put(out, state.peekOrNew(input));
                continue;
            }
            /// Assert that branches/return must be the last op. 
            assert opIdx == numOps || !SoNOp.endsBlock(opc);
            /// Link data uses from opcode inputs
            SoNNode soNNode = SoNOp.endsBlock(opc) ? blRegion : SoNNode.newSoNNode(op);
            for (int i = dataUseStart; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                soNNode.setUse(i - dataUseStart, state.peekOrNew(input));
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
                state.put(out, soNNode);
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
                entry.getValue().setUse(j, state.peekOrNew(entry.getKey()));
            }
        }
    }

    /// ----------------------------------------------------
    /// Utils 
    /// ----------------------------------------------------
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
                    callArgs.add(state.peekOrNew(varnode));
                }
            }
        }
        if (succ)
            return callArgs;
        /// 2. By the default calling convension. 
        for (var varnode : graphFactory.getPossibleCallArgVarnodes()) {
            SoNNode def = state.peek(varnode);
            if (def != null)
                callArgs.add(def);
        }
        /// Also add the StackStore as a use. 
        Varnode stackStore = graphFactory.newStackStore();
        callArgs.add(state.peekOrNew(stackStore));
        return callArgs;
    }

    private List<SoNNode> getPotentialReturnValues() {
        /// Determine the return value. That is, link data uses of the ReturnRegion node. 
        List<SoNNode> returnValues = new ArrayList<>();
        /// 1. By decompiled parameters. 
        for (Varnode varnode : cfgFunction.getReturnVarnodes()) {
            SoNNode def = state.peek(varnode);
            if (def != null)
                returnValues.add(def);
        }
        if (!returnValues.isEmpty())
            return returnValues;
        /// 2. By the calling convension. 
        for (Varnode ret : graphFactory.getPossibleReturnVarnodes()) {
            SoNNode def = state.peek(ret);
            if (def != null)
                returnValues.add(def);
        }
        if (!returnValues.isEmpty())
            return returnValues;
        /// 3. Void return
        returnValues.add(newStorageOrConstant(graphFactory.newConstant(0)));
        return returnValues;
    }

}
