package com.gsat.sea;

import java.util.*;

import com.gsat.sea.SOGOp.ReturnRegion;
import com.gsat.sea.analysis.DominatorFrontiers;
import com.gsat.sea.analysis.Dominators;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class SOGBuilder {
    RevertibleDefState state = new RevertibleDefState();
    Deque<CFGBlock> worklist = new ArrayDeque<>();
    Set<CFGBlock> processed = new HashSet<>();
    SOGNode end = SOGNode.newEnd();
    List<SOGNode> regions;
    List<SemiDefState> phiDefs;
    Map<PcodeOp, SOGNode> phiMap;
    Map<SequenceNumber, List<SOGNode>> postEffectUse;

    GraphFactory graphFactory;
    CFGFunction cfgFunction;
    List<CFGBlock> nodes;

    boolean useRawPcode;

    /// 0x4f,0x5f,0x6f are a invaild spaceId-s, so will not conflict with normal address spaces. 
    static Varnode memoryNode = new Varnode(GraphFactory.getStoreSpace().getAddress(0x51), 1);
    static Varnode effectNode = new Varnode(GraphFactory.getStoreSpace().getAddress(0x6f), 1);

    public static abstract class AbstractDefState<V> {
        /// Defs are orginized as no intersecting intervals (except 'defs' for constants, 
        ///     they are allowed to have intersrctions). 
        /// Every interval has its def (stack) which records nodes that define values on this interval. 
        /// A use may be pieced by several defs. 
        /// When new def overlap with old ones, old ones are cut. 
        protected TreeMap<AddressInterval, V> state;

        protected SOGNode handleUndefinedAndPut(AddressInterval interval) {
            SOGNode node = handleUndefined(interval);
            putOnNewKey(interval, node);
            return node;
        }

        public boolean keyHasOverlap(AddressInterval interval) {
            AddressInterval floorKey = state.floorKey(interval);
            if (interval.getMinAddress().isConstantAddress()) {
                return interval.equals(floorKey);
            }
            boolean isIntersecting = floorKey != null && interval.intersect(floorKey) != null;
            if (isIntersecting)
                return true;
            AddressInterval higherKey = state.higherKey(interval);
            return higherKey != null && interval.intersect(higherKey) != null;
        }

        public boolean keyCovered(AddressInterval interval) {
            AddressInterval floorKey = state.floorKey(interval);
            if (floorKey != null && floorKey.equals(interval))
                return true;
            boolean isIntersecting = floorKey != null && interval.intersect(floorKey) != null;
            AddressInterval iterStart = isIntersecting ? floorKey : interval;
            boolean result = false;
            for (AddressInterval entry : state.tailMap(iterStart).keySet()) {
                AddressInterval[] remainings = interval.substract(entry);
                if (remainings.length == 0)
                    result = true;
                if (remainings.length != 1 || interval.equals(remainings[0]))
                    break;
                interval = remainings[0];
            }
            return result;
        }

        public Set<Map.Entry<AddressInterval, V>> entrySet() {
            return state.entrySet();
        }

        protected SOGNode handleSubPiece(SOGNode input, int outSize, long offset, Varnode defined) {
            return SOGNode.newProject(input, outSize, offset, defined);
        }

        protected abstract SOGNode handleUndefined(AddressInterval interval);

        protected abstract void putOnNewKey(AddressInterval interval, SOGNode node);

        protected abstract V remove(AddressInterval interval);

        protected abstract SOGNode eput(Map.Entry<AddressInterval, V> entry, SOGNode node);

        protected abstract SOGNode eget(Map.Entry<AddressInterval, V> entry);

        public SOGNode peekOrNew(Varnode varnode) {
            return peekOrNew(AddressInterval.fromVarnode(varnode));
        }

        public SOGNode peekOrNew(AddressInterval varnode) {
            SOGNode node = peek(varnode);
            return node == null ? handleUndefinedAndPut(varnode) : node;
        }

        public SOGNode peek(Varnode varnode) {
            return peek(AddressInterval.fromVarnode(varnode));
        }

        public SOGNode peek(AddressInterval requiredRange) {
            Varnode requiredRangeNode = requiredRange.toVarnode();
            var sEntry = state.floorEntry(requiredRange);
            if (sEntry != null && sEntry.getKey().equals(requiredRange)) {
                return eget(sEntry); /// defStack is ensured non-empty
            }
            if (requiredRange.getMinAddress().isConstantAddress()) {
                return null;
            }
            boolean noDefOverlapped = true;
            /// Find all defs that are overlaped with this required use.
            /// Subpiece those defs and finally piece the use.
            boolean isIntersecting = sEntry != null && requiredRange.intersect(sEntry.getKey()) != null;
            AddressInterval iterStart = isIntersecting ? sEntry.getKey() : requiredRange;
            List<Pair<AddressInterval, SOGNode>> newDefs = new ArrayList<>();
            List<SOGNode> subPieces = new ArrayList<>();
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
                    SOGNode newStorage = handleUndefined(undefined);
                    newDefs.add(new Pair<>(undefined, newStorage));
                    subPieces.add(newStorage);
                    requiredRange = requiredRange.removeFromStart(sizeUndefined);
                }
                long intersectedLen = intersected.getLength();
                long offset = intersectedMin.subtract(entry.getKey().getMinAddress());
                SOGNode project, input = eget(entry);
                if (intersectedLen != entry.getKey().getLength()) {
                    Varnode defined = new Varnode(intersectedMin, (int) intersectedLen);
                    project = handleSubPiece(input, (int) intersectedLen, offset, defined);
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
                putOnNewKey(pair.first, pair.second);
            }
            if (requiredRange != null) {
                SOGNode newStorage = handleUndefinedAndPut(requiredRange);
                subPieces.add(newStorage);
            }
            SOGNode result;
            if (subPieces.size() == 1) {
                result = subPieces.get(0);
            } else {

                
                assert subPieces.size() > 1;
                result = SOGNode.newPiece(subPieces.size(), requiredRangeNode);
                int i = 0;
                for (SOGNode part : subPieces) {
                    result.setUse(i++, part);
                }
            }
            return result;
        }

        public SOGNode put(Varnode varnode, SOGNode node) {
            return put(AddressInterval.fromVarnode(varnode), node);
        }

        /// Return the old value associated with the key.
        public SOGNode put(AddressInterval requiredRange, SOGNode node) {
            assert node != null;
            var sEntry = state.floorEntry(requiredRange);
            if (sEntry != null && sEntry.getKey().equals(requiredRange)) {
                return eput(sEntry, node);
            }
            if (requiredRange.getMinAddress().isConstantAddress()) {
                putOnNewKey(requiredRange, node);
                return null;
            }
            /// Find all defined ranges that are covered / partly covered by this new define. And record that. 
            boolean isIntersecting = sEntry != null && requiredRange.intersect(sEntry.getKey()) != null;
            AddressInterval iterStart = isIntersecting ? sEntry.getKey() : requiredRange;
            List<Pair<AddressInterval, SOGNode>> newView = new ArrayList<>();
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
                    Varnode defined = remaining.toVarnode();
                    SOGNode subPiece = handleSubPiece(eget(entry), subPieceSize, subPieceOffset, defined);
                    newView.add(new Pair<>(remaining, subPiece));
                }
            }
            /// Remove all defs that overlap with this new def
            for (AddressInterval interval : tobeRemoved) {
                remove(interval);
            }
            /// Insert back remaining defs (not covered part of the removed defs).
            for (var pair : newView) {
                putOnNewKey(pair.first, pair.second);
            }
            /// Finally, insert the new def.
            putOnNewKey(requiredRange, node);
            return null;
        }

        public void removeOverlappedWith(AddressInterval interval) {
            var sEntry = state.floorEntry(interval);
            if (sEntry != null && sEntry.getKey().equals(interval)) {
                /// The key is exactly contained.
                state.remove(interval);
                return;
            }
            if (interval.getMinAddress().isConstantAddress()) {
                return;
            }
            /// Find all defs that are overlaped with this required use and then remove them. 
            boolean isIntersecting = sEntry != null && interval.intersect(sEntry.getKey()) != null;
            AddressInterval iterStart = isIntersecting ? sEntry.getKey() : interval;
            List<AddressInterval> tobeRemoved = new ArrayList<>();
            for (var entry : state.tailMap(iterStart).entrySet()) {
                AddressInterval eKey = entry.getKey();
                AddressInterval intersected = interval.intersect(eKey);
                if (intersected == null)
                    break;
                tobeRemoved.add(eKey);
            }
            /// Remove all defs that overlap with specific interval
            for (AddressInterval temp : tobeRemoved) {
                state.remove(temp);
            }
        }

    }

    public static class DefState extends AbstractDefState<SOGNode> {
        public DefState() {
            state = new TreeMap<>();
        }

        protected SOGNode handleUndefined(AddressInterval interval) {
            return SOGNode.newStoreOrConst(interval);
        }

        protected void putOnNewKey(AddressInterval interval, SOGNode node) {
            assert node != null;
            assert !state.containsKey(interval);
            state.put(interval, node);
        }

        protected SOGNode eput(Map.Entry<AddressInterval, SOGNode> entry, SOGNode node) {
            return entry.setValue(node);
        }

        protected SOGNode eget(Map.Entry<AddressInterval, SOGNode> entry) {
            return entry.getValue();
        }

        protected SOGNode remove(AddressInterval interval) {
            return state.remove(interval);
        }
    }

    public static class SemiDefState extends DefState {
        // Sizes of defined SOG nodes are flex and no subpieces needed. 
        //      This is why the word 'semi-def' is used. 
        @Override
        protected SOGNode handleSubPiece(SOGNode input, int outSize, long offset, Varnode defined) {
            SOGNode r = new SOGNode(input);
            r.definedNode = defined;
            return r;
        }

        @Override
        public SOGNode peek(AddressInterval requiredRange) {
            return state.get(requiredRange);
        }
    }

    public static class RevertibleDefState extends AbstractDefState<Stack<SOGNode>> {
        Stack<Stack<Pair<AddressInterval, Stack<SOGNode>>>> actions;
        DefState defsOnStart;

        RevertibleDefState() {
            defsOnStart = new DefState();
            state = new TreeMap<>();
            actions = new Stack<>();
            commit();
        }

        protected SOGNode handleUndefined(AddressInterval interval) {
            return defsOnStart.peekOrNew(interval);
        }

        protected void putOnNewKey(AddressInterval interval, SOGNode node) {
            assert node != null;
            assert !keyHasOverlap(interval);
            recordLog(interval, null);
            state.computeIfAbsent(interval, (k) -> new Stack<>()).push(node);
        }

        protected SOGNode eput(Map.Entry<AddressInterval, Stack<SOGNode>> entry, SOGNode node) {
            recordLog(entry.getKey(), null);
            SOGNode ret = entry.getValue().peek();
            entry.getValue().push(node);
            return ret;
        }

        protected SOGNode eget(Map.Entry<AddressInterval, Stack<SOGNode>> entry) {
            return entry.getValue().peek();
        }

        protected Stack<SOGNode> remove(AddressInterval interval) {
            recordLog(interval, state.get(interval));
            return state.remove(interval);
        }

        public void commit() {
            actions.push(new Stack<>());
        }

        public void revert() {
            var top = actions.pop();
            assert top.empty();
            var actionStack = actions.peek();
            while (!actionStack.empty()) {
                var action = actionStack.pop();
                if (action.second == null) {
                    Stack<SOGNode> defStack = state.get(action.first);
                    defStack.pop();
                    if (defStack.empty())
                        state.remove(action.first);
                } else {
                    removeOverlappedWith(action.first);
                    assert !keyHasOverlap(action.first);
                    state.put(action.first, action.second);
                }
            }
        }

        public void recordLog(AddressInterval interval, Stack<SOGNode> value) {
            actions.peek().push(new Pair<>(interval, value));
        }

    }

    SOGBuilder(CFGFunction cfgFunction, GraphFactory graphFactory) {
        this.nodes = cfgFunction.getBlocks();
        this.cfgFunction = cfgFunction;
        this.graphFactory = graphFactory;
        this.useRawPcode = cfgFunction.useRawPcode();
    }

    public SOG build() {
        // Step 1. Get dominator frontiers
        int[] idom = new Dominators<CFGBlock>(nodes).get();
        DominatorFrontiers<CFGBlock> df = new DominatorFrontiers<>(nodes, idom);
        List<Set<Integer>> domfrontsets = df.get();
        List<List<Integer>> childrenListInDT = df.getChildrenListInDT();
        // Step 2. Construct regions and insert PHI nodes 
        buildRegions();
        if (useRawPcode)
            insertPhiNodes(domfrontsets, false);
        else {
            preparePhi();
            insertPhiNodes(domfrontsets, true);
        }

        // Step 3. Construct Sea of Nodes.
        //      traversal in the order of dominator relations. 
        return build(childrenListInDT);
    }

    // '''
    // Basically, during the simplification process, the first input of the CBRANCH operation 
    // does not change - it will always be the original jump target. However, the decompiler 
    // adds some state to the CBRANCH operation, which can change the meaning of the 
    // operation (like whether the jump is taken on a true condition or a false condition). 
    // Also, the branching structure is encoded in the block graph, which explains what you 
    // saw with the getTrueOut and getFalseOut methods. Keep in mind that simplification can 
    // make some pretty drastic changes - for example, an entire block could be removed if 
    // its pcode ops were all simplified away.
    // '''
    // https://github.com/NationalSecurityAgency/ghidra/issues/2736
    // So, ghidra is right.. 
    private int determineCBRFallThrough(PcodeOp cbr, SequenceNumber succ0, SequenceNumber succ1) {
        // Ghidra is so buggy. PcodeBlock.getTrueOut returns wrong results. 
        // So we can only rely on ourselves. 
        SequenceNumber br = cbr.getSeqnum();
        Address target = cbr.getInput(0).getAddress();
        if (target.equals(succ0.getTarget()) ^ target.equals(succ1.getTarget())) {
            return target.equals(succ1.getTarget()) ? 0 : 1;
        }
        if (succ0.getTarget().equals(succ1.getTarget())) {
            if (succ0.getTime() == succ1.getTime())
                // Fail to determine fall through. 
                return -1;
            return succ0.getTime() < succ1.getTime() ? 0 : 1;
        }
        Long s0 = succ0.getTarget().subtract(br.getTarget());
        Long s1 = succ1.getTarget().subtract(br.getTarget());
        if (s0 >= 0 && s1 >= 0)
            return s0 < s1 ? 0 : 1;
        return s1 < 0 ? 0 : 1;
    }

    private void buildRegions() {
        regions = new ArrayList<>(nodes.size());
        phiDefs = new ArrayList<SemiDefState>(nodes.size());
        Integer[] fallThroughs = new Integer[nodes.size()];
        Arrays.fill(fallThroughs, -1);
        for (CFGBlock n : nodes) {
            phiDefs.add(new SemiDefState());
            /// Init Region Nodes. 
            PcodeOp last = n.getLastOp();
            assert !n.isReturnBlock() || last.getOpcode() == PcodeOp.RETURN;
            SOGNode controlNode = SOGNode.newRegion(last);
            if (last != null && last.getOpcode() == PcodeOp.CBRANCH && n.getSuccessors().size() == 2) {
                // The assert fails when cbr just jump to the fallthrough
                // TODO Maybe check it is this case rather than bugs. 
                // assert n.getSuccessors().size() == 2;
                if (useRawPcode) {
                    SequenceNumber succ0 = n.getSuccessors().get(0).getStartSeqNum();
                    SequenceNumber succ1 = n.getSuccessors().get(1).getStartSeqNum();
                    fallThroughs[n.id()] = determineCBRFallThrough(last, succ0, succ1);
                } else {
                    // PcodeBlock.getFalseOut returns the first out, 
                    // which means the first out is the fallthrough. 
                    fallThroughs[n.id()] = 0;
                }
            }
            regions.add(controlNode);
        }
        /// Process region control inputs
        for (CFGBlock bl : nodes) {
            SOGNode blRegion = regions.get(bl.id());
            for (CFGBlock pred : bl.getPredecessors()) {
                int prid = pred.id();
                if (fallThroughs[prid] == -1)
                    blRegion.addControlUse(regions.get(prid));
                else {
                    int projIdx = pred.getSuccIdx(bl) == fallThroughs[prid] ? 0 : 1;
                    SOGNode prRegion = regions.get(prid);
                    SOGNode cproj = SOGNode.newControlProject(prRegion, projIdx);
                    blRegion.addControlUse(cproj);
                }
            }
        }
        SOGNode start = SOGNode.newBrRegion(0);
        regions.get(0).addControlUse(start);
    }

    private void insertPhiNodes(List<Set<Integer>> domfrontsets, boolean effectOnly) {
        /// Get all defsites, i.e. each varnode is defined on which basic blocks
        /// It's important to perserve order (make sure Varnode(A, size=s1) is before Varnode(A, size=s2) where s1 < s2)
        TreeMap<Varnode, Set<Integer>> defsites = new TreeMap<>(new AddressInterval.VarnodeComparator());
        for (CFGBlock n : cfgFunction.getBlocks()) {
            for (PcodeOp op : n.getPcodeOps()) {
                if (SOGOp.defineOtherEffect(op.getOpcode())) /// effect def
                    defsites.computeIfAbsent(effectNode, k -> new HashSet<>()).add(n.id());
                if (SOGOp.defineMemoryEffect(op.getOpcode()))
                    defsites.computeIfAbsent(memoryNode, k -> new HashSet<>()).add(n.id());
                if (effectOnly)
                    continue;
                Varnode out = op.getOutput();
                if (out == null)
                    continue; /// no data out
                defsites.computeIfAbsent(out, k -> new HashSet<>()).add(n.id());
            }
        }
        /// Inserting phi nodes
        for (var ndefs : defsites.entrySet()) {
            AddressInterval interval = AddressInterval.fromVarnode(ndefs.getKey());
            Deque<Integer> worklist = new ArrayDeque<>(ndefs.getValue());
            int sotreSpaceId = GraphFactory.getStoreSpace().getSpaceID();
            while (!worklist.isEmpty()) {
                Integer n = worklist.pop();
                for (Integer blId : domfrontsets.get(n)) {
                    DefState blPhiDefs = phiDefs.get(blId);
                    if (blPhiDefs.keyCovered(interval))
                        continue;
                    int numPre = nodes.get(blId).getPredecessors().size();
                    int phiType = ndefs.getKey().equals(effectNode) ? 3
                            : (ndefs.getKey().getSpace() == sotreSpaceId ? 2 : 0);
                    SOGNode phi = SOGNode.newPhi(
                        regions.get(blId), ndefs.getKey(), numPre, phiType);
                    blPhiDefs.put(interval, phi);
                    if (!ndefs.getValue().contains(blId))
                        worklist.push(blId);
                }
            }
        }
    }

    private void preparePhi() {
        phiMap = new HashMap<>();
        for (CFGBlock n : cfgFunction.getBlocks()) {
            int blId = n.id();
            for (PcodeOp op : n.getPcodeOps()) {
                if (op.getOpcode() != PcodeOp.MULTIEQUAL)
                    continue;
                SOGNode phi = SOGNode.newPhi(regions.get(blId), op, 0);
                phi.addDefinedOp(op);
                phiMap.put(op, phi);
            }
        }
    }

    private SOG build(List<List<Integer>> bfsOrderTree) {
        postEffectUse = new HashMap<>();
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
        // buildOne(bfsOrderTree, nodes.get(0));
        assert processed.size() == cfgFunction.getNumBlocks();
        // Ghidra Warning: Ignoring partial resolution of indirect
        // assert postEffectUse.isEmpty();
        postEffectUse.clear();
        return new SOG(end);
    }

    // private void buildOne(List<List<Integer>> bfsOrderTree, CFGBlock bl) {
    //     buildOneBlock(bl);
    //     processed.add(bl); // Mark as processed.
    //     state.commit();
    //     for (var childId : bfsOrderTree.get(bl.id())) {
    //         buildOne(bfsOrderTree, nodes.get(childId));
    //     }
    //     /// backtrack
    //     state.revert();
    // }

    private void buildOneBlock(CFGBlock bl) {
        int blId = bl.id();
        SOGNode blRegion = regions.get(blId);
        for (var entry : phiDefs.get(blId).entrySet()) {
            state.put(entry.getKey(), entry.getValue()); // Add phi defs
        }
        int opIdx = 0, numOps = bl.numOps();
        for (PcodeOp op : bl.getPcodeOps()) {
            opIdx += 1;
            int opc = op.getOpcode(), dataUseStart = SOGOp.dataUseStart(opc);
            if (opc == PcodeOp.COPY) {
                /// Omit COPY
                Varnode input = op.getInput(0), out = op.getOutput();
                state.put(out, state.peekOrNew(input));
                continue;
            }
            if (opc == PcodeOp.MULTIEQUAL) {
                Varnode out = op.getOutput();
                state.put(out, phiMap.get(op));
                continue;
            }
            /// Assert that branches/return must be the last op.
            /// opt model may violate the following assertion (succ returns). 
            // assert opIdx == numOps || !SOGOp.endsBlock(opc); 
            /// TODO May fix it. 
            if (opIdx != numOps && SOGOp.endsBlock(opc)) 
                continue;
            /// Link data uses from opcode inputs
            SOGNode soNNode = SOGOp.endsBlock(opc) ? blRegion : SOGNode.newSOGNodeFromOp(op);
            for (int i = dataUseStart; i < op.getNumInputs() && i - dataUseStart < soNNode.numDataUses(); i++) {
                Varnode input = op.getInput(i);
                soNNode.setUse(i - dataUseStart, state.peekOrNew(input));
            }
            /// Link effect edges 
            if (SOGOp.useOtherEffect(opc))
                soNNode.addOtherEffectUse(state.peekOrNew(effectNode));
            if (SOGOp.defineOtherEffect(opc))
                state.put(effectNode, soNNode);
            if (SOGOp.useMemoryEffect(opc))
                soNNode.addMemoryEffectUse(state.peekOrNew(memoryNode));
            if (SOGOp.defineMemoryEffect(opc))
                state.put(memoryNode, soNNode);
            if (opc == PcodeOp.INDIRECT) {
                int seq = (int) op.getInput(1).getAddress().getOffset();
                SequenceNumber seqnum = new SequenceNumber(op.getSeqnum().getTarget(), seq);
                postEffectUse.computeIfAbsent(seqnum, k -> new ArrayList<>()).add(soNNode);
            }
            List<SOGNode> lst = postEffectUse.get(op.getSeqnum());
            if (lst != null) {
                for (SOGNode node: lst) {
                    node.addMemoryEffectUse(state.peekOrNew(memoryNode));
                    node.addOtherEffectUse(state.peekOrNew(effectNode));
                }
                postEffectUse.remove(op.getSeqnum());
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
            assert blRegion.getUses().size() > 1;
            end.addControlUse(blRegion); // Link RETURN-s to END
        }
        /// Link succ's phi nodes
        HashMap<Integer, Integer> occurenceMap = new HashMap<>();
        for (CFGBlock succ : bl.getSuccessors()) {
            /// Multi-edges may exist ...
            occurenceMap.putIfAbsent(succ.id(), 0);
            int occurence = occurenceMap.get(succ.id());
            int inOrder = succ.getPredIdx(bl, occurence);
            occurenceMap.put(succ.id(), occurence + 1);
            int j = inOrder;
            for (var entry : phiDefs.get(succ.id()).entrySet()) {
                entry.getValue().setPhiUse(j, state.peekOrNew(entry.getKey()));
            }
            for (PcodeOp op : succ.getPcodeOps()) {
                if (op.getOpcode() != PcodeOp.MULTIEQUAL)
                    continue;
                if (inOrder >= op.getNumInputs())
                    continue;
                Varnode in = op.getInput(inOrder);
                phiMap.get(op).setPhiUse(j, state.peekOrNew(in));
            }
        }
    }

}
