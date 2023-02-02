package com.gsat.sea;

import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.TreeMap;

import com.gsat.sea.analysis.DAGGraph;
import com.gsat.sea.analysis.SCC;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class CFGFunction implements DAGGraph<CFGBlock> {
    Address fva;
    CFGBlock root;
    TreeMap<SequenceNumber, CFGBlock> blocks;
    private Stack<CFGBlock> worklist = null;

    CFGFunction(Address start) {
        fva = start;
        root = null;
        blocks = new TreeMap<>();
    }

    public Address getAddress() {
        return fva;
    }

    public CFGBlock root() {
        if (root != null)
            return root;
        return blocks.get(new SequenceNumber(fva, 0));
    }

    public void append(CFGBlock bl) {
        assert blocks.get(bl.getFirstOpSeqNum()) == null;
        blocks.put(bl.getFirstOpSeqNum(), bl);
        if (worklist != null)
            worklist.push(bl);
    }

    public List<CFGBlock> getBlocks() {
        List<CFGBlock> result = new ArrayList<>();
        CFGBlock root = root(); // root may not have least address 
        root.setid(0);
        result.add(root);
        int i = 1;
        for (CFGBlock bl : blocks.values())
            if (bl != root) {
                result.add(bl);
                bl.setid(i++);
            }
        return result;
    }

    public int getNumBlocks() {
        return blocks.size() + (root == null ? 0 : 1);
    }

    /// Get the first block that contains this address
    private CFGBlock getFirstBlockContaining(SequenceNumber seqnum) {
        var entry = blocks.floorEntry(seqnum);
        if (entry == null)
            return null;
        CFGBlock result;
        if (entry.getValue().startsAt(seqnum)) {
            return entry.getValue();
        } else {
            result = entry.getValue();
            if (!result.containingSeqNum(seqnum))
                return null;
        }
        return result;
    }

    private CFGBlock getFirstBlockContaining(Address address) {
        return getFirstBlockContaining(new SequenceNumber(address, 0));
    }

    /// cur.getLastOp().getInput(0).getAddress() == target
    private void resolveBranchTarget(Address target, CFGBlock cur) {
        if (target.isConstantAddress()) {
            int splitOffset = (int) target.getOffset();
            int splitOrder = cur.numSeq() - 1 + splitOffset;
            CFGBlock targetBl, splitted = cur;
            if (splitOffset <= 0) {
                while (splitOrder < 0) {
                    SequenceNumber blSeqnum = splitted.getFirstOpSeqNum();
                    var entry = blocks.lowerEntry(blSeqnum);
                    if (entry == null)
                        return; // Jump out of this function. Just ignore. 
                    splitted = entry.getValue();
                    splitOrder += splitted.numSeq();
                }
            } else {
                while (splitOrder >= splitted.numSeq()) {
                    splitOrder -= splitted.numSeq();
                    SequenceNumber lastOpSeqnum = splitted.getLastOpSeqNum();
                    var entry = blocks.higherEntry(lastOpSeqnum);
                    if (entry == null)
                        return; // Jump out of this function. Just ignore. 
                    splitted = entry.getValue();
                }
            }
            if (splitOrder == 0) {
                targetBl = splitted;
            } else {
                int splitIdx = splitted.getOpIdxFromOrder(splitOrder);
                assert splitIdx > 0;
                targetBl = splitted.splitAt(splitIdx);
                append(targetBl);
                if (splitted == cur) // Ref equal
                    cur = targetBl; // cur points to the block that branchs
            }
            cur.linkOut(targetBl);
        } else if (target.isLoadedMemoryAddress()) {
            CFGBlock targetBl = getFirstBlockContaining(target);
            if (targetBl == null)
                return; // Jump out of this function. Just ignore. 
            if (!targetBl.startsAt(target)) {
                boolean targetIsCur = targetBl == cur;
                targetBl = targetBl.splitAt(target);
                append(targetBl);
                if (targetIsCur)
                    cur = targetBl;
            }
            cur.linkOut(targetBl);
        } else {
            // assert false;
        }
    }

    /// Get potential blocks that end with a tail call 
    public Set<CFGBlock> getReturnBlocksEndWithBr() {
        Set<CFGBlock> blEndWithBr2Func = new HashSet<>();
        for (CFGBlock bl: blocks.values()) {
            if (!bl.isReturnBlock()) 
                continue;
            PcodeOp last = bl.getLastOp();
            if (last == null || last.getOpcode() != PcodeOp.BRANCH) 
                continue;
            blEndWithBr2Func.add(bl);
        }
        return blEndWithBr2Func;
    }

    /// TODO Try ensuring edges order and resolving in-block branches. 
    ///      And merge fixReturnBlockHasSucc. 
    public void fixFlow() {
        fixInBlockBranch();
        removeEmptyBlock();
        fixMultipleHeads();
        fixNoReturn();
    }

    /// When imported CFG is used to construct CFGFunction, 
    /// there may be some branches/return PcodeOp inside some blocks. 
    /// These are inconsistent and need fixing. 
    public void fixInBlockBranch() {
        worklist = new Stack<>();
        worklist.addAll(blocks.values());
        while (!worklist.isEmpty()) {
            CFGBlock bl = worklist.pop();
            List<PcodeOp> oplist = bl.getPcodeOps(); // ref to bl.oplist
            if (oplist.isEmpty())
                continue;
            for (int i = 0; i < oplist.size() - 1; i++) {
                PcodeOp op = oplist.get(i);
                int opc = op.getOpcode();
                if (opc == PcodeOp.RETURN) {
                    /// Flow after return instruction should be cleared 
                    bl.truncateOpList(i + 1);
                    break;
                } else if (opc == PcodeOp.BRANCH || opc == PcodeOp.CBRANCH
                        || opc == PcodeOp.BRANCHIND) {
                    /// Note, CBRANCH has Fall Through Flow, 
                    /// the edge bl -> newBl is added inside `splitAt` for CBRANCH
                    CFGBlock newBl = bl.splitAt(i + 1);
                    append(newBl);
                    if (opc == PcodeOp.BRANCHIND) {
                        bl.linkOut(newBl); /// Cannot resolve the target of BRANCHIND
                    } else {
                        Address targetAddr = op.getInput(0).getAddress();
                        resolveBranchTarget(targetAddr, bl);
                    }
                }
            }
            PcodeOp lastOp = oplist.get(oplist.size() - 1);
            int opc = lastOp.getOpcode();
            if (opc == PcodeOp.RETURN) {
                bl.clearOutFlow();
            } else if (opc == PcodeOp.BRANCH) {
                /// TODO May try fixing other block-end operations 
            }
        }
        worklist = null;
    }

    /// Remove empty blocks
    public void removeEmptyBlock() {
        List<SequenceNumber> removed = new ArrayList<>();
        for (var entry : blocks.entrySet()) {
            if (entry.getValue().numOps() == 0) {
                entry.getValue().unlink();
                removed.add(entry.getKey());
            }
        }
        for (var key : removed) {
            blocks.remove(key);
        }
    }

    /// When imported CFG is used to construct CFGFunction, 
    /// some (broken) CFG has multiple heads. Add a start node to fix it. 
    public void fixMultipleHeads() {
        List<CFGBlock> nodes = getBlocks();
        SCC<CFGBlock> sccAlg = new SCC<>(nodes);
        int[] sccIds = sccAlg.getColor();
        boolean[] sccIsHead = new boolean[sccAlg.getSccNum()];
        Arrays.fill(sccIsHead, true);
        for (int i = 0; i < nodes.size(); i++) {
            CFGBlock node = nodes.get(i);
            int sccId = sccIds[i];
            for (var pred : node.getPredecessors()) {
                if (sccId != sccIds[pred.id()]) {
                    sccIsHead[sccId] = false;
                    break;
                }
            }
        }
        int numHeads = 0;
        for (var isHead : sccIsHead) {
            numHeads += isHead ? 1 : 0;
        }
        assert numHeads > 0; // Impossible. 
        CFGBlock preRoot = root();
        int rootScc = sccIds[preRoot.id()];
        if (numHeads == 1 && sccIsHead[rootScc])
            return; // Good CFG.
        assert root == null;
        AddressSpace space = fva.getAddressSpace();
        root = new CFGBlock(space.getMaxAddress(), 0);
        root.linkOut(preRoot);
        for (var node : nodes) {
            int nSccId = sccIds[node.id()];
            if (sccIsHead[nSccId] && nSccId != rootScc) {
                /// Link all nodes in the non-root CFG heads
                root.linkOut(node);
            }
        }
    }

    /// Some CFG may have no return block (e.g. call exit()). 
    public void fixNoReturn() {
        int numReturn = 0;
        for (var entry : blocks.entrySet()) {
            if (entry.getValue().isReturnBlock())
                numReturn += 1;
        }
        if (numReturn > 0)
            return;
        Set<CFGBlock> possibleEndBlocks = new HashSet<>();
        /// Use blocks that end with call instruction 
        for (var entry : blocks.entrySet()) {
            List<PcodeOp> oplist = entry.getValue().getPcodeOps();
            int i = oplist.size() - 1;
            PcodeOp lastNoBranch = oplist.get(i);
            while (i > 0 && SoNOp.isBlockEndControl(lastNoBranch.getOpcode())) {
                lastNoBranch = oplist.get(--i);
            }
            if (SoNOp.isCall(lastNoBranch.getOpcode())) {
                possibleEndBlocks.add(entry.getValue());
            }
        }
        /// Use blocks that has call instruction 
        if (possibleEndBlocks.isEmpty()) {
            for (var entry : blocks.entrySet()) {
                for (PcodeOp op : entry.getValue().getPcodeOps())
                    if (SoNOp.isCall(op.getOpcode())) {
                        possibleEndBlocks.add(entry.getValue());
                        break;
                    }
            }
        }
        /// Use all blocks
        if (possibleEndBlocks.isEmpty()) {
            possibleEndBlocks.addAll(blocks.values());
        }
        AddressSpace space = fva.getAddressSpace();
        CFGBlock retbl = new CFGBlock(space.getMaxAddress(), 0);
        append(retbl);
        for (var bl : possibleEndBlocks) {
            bl.linkOut(retbl);
        }
    }
}
