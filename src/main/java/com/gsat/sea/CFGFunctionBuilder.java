package com.gsat.sea;

import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.TreeMap;

import com.gsat.sea.CFGBlock.OpSite;
import com.gsat.sea.analysis.SCC;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class CFGFunctionBuilder {
    Address fva;
    Function function;
    CFGBlock root;
    TreeMap<SequenceNumber, CFGBlock> blocks;
    private Stack<CFGBlock> worklist = null;

    CFGFunctionBuilder(Address start, Function func) {
        fva = start;
        function = func;
        root = null;
        blocks = new TreeMap<>();
    }

    public Address getAddress() {
        return fva;
    }

    public CFGBlock root() {
        if (root != null)
            return root;
        for (var bl : blocks.values()) {
            if (bl.getAddress().equals(fva))
                return bl;
        }
        for (var bl : blocks.values())
            if (bl.getAddress().compareTo(fva) >= 0)
                return bl;
        return blocks.firstEntry().getValue();
    }

    public void append(CFGBlock bl) {
        // Nop block maybe generated and break this assert. Maybe just ignore it. 
        // assert blocks.get(bl.getStartSeqNum()) == null;
        blocks.put(bl.getStartSeqNum(), bl);
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

    public CFGFunction finalizeFuncion(int pcodeLevel, HighFunction hfunc) {
        return new CFGFunction(fva, getBlocks(), pcodeLevel, hfunc);
    }

    public int getNumBlocks() {
        return blocks.size() + (root == null ? 0 : 1);
    }

    /// Get the first block that contains this address
    public CFGBlock getFirstBlockContaining(SequenceNumber seqnum) {
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

    public CFGBlock getFirstBlockContaining(Address address) {
        return getFirstBlockContaining(new SequenceNumber(address, 0));
    }

    /// Get the OpSite at base + orderOffset
    public OpSite getOpSiteRelToBlock(CFGBlock base, int orderOffset) {
        CFGBlock current = base;
        while (orderOffset < 0) {
            SequenceNumber blSeqnum = current.getStartSeqNum();
            var entry = blocks.lowerEntry(blSeqnum);
            if (entry == null)
                return null; // Jump out of this function. Just ignore. 
            current = entry.getValue();
            orderOffset += current.numSeq();
        }
        while (orderOffset >= current.numSeq()) {
            orderOffset -= current.numSeq();
            SequenceNumber lastOpSeqnum = current.getLastSeqNum();
            var entry = blocks.higherEntry(lastOpSeqnum);
            if (entry == null)
                return null;
            current = entry.getValue();
        }
        int opIdx = current.getOpIdxFromOrder(orderOffset);
        assert opIdx != -1;
        return new OpSite(current, opIdx);
    }

    /// Get first OpSite that starts at the address
    public OpSite getOpSiteAtAddress(Address address) {
        CFGBlock targetBl = getFirstBlockContaining(address);
        if (targetBl == null)
            return null;
        int opIdx = targetBl.getOpIdxFromAddress(address);
        if (opIdx == -1)
            return null;
        return new OpSite(targetBl, opIdx);
    }

    private Address getAvailableBlockStart(long nskip) {
        Address addr = fva.getAddressSpace().getMaxAddress();
        SequenceNumber seqnum = new SequenceNumber(addr, 0);
        while (nskip >= 0) {
            while (blocks.containsKey(seqnum)) {
                addr = addr.subtract(1);
                seqnum = new SequenceNumber(addr, 0);
            }
            nskip -= 1;
            addr = addr.subtract(1);
            seqnum = new SequenceNumber(addr, 0);
        }
        return addr;
    }

    /// TODO Try ensuring edges order and resolving in-block branches. 
    ///      And merge fixReturnBlockHasSucc. 
    public void fixFlow() {
        fixBranch();
        // removeEmptyBlock();
        fixMultipleHeads();
        fixNoReturn();
    }

    /// When imported CFG is used to construct CFGFunction, 
    /// there may be some branches/return PcodeOp inside some blocks. 
    /// These are inconsistent and need fixing. 
    public void fixBranch() {
        worklist = new Stack<>();
        worklist.addAll(blocks.values());
        while (!worklist.isEmpty()) {
            fixBranchAt(worklist.pop());
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
    /// some (broken) CFG has multiple heads (i.e. multiple entries). 
    /// Add a start node to fix it. 
    public void fixMultipleHeads() {
        List<CFGBlock> nodes = getBlocks();
        /// Find those CFG heads. They are strong connected components 
        ///     that have no outer predecessors. 
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
        /// Check if there is only one head. And the head is the function entry point. 
        CFGBlock preRoot = root();
        int rootScc = sccIds[preRoot.id()];
        if (numHeads == 1 && sccIsHead[rootScc])
            return; // Good CFG.
        /// Otherwise, add a start node to fix it. 
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
            if (i < 0)
                continue;
            PcodeOp lastNoBranch = oplist.get(i);
            while (i > 0 && SOGOp.endsBlock(lastNoBranch.getOpcode())) {
                lastNoBranch = oplist.get(--i);
            }
            if (SOGOp.isCall(lastNoBranch.getOpcode())) {
                possibleEndBlocks.add(entry.getValue());
            }
        }
        /// Use blocks that ends with BRANCHIND
        if (possibleEndBlocks.isEmpty()) {
            for (var entry : blocks.entrySet()) {
                PcodeOp lastOp = entry.getValue().getLastOp();
                if (lastOp != null && lastOp.getOpcode() == PcodeOp.BRANCHIND) {
                    possibleEndBlocks.add(entry.getValue());
                }
            }
        }
        /// Use blocks that ends with CBRANCH
        if (possibleEndBlocks.isEmpty()) {
            for (var entry : blocks.entrySet()) {
                PcodeOp lastOp = entry.getValue().getLastOp();
                if (lastOp != null && lastOp.getOpcode() == PcodeOp.CBRANCH) {
                    possibleEndBlocks.add(entry.getValue());
                }
            }
        }
        /// Use blocks that has call instruction 
        if (possibleEndBlocks.isEmpty()) {
            for (var entry : blocks.entrySet()) {
                for (PcodeOp op : entry.getValue().getPcodeOps())
                    if (SOGOp.isCall(op.getOpcode())) {
                        possibleEndBlocks.add(entry.getValue());
                        break;
                    }
            }
        }
        /// Use all blocks
        if (possibleEndBlocks.isEmpty()) {
            possibleEndBlocks.addAll(blocks.values());
        }
        CFGBlock retbl = new CFGBlock(getAvailableBlockStart(0), 0);
        append(retbl);
        for (var bl : possibleEndBlocks) {
            bl.linkOut(retbl);
        }
    }

    /// Link the block with its branch target. 
    private void linkBranchTarget(CFGBlock cur, CFGBlock fallThrough) {
        PcodeOp lastOp = cur.getLastOp();
        int opc = lastOp.getOpcode();
        if (opc == PcodeOp.BRANCHIND) {
            cur.linkOut(fallThrough); /// Cannot resolve the target of BRANCHIND
            return;
        }
        if (opc != PcodeOp.BRANCH && opc != PcodeOp.CBRANCH) {
            return; /// No branch to link 
        }
        Address target = lastOp.getInput(0).getAddress();
        OpSite splitSite = null;
        if (target.isConstantAddress()) {
            int splitOffset = (int) target.getOffset();
            int splitOrder = cur.numSeq() - 1 + splitOffset;
            splitSite = getOpSiteRelToBlock(cur, splitOrder);
        } else if (target.isLoadedMemoryAddress()) {
            splitSite = getOpSiteAtAddress(target);
        } else {
            // To Be Done?
        }
        if (splitSite == null)
            return; // Jump out of this function. Just ignore. 
        CFGBlock targetBl, splitted = splitSite.getBlock();
        int splitIdx = splitSite.getOpIdx();
        if (splitIdx == 0) {
            targetBl = splitted;
        } else {
            assert splitIdx > 0;
            targetBl = splitted.splitAt(splitIdx);
            append(targetBl);
            linkBranchTarget(splitted, targetBl);
            if (splitted == cur) // Ref equal
                cur = targetBl; // cur points to the block that branchs
        }
        cur.linkOut(targetBl);
    }

    private void fixBranchAt(CFGBlock bl) {
        List<PcodeOp> oplist = bl.getPcodeOps(); // ref to bl.oplist
        if (oplist.isEmpty())
            return;
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
                linkBranchTarget(bl, newBl);
            }
        }
        PcodeOp lastOp = oplist.get(oplist.size() - 1);
        int opc = lastOp.getOpcode();
        if (opc == PcodeOp.RETURN) {
            bl.clearOutFlow();
        } else if (opc == PcodeOp.CBRANCH && bl.getSuccessors().size() == 1) {
            linkBranchTarget(bl, null);
        }
    }

    /// A return block must ends with RETURN. 
    /// Replace tail unconditional branches with calls (i.e. tail calls). 
    /// For tail conditional branches, add another return block to fix it. 
    /// For other cases, just append a return op. 
    public void resolveTailBranches(GraphFactory graphFactory) {
        List<CFGBlock> newReturns = new ArrayList<>();
        for (CFGBlock bl : blocks.values()) {
            if (!bl.isReturnBlock())
                continue;
            PcodeOp lastOp = bl.getLastOp();
            if (lastOp != null && lastOp.getOpcode() == PcodeOp.RETURN)
                continue;
            int opc = lastOp != null ? lastOp.getOpcode() : PcodeOp.PCODE_MAX;
            if (opc == PcodeOp.BRANCH || opc == PcodeOp.BRANCHIND) {
                Varnode target = lastOp.getInput(0);
                bl.truncateOpList(bl.numOps() - 1);
                PcodeOp newCall = new PcodeOp(lastOp.getSeqnum(),
                        PcodeOp.CALL, new Varnode[] { target }, null);
                graphFactory.adaptOp(newCall, bl, function);
            } else if (opc == PcodeOp.CBRANCH) {
                Address nextAddr = getAvailableBlockStart(newReturns.size());
                CFGBlock retBl = new CFGBlock(nextAddr, 1);
                bl.linkOut(retBl);
                newReturns.add(retBl);
                bl = retBl;
            }
            PcodeOp nullReturn = new PcodeOp(
                    bl.getLastSeqNum(), PcodeOp.RETURN, new Varnode[0], null);
            graphFactory.adaptOp(nullReturn, bl, function);
        }
        for (CFGBlock retBl : newReturns)
            append(retBl);
    }

}
