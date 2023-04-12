package com.gsat.sea;

import java.util.List;
import java.util.Comparator;
import java.util.ArrayList;

import com.gsat.sea.analysis.DAGNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;

/// A CFGBlock contains a sequence of pcode ops 
///     occupying a sequence number interval ranged from `start` to `last`. 
public class CFGBlock implements DAGNode<CFGBlock> {
    int _id;
    private ArrayList<PcodeOp> oplist;
    ArrayList<CFGBlock> cfgIns;
    ArrayList<CFGBlock> cfgOuts;

    SequenceNumber start = null;
    SequenceNumber last = null;

    public static class IdComparator implements Comparator<CFGBlock> {
        public int compare(CFGBlock o1, CFGBlock o2) {
            return Integer.compare(o1._id, o2._id);
        }
    }

    public static class OpSite {
        CFGBlock bl;
        int opIdx;

        public OpSite(CFGBlock bl, int opIdx) {
            this.bl = bl;
            this.opIdx = opIdx;
        }

        public CFGBlock getBlock() {
            return bl;
        }

        public int getOpIdx() {
            return opIdx;
        }
    }

    CFGBlock(Address nodeStartEa, int speculativeNumInsts) {
        this(new SequenceNumber(nodeStartEa, 0), speculativeNumInsts);
    }

    CFGBlock(SequenceNumber seqnum, int speculativeNumInsts) {
        assert seqnum != null;
        start = seqnum;
        oplist = new ArrayList<>(speculativeNumInsts);
        cfgIns = new ArrayList<>();
        cfgOuts = new ArrayList<>();
    }

    public int id() {
        return _id;
    }

    public int hashCode() {
        return _id;
    }

    public void setid(int id) {
        _id = id;
    }

    public PcodeOp getFirstOp() {
        PcodeOp first = null;
        if (oplist.size() > 0)
            first = oplist.get(0);
        return first;
    }

    public PcodeOp getLastOp() {
        PcodeOp last = null;
        if (oplist.size() > 0)
            last = oplist.get(oplist.size() - 1);
        return last;
    }

    // SequenceNumber.equals only check the equivalence of the (Address, uniq) tuple. 
    void append(PcodeOp pcodeOp) {
        SequenceNumber opSeqnum = pcodeOp.getSeqnum();
        if (opSeqnum != last && !opSeqnum.equals(last)) {
            opSeqnum.setOrder(numSeq());
            last = opSeqnum;
        }
        oplist.add(pcodeOp);
    }

    public void truncateOpList(int endIdx) {
        for (int i = oplist.size() - 1; i >= endIdx; i--) {
            PcodeOp op = oplist.remove(i);
            last = op.getSeqnum();
        }
    }

    /// Returned oplist should be readonly. That is, no inserting, deleting etc.. 
    /// But modify the op inside it is allowed. 
    public List<PcodeOp> getPcodeOps() {
        return oplist;
    }

    public int numOps() {
        return oplist.size();
    }

    public int numSeq() {
        return last == null ? 0 : last.getOrder() + 1;
    }

    void linkOut(CFGBlock bl) {
        if (!cfgOuts.contains(bl)) {
            cfgOuts.add(bl);
            bl.cfgIns.add(this);
        }
    }

    void unLinkOut(CFGBlock bl) {
        cfgOuts.remove(bl);
        bl.cfgIns.remove(this);
    }

    void clearInFlow() {
        for (var pred : cfgIns)
            pred.cfgOuts.remove(this);
        cfgIns.clear();
    }

    void clearOutFlow() {
        for (var succ : getSuccessors())
            succ.cfgIns.remove(this);
        cfgOuts.clear();
    }

    public Address getAddress() {
        return start.getTarget();
    }

    /// Warning, Considering delay slots? 
    public SequenceNumber getStartSeqNum() {
        return start;
    }

    /// Warning, considering delay slots? 
    public SequenceNumber getLastSeqNum() {
        return last == null ? start : last;
    }

    public boolean containingSeqNum(SequenceNumber seqnum) {
        return getOpIdxFromSeqnum(seqnum) != -1;
    }

    public boolean startsAt(SequenceNumber seqnum) {
        return getStartSeqNum().equals(start);
    }

    public List<CFGBlock> getPredecessors() {
        return cfgIns;
    }

    public List<CFGBlock> getSuccessors() {
        return cfgOuts;
    }

    public int getPredIdx(CFGBlock pred) {
        return cfgIns.indexOf(pred);
    }

    public boolean isReturnBlock() {
        return cfgOuts.size() == 0;
    }

    public int getOpIdxFromOrder(int opOrder) {
        for (int i = opOrder; i < oplist.size(); i++) {
            SequenceNumber opSeqnum = oplist.get(i).getSeqnum();
            if (opSeqnum.getOrder() == opOrder)
                return i;
        }
        return -1;
    }

    public int getOpIdxFromSeqnum(SequenceNumber seqnum) {
        for (int i = 0; i < oplist.size(); i++) {
            if (oplist.get(i).getSeqnum().equals(seqnum))
                return i;
        }
        return -1;
    }

    public int getOpIdxFromAddress(Address splitAddr) {
        return getOpIdxFromSeqnum(new SequenceNumber(splitAddr, 0));
    }

    /// We should ensure that the splitting is only allowed 
    ///     when the first op of the new block starts a new opOrder.  
    /// That is, we should split by the opOrder rather than the opIdx. 
    public CFGBlock splitAt(int opIdx) {
        int numOps = oplist.size();
        SequenceNumber newStart = oplist.get(opIdx).getSeqnum();
        assert opIdx > 0 && opIdx < numOps;
        assert !oplist.get(opIdx - 1).getSeqnum().equals(newStart);
        CFGBlock newBl = new CFGBlock(newStart, numOps - opIdx);
        for (int i = opIdx; i < numOps; i++) {
            newBl.append(oplist.get(i));
        }
        truncateOpList(opIdx);
        newBl.cfgOuts.addAll(cfgOuts);
        for (var succ : cfgOuts) {
            succ.cfgIns.remove(this);
            succ.cfgIns.add(newBl);
        }
        cfgOuts.clear();
        if (SoNOp.hasFallThrough(getLastOp().getOpcode())) {
            linkOut(newBl);
        }
        return newBl;
    }

    public void unlink() {
        if (cfgOuts.size() == 0) {
            clearInFlow();
        } else if (cfgIns.size() == 0) {
            clearOutFlow();
        } else {
            for (var pred : cfgIns) {
                for (var succ : cfgOuts) {
                    pred.cfgOuts.remove(this);
                    succ.cfgIns.remove(this);
                    pred.linkOut(succ);
                }
            }
            cfgIns.clear();
            cfgOuts.clear();
        }
    }

    public String[] getFeatureStrs(int opt) {
        String[] bbMnems = new String[oplist.size()];
        int idx = 0;
        for (PcodeOp pcode : oplist) {
            if (opt > 0)
                bbMnems[idx++] = pcode.toString();
            else
                bbMnems[idx++] = pcode.getMnemonic();
        }
        return bbMnems;
    }

    public int getEdgeType(int predSlot) {
        int type = 0;
        if (predSlot >= 0 && predSlot < cfgIns.size())
            type = 1;
        return type;
    }
}
