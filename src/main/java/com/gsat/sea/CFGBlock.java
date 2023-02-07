package com.gsat.sea;

import java.util.List;
import java.util.Comparator;
import java.util.ArrayList;

import com.gsat.sea.analysis.DAGNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;

public class CFGBlock implements DAGNode<CFGBlock> {
    int _id;
    Address address = null;
    private ArrayList<PcodeOp> oplist;
    ArrayList<CFGBlock> cfgIns;
    ArrayList<CFGBlock> cfgOuts;

    private int numSeq = 0;

    /// TODO should fix the numInstChecked to be the number of the delaySlots ? 
    ///      very strange case, maybe just ignore it. 
    static private int numInstCheckedToDeterminingAddr = 2;

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
        address = nodeStartEa;
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

    void append(PcodeOp pcodeOp) {
        if (pcodeOp.getSeqnum() != null)
            pcodeOp.getSeqnum().setOrder(numSeq++);
        oplist.add(pcodeOp);
    }

    public void truncateOpList(int endIdx) {
        for (int i = oplist.size() - 1; i >= endIdx; i--) {
            PcodeOp op = oplist.remove(i);
            if (op.getSeqnum() != null)
                numSeq--;
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
        return numSeq;
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

    /// ??? 
    public Address getAddress() {
        assert address != null || !oplist.isEmpty();
        if (address == null)
            address = getMinAddress();
        return address;
    }

    /// Warning, first op seqnum may not be the least seqnum 
    /// Considering delay slots. 
    public SequenceNumber getStartSeqNum() {
        SequenceNumber seqnum = null;
        if (!oplist.isEmpty()) {
            seqnum = oplist.get(0).getSeqnum();
        }
        if (seqnum == null && address != null)
            seqnum = new SequenceNumber(address, 0);
        assert seqnum != null;
        return seqnum;
    }

    /// Warning, first op seqnum may not be the least seqnum 
    /// Considering delay slots. 
    public SequenceNumber getLastOpSeqNum() {
        if (oplist.isEmpty()) {
            return new SequenceNumber(address, 0);
        } else {
            return oplist.get(oplist.size() - 1).getSeqnum();
        }
    }

    public Address getMinAddress() {
        int opIdx = 0, numInstChecked = 0;
        SequenceNumber opSeq = oplist.get(opIdx).getSeqnum();
        Address minAddr = opSeq.getTarget();
        int checkLimit = numInstCheckedToDeterminingAddr;
        while (opIdx > 0 && numInstChecked < checkLimit) {
            numInstChecked += opSeq.getTime() == 0 ? 1 : 0;
            opSeq = oplist.get(++opIdx).getSeqnum();
            if (opSeq.getTarget().getOffset() < minAddr.getOffset()) {
                minAddr = opSeq.getTarget();
            }
        }
        return minAddr;
    }

    public Address getMaxAddress() {
        int opIdx = oplist.size() - 1, numInstChecked = 0;
        SequenceNumber opSeq = oplist.get(opIdx).getSeqnum();
        Address maxAddr = opSeq.getTarget();
        int checkLimit = numInstCheckedToDeterminingAddr;
        while (opIdx > 0 && numInstChecked < checkLimit) {
            numInstChecked += opSeq.getTime() == 0 ? 1 : 0;
            opSeq = oplist.get(--opIdx).getSeqnum();
            if (opSeq.getTarget().getOffset() > maxAddr.getOffset()) {
                maxAddr = opSeq.getTarget();
            }
        }
        return maxAddr;
    }

    public boolean containingAddress(Address target) {
        if (target.getOffset() < address.getOffset())
            return false;
        if (target.getOffset() > getMaxAddress().getOffset())
            return false;
        return true;
    }

    public boolean containingSeqNum(SequenceNumber seqnum) {
        for (PcodeOp op : oplist) {
            if (op.getSeqnum() != null && op.getSeqnum().equals(seqnum))
                return true;
        }
        return false;
    }

    public boolean startsAt(SequenceNumber seqnum) {
        if (oplist.size() == 0)
            return seqnum.getTime() == 0 && seqnum.getTarget().equals(address);
        assert oplist.get(0).getSeqnum() != null;
        return oplist.get(0).getSeqnum().equals(seqnum);
    }

    public boolean startsAt(Address target) {
        return getAddress().equals(target);
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
        int numOps = oplist.size();
        for (int i = opOrder; i < numOps; i++) {
            SequenceNumber opSeqnum = oplist.get(i).getSeqnum();
            if (opSeqnum != null && opSeqnum.getOrder() == opOrder)
                return i;
        }
        return -1;
    }

    public int getOpIdxFromSeqnum(SequenceNumber seqnum) {
        int numOps = oplist.size(), opIdx = -1;
        for (int i = 0; i < numOps; i++) {
            SequenceNumber opSeqnum = oplist.get(i).getSeqnum();
            if (opSeqnum != null && opSeqnum.equals(seqnum)) {
                opIdx = i;
                break;
            }
        }
        return opIdx;
    }

    public int getOpIdxFromAddress(Address splitAddr) {
        return getOpIdxFromSeqnum(new SequenceNumber(splitAddr, 0));
    }

    /// Maybe we should ensure that the splitting is only allowed 
    ///     when the first op of the new block has a no null seqnum. 
    /// That is, we should split by the opOrder rather than the opIdx. 
    public CFGBlock splitAt(int opIdx) {
        int numOps = oplist.size();
        assert opIdx > 0 && opIdx < numOps;
        CFGBlock newBl = new CFGBlock(null, numOps - opIdx);
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
