package com.gsat.sea;

import java.util.List;

import com.gsat.sea.analysis.DAGNode;

import java.util.Comparator;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class CFGBlock implements DAGNode<CFGBlock> {
    int _id;
    Address address;
    ArrayList<PcodeOp> oplist;
    ArrayList<CFGBlock> cfgIns;
    ArrayList<CFGBlock> cfgOuts;

    public static class IdComparator implements Comparator<CFGBlock> {
        public int compare(CFGBlock o1, CFGBlock o2) {
            return Integer.compare(o1._id, o2._id);
        }
    }

    CFGBlock(Address nodeStartEa, int speculativeNumInsts) {
        oplist = new ArrayList<>(speculativeNumInsts);
        address = nodeStartEa;
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

    public PcodeOp getLastOp() {
        PcodeOp last = null;
        if (oplist.size() > 0)
            last = oplist.get(oplist.size() - 1);
        return last;
    }

    void append(PcodeOp pcodeOp) {
        oplist.add(pcodeOp);
    }

    void addOut(CFGBlock bl) {
        cfgOuts.add(bl);
    }

    void addIn(CFGBlock bl) {
        cfgIns.add(bl);
    }

    boolean removeOut(CFGBlock bl) {
        return cfgOuts.remove(bl);
    }

    boolean removeIn(CFGBlock bl) {
        return cfgIns.remove(bl);
    }

    public Address getAddress() {
        return address;
    }

    public List<CFGBlock> getPredecessors() {
        return cfgIns;
    }

    public List<CFGBlock> getSuccessors() {
        return cfgOuts;
    }

    public List<PcodeOp> getPcodeOps() {
        return oplist;
    }

    public String[] getFeatureStrs() {
        String[] bbMnems = new String[oplist.size()];
        int idx = 0;
        for (PcodeOp pcode : oplist) {
            bbMnems[idx++] = pcode.getMnemonic();
        }
        return bbMnems;
    }
}
