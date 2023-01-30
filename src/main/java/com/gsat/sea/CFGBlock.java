package com.gsat.sea;

import java.util.List;

import com.gsat.sea.analysis.DAGNode;

import java.util.Arrays;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class CFGBlock implements DAGNode<CFGBlock> {
    int _id;
    Address address;
    ArrayList<PcodeOp> instructions;
    ArrayList<CFGBlock> cfgIns;
    ArrayList<CFGBlock> cfgOuts;

    CFGBlock(Address nodeStartEa, int speculativeNumInsts) {
        instructions = new ArrayList<>(speculativeNumInsts);
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

    void append(PcodeOp pcodeOp) {
        instructions.add(pcodeOp);
    }

    void addOut(CFGBlock bl) {
        cfgOuts.add(bl);
    }

    void addIn(CFGBlock bl) {
        cfgIns.add(bl);
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
        return instructions;
    }
}
