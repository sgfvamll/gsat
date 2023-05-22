package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;

public class STGFunction implements DAGGraph<STGNode> {
    Address fva;
    boolean rawPcode;
    List<STGNode> nodes;

    STGFunction(Address start, Collection<STGNode> dfgNodes) {
        fva = start;
        nodes = new ArrayList<>();
        nodes.addAll(dfgNodes);
    }

    public Address getAddress() {
        return fva;
    }

    public boolean useRawPcode() {
        return rawPcode;
    }

    public STGNode root() {
        return nodes.get(0);
    }

    public Collection<STGNode> workroots() {
        return nodes;
    }

    public int getNumBlocks() {
        return nodes.size();
    }


}


