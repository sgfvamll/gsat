package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;

public class DFGFunction implements DAGGraph<DFGNode> {
    Address fva;
    boolean rawPcode;
    List<DFGNode> nodes;

    DFGFunction(Address start, Collection<DFGNode> dfgNodes) {
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

    public DFGNode root() {
        return nodes.get(0);
    }

    public Collection<DFGNode> workroots() {
        return nodes;
    }

    public int getNumBlocks() {
        return nodes.size();
    }


}


