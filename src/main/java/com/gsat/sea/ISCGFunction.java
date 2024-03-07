package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;

public class ISCGFunction implements DAGGraph<ISCGNode> {
    Address fva;
    boolean rawPcode;
    List<ISCGNode> nodes;

    ISCGFunction(Address start, Collection<ISCGNode> dfgNodes) {
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

    public ISCGNode root() {
        return nodes.get(0);
    }

    public Collection<ISCGNode> workroots() {
        return nodes;
    }

    public int getNumBlocks() {
        return nodes.size();
    }


}


