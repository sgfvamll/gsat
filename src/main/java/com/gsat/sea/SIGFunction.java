package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;

public class SIGFunction implements DAGGraph<SIGNode> {
    Address fva;
    boolean rawPcode;
    List<SIGNode> nodes;

    SIGFunction(Address start, Collection<SIGNode> dfgNodes) {
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

    public SIGNode root() {
        return nodes.get(0);
    }

    public Collection<SIGNode> workroots() {
        return nodes;
    }

    public int getNumBlocks() {
        return nodes.size();
    }


}


