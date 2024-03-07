package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;

public class TSCGFunction implements DAGGraph<TSCGNode> {
    Address fva;
    boolean rawPcode;
    List<TSCGNode> nodes;

    TSCGFunction(Address start, Collection<TSCGNode> dfgNodes) {
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

    public TSCGNode root() {
        return nodes.get(0);
    }

    public Collection<TSCGNode> workroots() {
        return nodes;
    }

    public int getNumBlocks() {
        return nodes.size();
    }


}


