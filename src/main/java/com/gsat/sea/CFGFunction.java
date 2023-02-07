package com.gsat.sea;

import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.HashSet;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class CFGFunction implements DAGGraph<CFGBlock> {
    Address fva;
    List<CFGBlock> blocks;

    CFGFunction(Address start, List<CFGBlock> nodes) {
        fva = start;
        blocks = nodes;
    }

    public Address getAddress() {
        return fva;
    }

    public CFGBlock root() {
        return blocks.get(0);
    }

    public List<CFGBlock> getBlocks() {
        return blocks;
    }

    public int getNumBlocks() {
        return blocks.size();
    }

    public TreeMap<Varnode, Set<Integer>> generateDefsites() {
        TreeMap<Varnode, Set<Integer>> defsites = new TreeMap<>(new AddressInterval.VarnodeComparator());
        for (CFGBlock n : blocks) {
            for (PcodeOp op : n.getPcodeOps()) {
                Varnode out = op.getOutput();
                if (out == null)
                    continue; /// no data out
                defsites.computeIfAbsent(out, k -> new HashSet<>()).add(n.id());
            }
        }
        return defsites;
    }

}
