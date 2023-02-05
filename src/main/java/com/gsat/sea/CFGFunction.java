package com.gsat.sea;

import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.HashSet;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class CFGFunction implements DAGGraph<CFGBlock> {
    Function function;
    List<CFGBlock> blocks;

    CFGFunction(Function func, List<CFGBlock> nodes) {
        function = func;
        blocks = nodes;
    }

    public Address getAddress() {
        return function.getEntryPoint();
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

    public Varnode[] getReturnVarnodes() {
        if (function == null || function.getReturn() == null) 
            return new Varnode[0];
        Parameter outParam = function.getReturn();
        return outParam.getVariableStorage().getVarnodes();
    }

}
