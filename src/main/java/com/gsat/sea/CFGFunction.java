package com.gsat.sea;

import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.Collection;
import java.util.HashSet;

import com.gsat.sea.analysis.DAGGraph;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class CFGFunction implements DAGGraph<CFGBlock> {
    Address fva;
    int pcodeLevel;    // 0<-raw, 1<-firstpass, 2<-normalize
    List<CFGBlock> blocks;
    HighFunction hfunc;

    CFGFunction(Address start, List<CFGBlock> nodes, int usedPcodeLevel, HighFunction thisHfunc) {
        fva = start;
        blocks = nodes;
        pcodeLevel = usedPcodeLevel;
        hfunc = thisHfunc;
    }

    public Address getAddress() {
        return fva;
    }

    public HighFunction getHighFunc() {
        return hfunc;
    }

    public boolean useRawPcode() {
        return pcodeLevel == 0;
    }

    public String pcodeLevel() {
        switch(pcodeLevel) {
            case 0: return "raw";
            case 1: return "firstpass";
            case 2: return "normalize";
            default:
                assert false; 
                return "unknown";
        }
    }

    public CFGBlock root() {
        return blocks.get(0);
    }

    public Collection<CFGBlock> workroots() {
        return blocks;
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
