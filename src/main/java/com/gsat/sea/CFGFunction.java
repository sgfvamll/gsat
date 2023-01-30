package com.gsat.sea;

import java.util.List;

import ghidra.program.model.address.Address;

import java.util.ArrayList;

public class CFGFunction {
    ArrayList<CFGBlock> blocks;
    int numEntries = 0;

    CFGFunction(int initNumBlocks) {
        blocks = new ArrayList<>(initNumBlocks);
        blocks.add(null);    // Leave for the root block
    }

    private void updateNumEntries(CFGBlock bl) {
        if (bl.getPredecessors().isEmpty()) 
            numEntries += 1;
    }

    public void append(CFGBlock bl) {
        bl.setid(getNumBlocks());
        blocks.add(bl);
        updateNumEntries(bl);
    }

    public void setRoot(CFGBlock bl) {
        bl.setid(0);
        blocks.set(0, bl);
        updateNumEntries(bl);
    }

    public List<CFGBlock> getBlocks() {
        return blocks;
    }

    public int getNumBlocks() {
        return blocks.size();
    }

    /// Some broken CFG has multiple entries. Add a start node to fix it. 
    public void fixMultipleEntries() {
        if (numEntries <= 1) 
            return;
        Address fva = blocks.get(0).getAddress();
        CFGBlock start = new CFGBlock(fva, 0);
        for (var node : blocks) {
            node.setid(node.id()+1);
            if (node.getPredecessors().size() == 0) {
                start.addOut(node);
                node.addIn(start);
            }
        }
        start.setid(0);
        blocks.add(0, start);
        numEntries = 1;
    }
}
