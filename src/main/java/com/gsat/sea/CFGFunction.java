package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;

public class CFGFunction {
    ArrayList<CFGBlock> blocks;

    CFGFunction(int initNumBlocks) {
        blocks = new ArrayList<>(initNumBlocks);
        blocks.add(null);    // Leave for the root block
    }

    public void append(CFGBlock bl) {
        bl.setid(getNumBlocks());
        blocks.add(bl);
    }

    public void setRoot(CFGBlock bl) {
        bl.setid(0);
        blocks.set(0, bl);
    }

    public List<CFGBlock> getBlocks() {
        return blocks;
    }

    public int getNumBlocks() {
        return blocks.size();
    }
}
