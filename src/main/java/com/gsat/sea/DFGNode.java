package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;

import com.gsat.sea.analysis.DAGNode;
import ghidra.program.model.pcode.PcodeOp;

public class DFGNode implements DAGNode<DFGNode>  {
    static int gid;
    int _id;
    PcodeOp op;
    List<DFGNode> uses;

    static void clearIdCount() {
        gid = 0;
    }

    DFGNode(PcodeOp op) {
        this._id = gid++;
        this.op = op;
        uses = new ArrayList<>();
    }

    public int id() {
        return _id;
    }

    public int hashCode() {
        return _id;
    }

    public void addUse(DFGNode use) {
        uses.add(use);
    }

    public String[] getFeatureStrs(int opt) {
        if (opt > 0)
            return new String[] { op.toString() };
        else
            return new String[] { op.getMnemonic() };
    }

    public int getEdgeType(int predSlot) {
        return 1;
    }

    public List<DFGNode> getPredecessors() {
        return null;
    }

    public List<DFGNode> getSuccessors() {
        return uses;
    }
}
