package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import com.gsat.sea.analysis.DAGNode;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class TSCGNode implements DAGNode<TSCGNode> {
    static int gid;
    int _id;
    PcodeOp op;
    Varnode varnode;
    List<TSCGNode> uses;
    private int[] numUsesPerType; // 0-data, 1-control, 2-memory effect, 3-other effect

    static void clearIdCount() {
        gid = 0;
    }

    TSCGNode(PcodeOp op, Varnode varnode) {
        this._id = gid++;
        this.op = op;
        this.varnode = varnode;
        uses = new ArrayList<>();
        numUsesPerType = new int[SOGNode.nUsesType];
        Arrays.fill(numUsesPerType, 0);
    }

    TSCGNode(PcodeOp op) {
        this(op, null);
    }

    TSCGNode(Varnode varnode) {
        this(null, varnode);
    }

    public int id() {
        return _id;
    }

    public int hashCode() {
        return _id;
    }

    void addUse(int type, TSCGNode inp) {
        assert type < SOGNode.nUsesType && type >= 0;
        int insertAt = 0;
        for (int i = 0; i <= type; i++)
            insertAt += numUsesPerType[i];
        uses.add(insertAt, inp);
        numUsesPerType[type] += 1;
    }

    public String[] getFeatureStrs(int opt) {
        if (op != null)
            return new String[] { op.getMnemonic() };
        else
            return new String[] { varnode.toString() };
    }

    public int getEdgeType(int predSlot) {
        for (int i = 0; i < numUsesPerType.length; i++) {
            if (predSlot < numUsesPerType[i])
                return i + 1;
            predSlot -= numUsesPerType[i];
        }
        return 0;
    }

    public List<TSCGNode> getPredecessors() {
        return null;
    }

    public List<TSCGNode> getSuccessors() {
        return uses;
    }
}
