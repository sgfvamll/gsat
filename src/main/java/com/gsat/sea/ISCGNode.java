package com.gsat.sea;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import com.gsat.sea.analysis.DAGNode;
import ghidra.program.model.pcode.PcodeOp;

public class ISCGNode implements DAGNode<ISCGNode>  {
    static int gid;
    int _id;
    PcodeOp op;
    List<ISCGNode> uses;
    private int[] numUsesPerType; // 0-data, 1-control, 2-memory effect, 3-other effect

    static void clearIdCount() {
        gid = 0;
    }

    ISCGNode(PcodeOp op) {
        this._id = gid++;
        this.op = op;
        uses = new ArrayList<>();
        numUsesPerType = new int[SOGNode.nUsesType];
        Arrays.fill(numUsesPerType, 0);
    }

    public int id() {
        return _id;
    }

    public int hashCode() {
        return _id;
    }

    void addUse(int type, ISCGNode inp) {
        assert type < SOGNode.nUsesType && type >= 0;
        int insertAt = 0;
        for (int i = 0; i <= type; i++)
            insertAt += numUsesPerType[i];
        uses.add(insertAt, inp);
        numUsesPerType[type] += 1;
    }

    public String[] getFeatureStrs(int opt) {
        if (opt > 0)
            return new String[] { op.toString() };
        else
            return new String[] { op.getMnemonic() };
    }

    public int getEdgeType(int predSlot) {
        for (int i = 0; i < numUsesPerType.length; i++) {
            if (predSlot < numUsesPerType[i])
                return i + 1;
            predSlot -= numUsesPerType[i];
        }
        return 0;
    }

    public List<ISCGNode> getPredecessors() {
        return null;
    }

    public List<ISCGNode> getSuccessors() {
        return uses;
    }
}
