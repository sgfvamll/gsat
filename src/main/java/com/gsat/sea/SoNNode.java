package com.gsat.sea;

import java.util.ArrayList;
import java.util.List;

import com.gsat.sea.SoNOp.*;
import com.gsat.sea.analysis.DAGNode;

import ghidra.dbg.gadp.protocol.Gadp.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SoNNode implements DAGNode<SoNNode> {
    static int idCnt = 0;

    public static void clearIdCount() {
        idCnt = 0;
    }

    private int id;
    private BaseOp op;
    List<SoNNode> uses;

    SoNNode(BaseOp operation, int initUses) {
        id = idCnt++;
        op = operation;
        uses = new ArrayList<>(initUses);
        for (int i = 0; i < initUses; i++)
            uses.add(null);
    }

    SoNNode(int opc, int initUses) {
        // TODO share baseop objects
        this(new BaseOp(opc), initUses);
        assert opc != PcodeOp.MULTIEQUAL;
    }

    public int id() {
        return id;
    }

    public BaseOp op() {
        return op;
    }

    public int opcode() {
        return op.opcode();
    }

    public String mnemonic() {
        return op.mnem();
    }

    public int hashCode() {
        return id;
    }

    public List<SoNNode> getPredecessors() {
        return null;
    }

    public List<SoNNode> getSuccessors() {
        return getUses();
    }

    public String[] getFeatureStrs() {
        return new String[] { mnemonic() };
    }

    public List<SoNNode> getUses() {
        return uses;
    }

    void setUse(int idx, SoNNode inp) {
        uses.set(idx, inp);
    }

    void addUse(SoNNode inp) {
        uses.add(inp);
    }

    public static SoNNode newRegionFromLastOp(PcodeOp last, boolean isReturnBlock) {
        SoNNode controlNode = null;
        if (isReturnBlock)
            return SoNNode.newReturnRegion(0);
        if (last == null)
            controlNode = SoNNode.newRegion(0);
        else {
            int opc = last.getOpcode();
            switch (opc) {
                case PcodeOp.CBRANCH:
                    controlNode = SoNNode.newBrRegion(1);
                    break;
                case PcodeOp.BRANCHIND:
                    controlNode = SoNNode.newBrIndRegion(1);
                    break;
                case PcodeOp.RETURN:
                    assert false;
                    break;
                default:
                    controlNode = SoNNode.newRegion(0);
                    break;
            }
        }
        return controlNode;
    }

    public static SoNNode newEnd() {
        return new SoNNode(new End(), 0);
    }

    public static SoNNode newRegion(int numUses) {
        return new SoNNode(new Region(), numUses);
    }

    public static SoNNode newBrRegion(int numUses) {
        return new SoNNode(new BrRegion(), numUses);
    }

    public static SoNNode newBrIndRegion(int numUses) {
        return new SoNNode(new BrIndRegion(), numUses);
    }

    public static SoNNode newReturnRegion(int numUses) {
        return new SoNNode(new ReturnRegion(), numUses);
    }

    public static SoNNode newPhi(SoNNode region, int numDataUses) {
        SoNNode phi = new SoNNode(new Phi(), 1 + numDataUses);
        phi.setUse(0, region);
        return phi;
    }

    public static SoNNode newMemorySpace(long spaceId) {
        BaseOp op = new MemorySpace(spaceId);
        return new SoNNode(op, 0);
    }

    public static SoNNode newConstant(long c, int size) {
        BaseOp op = new ConstantLong(c, size);
        return new SoNNode(op, 0);
    }

    public static SoNNode newRegisterStore(long c, int size) {
        BaseOp op = new RegisterStore(c, size);
        return new SoNNode(op, 0);
    }

    public static SoNNode newMemoryStore(long c, int size) {
        BaseOp op = new MemoryStore(c, size);
        return new SoNNode(op, 0);
    }

    public static SoNNode newStackStore(long c, int size) {
        BaseOp op = new StackStore(c, size);
        return new SoNNode(op, 0);
    }

    public static SoNNode newOtherStore(long spaceId, long c, int size) {
        BaseOp op = new OtherStore(spaceId, c, size);
        return new SoNNode(op, 0);
    }
}
