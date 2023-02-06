package com.gsat.sea;

import java.util.ArrayList;
import java.util.List;

import com.gsat.sea.SoNOp.*;
import com.gsat.sea.analysis.DAGNode;

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

    private SoNNode(int opc, int initUses) {
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

    public String[] getFeatureStrs(int opt) {
        if (opt > 0)
            return new String[] { op.toString() };
        else
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

    public static SoNNode newBaseSoNNodeFromOp(PcodeOp op) {
        int opc = op.getOpcode();
        SoNNode result;
        switch (opc) {
            case PcodeOp.SUBPIECE:
                result = newProject(op.getOutput().getSize());
                break;
            default:
                result = new SoNNode(opc, SoNOp.numDataUseOfPcodeOp(op));
        }
        return result;
    }

    public static SoNNode newStoreOrConst(Varnode varnode) {
        return newStoreOrConst(varnode.getAddress().getAddressSpace(), varnode.getOffset(), varnode.getSize());
    }

    public static SoNNode newStoreOrConst(AddressInterval interval) {
        return newStoreOrConst(interval.getMinAddress().getAddressSpace(),
                interval.getMinAddress().getOffset(), (int) interval.getLength());
    }

    public static SoNNode newStoreOrConst(AddressSpace space, long offset, int size) {
        if (space == GraphFactory.getStoreSpace()) {
            return SoNNode.newMemorySpace(offset); // represents the entire memory space 
        } else if (space.isConstantSpace()) {
            return SoNNode.newConstant(offset, size);
        } else if (space.isRegisterSpace()) {
            return SoNNode.newRegisterStore(offset, size); // one register store
        } else if (space.isMemorySpace()) {
            return SoNNode.newMemoryStore(offset, size); // one memory store
        } else if (space.isStackSpace()) {
            return SoNNode.newStackStore(offset, size); // one stack store
        }
        return SoNNode.newOtherStore(space.getSpaceID(), offset, size);
    }

    public static SoNNode newRegion(PcodeOp last) {
        SoNNode controlNode = null;
        if (last == null)
            controlNode = SoNNode.newBrRegion(0);
        else {
            int opc = last.getOpcode();
            switch (opc) {
                case PcodeOp.CBRANCH:
                    controlNode = SoNNode.newCBrRegion(1);
                    break;
                case PcodeOp.BRANCHIND:
                    controlNode = SoNNode.newBrIndRegion(1);
                    break;
                case PcodeOp.RETURN:
                    controlNode = SoNNode.newReturnRegion(SoNOp.numDataUseOfPcodeOp(last));
                    break;
                default:
                    controlNode = SoNNode.newBrRegion(0);
                    break;
            }
        }
        return controlNode;
    }

    public static SoNNode newEnd() {
        return new SoNNode(new End(), 0);
    }

    public static SoNNode newBrRegion(int numUses) {
        return new SoNNode(new BrRegion(), numUses);
    }

    public static SoNNode newCBrRegion(int numUses) {
        return new SoNNode(new CBrRegion(), numUses);
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

    public static SoNNode newProject(int outSize) {
        BaseOp op = new Project(outSize);
        return new SoNNode(op, 2);
    }

    public static SoNNode newPiece(int numDataUses) {
        return new SoNNode(PcodeOp.PIECE, numDataUses);
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
