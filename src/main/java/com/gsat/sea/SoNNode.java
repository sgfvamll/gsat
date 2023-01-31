package com.gsat.sea;

import java.util.ArrayList;
import java.util.List;

import com.gsat.sea.Operations.*;

import ghidra.dbg.gadp.protocol.Gadp.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SoNNode {
    static long idCnt = 0;

    public static void clearIdCount() {
        idCnt = 0;
    }

    private long id;
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

    public long id() {
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

    public List<SoNNode> getUses() {
        return uses;
    }

    void setUse(int idx, SoNNode inp) {
        uses.set(idx, inp);
    }

    void addUse(SoNNode inp) {
        uses.add(inp);
    }

    public static boolean isCall(int opc) {
        return opc == PcodeOp.CALL || opc == PcodeOp.CALLIND || opc == PcodeOp.CALLOTHER;
    }

    public static boolean hasEffect(int opc) {
        return isCall(opc) || opc == PcodeOp.STORE;
    }

    /// Check if this opcode ends a basic block
    public static boolean isBlockEndControl(int opc) {
        return (opc == PcodeOp.BRANCH) || (opc == PcodeOp.CBRANCH)
                || (opc == PcodeOp.BRANCHIND) || (opc == PcodeOp.RETURN);
    }

    public static int dataUseStart(int opc) {
        switch (opc) {
            case PcodeOp.BRANCH:
            case PcodeOp.CBRANCH:
            case PcodeOp.MULTIEQUAL:
            case PcodeOp.RETURN:
                return 1;
            default:
                return 0;
        }
    }

    public static int numDataUseFromOp(PcodeOp op) {
        return op.getNumInputs() - dataUseStart(op.getOpcode());
    }

    public static SoNNode newRegionFromLastOp(PcodeOp last, boolean isReturnBlock) {
        SoNNode controlNode = null;
        if (isReturnBlock)
            return SoNNode.newReturnRegion(1);
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
                    controlNode = SoNNode.newReturnRegion(1);
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