package com.gsat.sea;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.gsat.sea.SoNOp.*;
import com.gsat.sea.analysis.DAGNode;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SoNNode implements DAGNode<SoNNode> {
    static int idCnt = 0;
    static final int nUsesType = 4;

    public static void clearIdCount() {
        idCnt = 0;
    }

    private int id;
    private int[] numUsesPerType; // 0-data, 1-control, 2-memory effect, 3-other effect
    private BaseOp op; // op is allowed to be shared by multiple nodes and should be immutable. 
    List<SoNNode> uses;

    public SoNNode(BaseOp operation, int initUses) {
        id = idCnt++;
        op = operation;
        uses = new ArrayList<>(initUses);
        for (int i = 0; i < initUses; i++)
            uses.add(null);
        numUsesPerType = new int[nUsesType];
        Arrays.fill(numUsesPerType, 0);
        numUsesPerType[0] = initUses;
    }

    public SoNNode(SoNNode node) {
        this(node.op, node.uses.size());
        for (int i = 0; i < node.uses.size(); i++)
            uses.set(i, node.uses.get(i));
        int nUsesTypes = node.numUsesPerType.length;
        numUsesPerType = new int[nUsesType];
        for (int i = 0; i < nUsesTypes; i++)
            numUsesPerType[i] = node.numUsesPerType[i];
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

    public int getEdgeType(int predSlot) {
        for (int i = 0; i < numUsesPerType.length; i++) {
            if (predSlot < numUsesPerType[i])
                return i + 1;
            predSlot -= numUsesPerType[i];
        }
        return 0;
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

    void addUse(int type, SoNNode inp) {
        assert type < nUsesType && type >= 0;
        int insertAt = 0;
        for (int i = 0; i <= type; i++)
            insertAt += numUsesPerType[i];
        uses.add(insertAt, inp);
        numUsesPerType[type] += 1;
    }

    void addDataUse(SoNNode inp) {
        addUse(0, inp);
    }

    void addControlUse(SoNNode inp) {
        addUse(1, inp);
    }

    void addMemoryEffectUse(SoNNode inp) {
        addUse(2, inp);
    }

    void addOtherEffectUse(SoNNode inp) {
        addUse(3, inp);
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

    public static SoNNode newPhi(SoNNode region, int numUses, int type) {
        int numDataUses = 1 + (type != 0 ? 0 : numUses);
        int numEffectUses = type != 0 ? numUses : 0;
        SoNNode phi = new SoNNode(new Phi(), numDataUses);
        phi.setUse(0, region);
        for (int i = 0; i < numEffectUses; i++)
            phi.addUse(type, null);
        return phi;
    }

    public static SoNNode newProject(int outSize) {
        BaseOp op = new Project(outSize);
        return new SoNNode(op, 2);
    }

    public static SoNNode newProject(SoNNode input, int outSize, long offset) {
        SoNNode project = SoNNode.newProject(outSize);
        project.setUse(0, input);
        project.setUse(1, SoNNode.newConstant(offset, 8));
        return project;
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
