package com.gsat.sea;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.gsat.sea.SOGOp.*;
import com.gsat.sea.analysis.DAGNode;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SOGNode implements DAGNode<SOGNode> {
    static int idCnt = 0;
    static final int nUsesType = 4;

    public static void clearIdCount() {
        idCnt = 0;
    }

    private int id;
    private int[] numUsesPerType; // 0-data, 1-control, 2-memory effect, 3-other effect
    private BaseOp op; // op is allowed to be shared by multiple nodes and should be immutable. 
    List<SOGNode> uses;
    List<PcodeOp> definedOps; // Pcode ops that define this node. 
    Varnode definedNode = null;

    public SOGNode(BaseOp operation, int initUses) {
        id = idCnt++;
        op = operation;
        uses = new ArrayList<>(initUses);
        for (int i = 0; i < initUses; i++)
            uses.add(null);
        numUsesPerType = new int[nUsesType];
        Arrays.fill(numUsesPerType, 0);
        numUsesPerType[0] = initUses;
        definedOps = new ArrayList<>();
    }

    public SOGNode(SOGNode node) {
        this(node.op, node.uses.size());
        for (int i = 0; i < node.uses.size(); i++)
            uses.set(i, node.uses.get(i));
        int nUsesTypes = node.numUsesPerType.length;
        numUsesPerType = new int[nUsesType];
        for (int i = 0; i < nUsesTypes; i++)
            numUsesPerType[i] = node.numUsesPerType[i];
        definedOps.addAll(node.definedOps);
        definedNode = node.definedNode;
    }

    private SOGNode(int opc, int initUses) {
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

    public List<SOGNode> getPredecessors() {
        return null;
    }

    public List<SOGNode> getSuccessors() {
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

    public void addDefinedOp(PcodeOp op) {
        definedOps.add(op);
    }

    public List<PcodeOp> getDefinedOps() {
        return definedOps;
    }

    public Varnode getDefinedVarnode() {
        return definedNode;
    }

    public List<SOGNode> getUses() {
        return uses;
    }

    public List<SOGNode> getDataUses() {
        return uses.subList(0, numUsesPerType[0]);
    }

    void setUse(int idx, SOGNode inp) {
        uses.set(idx, inp);
    }

    void setPhiUse(int idx, SOGNode inp) {
        if (numDataUses() == 0) 
            // effect phi, skip the region input.  
            idx += 1;   
        uses.set(idx, inp);
    }

    void addUse(int type, SOGNode inp) {
        assert type < nUsesType && type >= 0;
        int insertAt = 0;
        for (int i = 0; i <= type; i++)
            insertAt += numUsesPerType[i];
        uses.add(insertAt, inp);
        numUsesPerType[type] += 1;
    }

    int numUses() {
        return uses.size();
    }

    int numDataUses() {
        return numUsesPerType[0];
    }

    void addDataUse(SOGNode inp) {
        addUse(0, inp);
    }

    void addControlUse(SOGNode inp) {
        addUse(1, inp);
    }

    void addMemoryEffectUse(SOGNode inp) {
        addUse(2, inp);
    }

    void addOtherEffectUse(SOGNode inp) {
        addUse(3, inp);
    }

    public static SOGNode newSOGNodeFromOp(PcodeOp op) {
        int opc = op.getOpcode();
        SOGNode result;
        switch (opc) {
            case PcodeOp.SUBPIECE:
                result = newProject(op.getOutput().getSize());
                break;
            case PcodeOp.INDIRECT:
                result = new SOGNode(opc, 1);
                break;
            default:
                result = new SOGNode(opc, SOGOp.numDataUseOfPcodeOp(op));
        }
        result.definedOps.add(op);
        result.definedNode = op.getOutput();
        return result;
    }

    public static SOGNode newStoreOrConst(Varnode varnode) {
        return newStoreOrConst(varnode.getAddress().getAddressSpace(), varnode.getOffset(), varnode.getSize());
    }

    public static SOGNode newStoreOrConst(AddressInterval interval) {
        return newStoreOrConst(interval.getMinAddress().getAddressSpace(),
                interval.getMinAddress().getOffset(), (int) interval.getLength());
    }

    public static SOGNode newStoreOrConst(AddressSpace space, long offset, int size) {
        SOGNode result;
        if (space == GraphFactory.getStoreSpace()) {
            result = SOGNode.newMemorySpace(offset); // represents the entire memory space 
        } else if (space.isConstantSpace()) {
            result = SOGNode.newConstant(offset, size);
        } else if (space.isRegisterSpace()) {
            result = SOGNode.newRegisterStore(offset, size); // one register store
        } else if (space.isMemorySpace()) {
            result = SOGNode.newMemoryStore(offset, size); // one memory store
        } else if (space.isStackSpace()) {
            result = SOGNode.newStackStore(offset, size); // one stack store
        } else {
            result = SOGNode.newOtherStore(space.getSpaceID(), offset, size);
        }
        result.definedNode = new Varnode(space.getAddress(offset), size);
        return result;
    }

    public static SOGNode newRegion(PcodeOp last) {
        SOGNode controlNode = null;
        if (last == null)
            controlNode = SOGNode.newBrRegion(0);
        else {
            int opc = last.getOpcode();
            switch (opc) {
                case PcodeOp.CBRANCH:
                    controlNode = SOGNode.newCBrRegion(1);
                    break;
                case PcodeOp.BRANCHIND:
                    controlNode = SOGNode.newBrIndRegion(1);
                    break;
                case PcodeOp.RETURN:
                    controlNode = SOGNode.newReturnRegion(SOGOp.numDataUseOfPcodeOp(last));
                    break;
                default:
                    controlNode = SOGNode.newBrRegion(0);
                    break;
            }
            controlNode.definedOps.add(last);
        }
        return controlNode;
    }

    public static SOGNode newEnd() {
        return new SOGNode(new End(), 0);
    }

    public static SOGNode newBrRegion(int numUses) {
        return new SOGNode(new BrRegion(), numUses);
    }

    public static SOGNode newCBrRegion(int numUses) {
        return new SOGNode(new CBrRegion(), numUses);
    }

    public static SOGNode newBrIndRegion(int numUses) {
        return new SOGNode(new BrIndRegion(), numUses);
    }

    public static SOGNode newReturnRegion(int numUses) {
        return new SOGNode(new ReturnRegion(), numUses);
    }

    public static SOGNode newPhi(SOGNode region, PcodeOp op, int type) {
        SOGNode phi = newPhi(region, op.getOutput(), op.getNumInputs(), type);
        phi.definedOps.add(op);
        return phi;
    }

    public static SOGNode newPhi(SOGNode region, Varnode defined, int numUses, int type) {
        assert defined != null && region != null;
        int numDataUses = type != 0 ? 0 : numUses;
        int numEffectUses = type != 0 ? numUses : 0;
        SOGNode phi = new SOGNode(new Phi(), numDataUses);
        phi.addControlUse(region);
        for (int i = 0; i < numEffectUses; i++)
            phi.addUse(type, null);
        phi.definedNode = defined;
        return phi;
    }

    public static SOGNode newProject(int outSize) {
        BaseOp op = new Project(outSize);
        return new SOGNode(op, 2);
    }

    public static SOGNode newProject(SOGNode input, int outSize, long offset, Varnode defined) {
        SOGNode project = SOGNode.newProject(outSize);
        project.setUse(0, input);
        project.setUse(1, SOGNode.newConstant(offset, 8));
        project.definedNode = defined;
        return project;
    }

    public static SOGNode newControlProject(SOGNode input, long offset) {
        SOGNode project = new SOGNode(new Project(0), 0);
        project.addControlUse(input);
        project.addControlUse(SOGNode.newConstant(offset, 8));
        return project;
    }

    public static SOGNode newPiece(int numDataUses, Varnode defined) {
        SOGNode r = new SOGNode(PcodeOp.PIECE, numDataUses);
        r.definedNode = defined;
        return r;
    }

    public static SOGNode newMemorySpace(long spaceId) {
        BaseOp op = new MemorySpace(spaceId);
        return new SOGNode(op, 0);
    }

    public static SOGNode newConstant(long c, int size) {
        BaseOp op = new ConstantLong(c, size);
        return new SOGNode(op, 0);
    }

    public static SOGNode newRegisterStore(long c, int size) {
        BaseOp op = new RegisterStore(c, size);
        return new SOGNode(op, 0);
    }

    public static SOGNode newMemoryStore(long c, int size) {
        BaseOp op = new MemoryStore(c, size);
        return new SOGNode(op, 0);
    }

    public static SOGNode newStackStore(long c, int size) {
        BaseOp op = new StackStore(c, size);
        return new SOGNode(op, 0);
    }

    public static SOGNode newOtherStore(long spaceId, long c, int size) {
        BaseOp op = new OtherStore(spaceId, c, size);
        return new SOGNode(op, 0);
    }
}
