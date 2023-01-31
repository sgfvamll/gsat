package com.gsat.sea;

import ghidra.program.model.pcode.PcodeOp;

public class SoNOp {

    public static int numDataUseOfPcodeOp(PcodeOp op) {
        return op.getNumInputs() - dataUseStart(op.getOpcode());
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

    public static class BaseOp {
        private int opcode;

        BaseOp(int opc) {
            opcode = opc;
        }

        public int opcode() {
            return opcode;
        }

        public String mnem() {
            if (opcode >= 0) {
                return PcodeOp.getMnemonic(opcode);
            } else {
                return this.getClass().getSimpleName();
            }
        }
    }

    public static class End extends BaseOp {
        End() {
            super(-1);
        }
    }

    static class ConstantOp<T> extends BaseOp {
        T constant;
        int size;   // byte size of this constant

        ConstantOp(int opc, T c, int size) {
            super(opc);
            this.constant = c;
            this.size = size;
        }
    }

    public static class ConstantLong extends ConstantOp<Long> {
        ConstantLong(Long c, int size) {
            super(-2, c, size);
        }
    }

    public static class ConstantDouble extends ConstantOp<Double> {
        ConstantDouble(Double c, int size) {
            super(-3, c, size);
        }
    }

    public static class MemorySpace extends BaseOp {
        long id;
        MemorySpace(long spaceId) {
            super(-4);
            id = spaceId;
        }
    }

    static class Store extends BaseOp {
        long id;
        int size;
        Store(int opc, long storeId, int storeSize) {
            super(opc);
            id = storeId;
            size = storeSize;
        }
    }

    public static class RegisterStore extends Store {
        RegisterStore(long regId, int storeSize) {
            super(-5, regId, storeSize);
        }
    }

    public static class MemoryStore extends Store {
        MemoryStore(long memId, int storeSize) {
            super(-6, memId, storeSize);
        }
    }

    public static class StackStore extends Store {
        StackStore(long stackId, int storeSize) {
            super(-7, stackId, storeSize);
        }
    }

    public static class OtherStore extends Store {
        long spaceId;
        OtherStore(long spaceId, long stackId, int storeSize) {
            super(-8, stackId, storeSize);
            this.spaceId = spaceId;
        }
    }
    
    public static class Region extends BaseOp {
        Region() {
            super(-9);
        }
        protected Region(int opc) {
            super(opc);
        }
    }

    public static class BrRegion extends Region {
        BrRegion() {
            super(PcodeOp.CBRANCH);
        }
    }

    public static class BrIndRegion extends Region {
        BrIndRegion() {
            super(PcodeOp.BRANCHIND);
        }
    }

    public static class ReturnRegion extends Region {
        ReturnRegion() {
            super(PcodeOp.RETURN);
        }
    }

    public static class Phi extends BaseOp {
        Phi() {
            super(PcodeOp.MULTIEQUAL);
        }
    }
    
}
