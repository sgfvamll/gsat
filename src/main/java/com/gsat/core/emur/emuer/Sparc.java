package com.gsat.core.emur.emuer;

import java.math.BigInteger;
import java.util.List;

import com.gsat.core.emur.BaseEmuer;
import com.gsat.core.emur.LanguageId;

@LanguageId(processor = "sparc",size = 32)
public class Sparc extends BaseEmuer {
    // Up to six parameters3 may be passed by placing them in out registers %o0...%o5;
    // The callee finds its first six parameters in %i0 ... %i5, and the remainder (if any)
    // on the stack.
    // private String[] params = {"i0","i1","i2","i3", "i4", "i5"};
    private String[] params = {"o0","o1","o2","o3", "o4", "o5"};
    private String retReg = "o0";
    // A procedure’s return address, normally the address of the instruction just after
    // the CALL’s delay-slot instruction, is simply calculated as %i7 + 8
    private String retAddrReg = "o7";

    private String syscallReg = "g1";

    @Override
    protected boolean setArgs(List<Long> args) {
        emuHelper.writeRegister(emuHelper.getStackPointerRegister(),0x2FFF0000);
        emuHelper.writeRegister(retAddrReg, -8);
        for (int i=0; i < args.size(); i++) {
            if (i <= params.length - 1) {
                emuHelper.writeRegister(params[i],args.get(i));
            } else {
                try {

                    emuHelper.writeStackValue(4+(i- params.length)*4,4, args.get(i));
                } catch (Exception e) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    protected String getRetRegName() {
        return this.retReg;
    }

    @Override
    protected String getSyscallRegName() {
        return this.syscallReg;
    }

    @Override
    protected boolean checkSendto(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x85));
    }

    @Override
    protected boolean checkRecvfrom(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x7d));
    }
}
