package com.gsat.core.emur.emuer;

import java.math.BigInteger;
import java.util.List;

import com.gsat.core.emur.BaseEmuer;
import com.gsat.core.emur.LanguageId;

@LanguageId(processor = "mips",size = 64)
public class Mips64 extends BaseEmuer {
    private String[] params = {"a0","a1","a2","a3"};
    private String retReg = "v0";
    private String syscallReg = "v0";

    @Override
    protected boolean setArgs(List<Long> args) {
        emuHelper.writeRegister(emuHelper.getStackPointerRegister(),0x2FFF0000);
        for (int i=0; i < args.size(); i++) {
            if (i <= params.length - 1) {
                emuHelper.writeRegister(params[i],args.get(i));
            } else {
                try {
                    emuHelper.writeStackValue(8+(i- params.length)*8,8, args.get(i));
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
        return regValue.equals(BigInteger.valueOf(0x13b3));
    }

    @Override
    protected boolean checkRecvfrom(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x13b4));
    }

    @Override
    protected boolean checkSend(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x13b3));
    }
    
    @Override
    protected boolean checkRecv(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x13b4));
    }
}
