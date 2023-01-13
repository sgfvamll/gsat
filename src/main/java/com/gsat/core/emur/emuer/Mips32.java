package com.gsat.core.emur.emuer;

import java.math.BigInteger;
import java.util.List;

import com.gsat.core.emur.BaseEmuer;
import com.gsat.core.emur.LanguageId;

@LanguageId(processor = "mips",size = 32)
public class Mips32 extends BaseEmuer {
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
    protected boolean checkSendto(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x179b))||regValue.equals(BigInteger.valueOf(0x1054));
    }

    @Override
    protected boolean checkRecvfrom(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x1050))||regValue.equals(BigInteger.valueOf(0x179c));
    }

    @Override
    protected boolean checkSend(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x179b))||regValue.equals(BigInteger.valueOf(0x1054));
    }

    @Override
    protected boolean checkRecv(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x1050))||regValue.equals(BigInteger.valueOf(0x179c));
    }

}
