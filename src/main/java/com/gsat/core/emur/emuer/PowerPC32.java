package com.gsat.core.emur.emuer;

import java.math.BigInteger;
import java.util.List;

import com.gsat.core.emur.BaseEmuer;
import com.gsat.core.emur.LanguageId;

@LanguageId(processor = "powerpc",size = 32)
public class PowerPC32 extends BaseEmuer {
    private String[] params = {"r3","r4","r5","r6","r7","r8","r9","r10"};
    private String retReg = "r3";
    private String syscallReg = "r0";
    private long syscallNumOfSendto = 0x14f;
    private long syscallNumOfRecvfrom = 0x151;

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
    protected String getSyscallRegName() {
        return this.syscallReg;
    }

    @Override
    protected long getSyscallNumOfSendto() {
        return this.syscallNumOfSendto;
    }

    @Override
    protected long getSyscallNumOfRecvfrom() {
        return this.syscallNumOfRecvfrom;
    }

    @Override
    protected boolean checkSendto(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(syscallNumOfSendto));
    }

    @Override
    protected boolean checkRecvfrom(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(syscallNumOfRecvfrom));
    }

    @Override
    protected boolean checkSend(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x14e));
    }

    @Override
    protected boolean checkRecv(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(0x150));
    }

}
