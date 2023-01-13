package com.gsat.core.emur.emuer;

import java.math.BigInteger;
import java.util.List;

import com.gsat.core.emur.BaseEmuer;
import com.gsat.core.emur.LanguageId;

@LanguageId(processor = "x86",size = 64)
public class X8664 extends BaseEmuer {
    private String[] params = {"rdi","rsi","rdx","rcx","r8","r9"};
    private String retReg = "rax";
    private String syscallReg = "rax";
    private long syscallNumOfSendto = 0x2c;
    private long syscallNumOfRecvfrom = 0x2d;

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
        return regValue.equals(BigInteger.valueOf(syscallNumOfSendto));
    }

    @Override
    protected boolean checkRecv(BigInteger regValue) {
        return regValue.equals(BigInteger.valueOf(syscallNumOfRecvfrom));
    }
}
