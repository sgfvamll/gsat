package com.gsat.core.emur;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncTestData;


public abstract class BaseEmuer {
    protected EmulatorHelper emuHelper;
    protected Program program;
    protected FlatProgramAPI flatApi;
    protected Function func;
    protected BaseFunc funcInfo;
    protected Address controlledReturnAddr;
    protected boolean send;
    protected boolean recv;
    protected boolean sendto;
    protected boolean recvfrom;


    public void init(Program program,FlatProgramAPI flatApi, Function func,BaseFunc funcInfo) {
        this.program = program;
        this.flatApi = flatApi;
        this.func = func;
        this.funcInfo = funcInfo;
        this.send = false;
        this.recv = false;
        this.sendto = false;
        this.recvfrom = false;
    }

    public Function getFunc() {
        return func;
    }

    protected void initEmuHelper() {
        this.emuHelper = new EmulatorHelper(program);
        emuHelper.writeRegister(emuHelper.getPCRegister(),func.getEntryPoint().getOffset());
    }

    private boolean emulating() {
        TaskMonitor monitor = flatApi.getMonitor();
        int maxCount = 10000;
        int count = 0;
        int depth = 0;
        Set<Long> breakpoint = new HashSet<Long>();
        breakpoint.add(Long.valueOf(0x4E3982));
        breakpoint.add(Long.valueOf(0x4E3928));
        while(!monitor.isCancelled()) {
            count += 1;
            if (count > maxCount) {
                break;
            }
            Address executionAddress = emuHelper.getExecutionAddress();
            
            // BigInteger syscallRegVal =  emuHelper.readRegister(syscallRegName);

//            System.out.printf("0x%x\n",executionAddress.getOffset());
            if (executionAddress.getOffset() == controlledReturnAddr.getOffset()) {
                return true;
            }
            Instruction instruction = program.getListing().getInstructionAt(executionAddress);
                // String mnemonic = instruction.getMnemonicString();
            // if (breakpoint.contains(executionAddress.getOffset())) {
            //     System.out.println("here");
            // }
            if (instruction != null) {
                PcodeOp[] excutionPcodeOps = instruction.getPcode();
                String syscallRegName = getSyscallRegName();
                if (excutionPcodeOps != null&& syscallRegName != null) {
                    for (PcodeOp pcodeOp:excutionPcodeOps) {
                        String mnemonic = pcodeOp.getMnemonic();
                        if (mnemonic.equals("CALL")) {
                            // return true;
                            depth += 1;
                        }
                        if (mnemonic.equals("RETURN")) {
                            depth -= 1;
                        }
                        BigInteger syscallRegValue = emuHelper.readRegister(syscallRegName);
                        if (depth==0 && mnemonic.equals("CALLOTHER") ) {
                            if (checkSendto(syscallRegValue)) {
                                sendto = true;
                            }
                            if (checkRecvfrom(syscallRegValue)) {
                                recvfrom = true;
                            }
                            if (checkSend(syscallRegValue)) {
                                send = true;
                            }
                            if (checkRecv(syscallRegValue)) {
                                recv = true;
                            }
                        }
                    }
                }
            }
            try {
                
                
                boolean success = emuHelper.step(monitor);
                if (!success) {
                    return false;
                }
            } catch (CancelledException e) {
                return false;
            }
        }
        return false;
    }

    protected abstract boolean setArgs(List<Long> args);

    protected boolean preSetMem(Map<Long, byte[]> memConf) {
        for (Map.Entry<Long,byte[]> item:memConf.entrySet()) {
            emuHelper.writeMemory(flatApi.toAddr(item.getKey()),item.getValue());
        }
        return true;
    }

    protected boolean checkConditions(Map<Long, byte[]> conditions) {
        for (Map.Entry<Long,byte[]> item:conditions.entrySet()) {
            byte[] res = emuHelper.readMemory(flatApi.toAddr(item.getKey()),item.getValue().length);
            if (!Arrays.equals(res,item.getValue())) {
                return false;
            }
        }
        return true;
    }

    protected abstract String getRetRegName();

    protected long getSyscallNumOfSendto() {
        return -1;
    }

    protected long getSyscallNumOfRecvfrom() {
        return -1;
    }

    protected String getSyscallRegName() {
        return null;
    }

    protected boolean checkSendto(BigInteger regValue) {
        return false;
    }

    protected boolean checkRecvfrom(BigInteger regValue) {
        return false;
    }

    protected boolean checkSend(BigInteger regValue) {
        return false;
    }
    
    protected boolean checkRecv(BigInteger regValue) {
        return false;
    }

    protected boolean checkRet(byte[] expectedVal) {
        BigInteger bigInt = emuHelper.readRegister(getRetRegName());
//        System.out.println(Arrays.toString(bigInt.toByteArray()));
        BigInteger expectedBigInt = new BigInteger(expectedVal);
        if (bigInt.equals(expectedBigInt)) {
            return true;
        }
        return false;
    }

    protected void setRetAddr(long retAddr) {
        this.controlledReturnAddr = flatApi.toAddr(retAddr);
    }

    public boolean doEmulate() {
        if (funcInfo.getTests() == null) {
            return true;
        }
        for (FuncTestData testData:funcInfo.getTests()) {
            initEmuHelper();
            funcInfo.setEmuHelper(emuHelper);
            funcInfo.setProgram(program);
            try {
                setRetAddr(testData.getControlledRetAddr());
                List<Long> args = testData.getArguments();
                if (args != null) {
                    boolean setRes = setArgs(args);
                    if (!setRes) {
                        return false;
                    }
                }
                Map<Long,byte[]> memPreset = testData.getPresetMem();
                if (memPreset != null) {
                    boolean setMemRes = preSetMem(memPreset);
                    if (!setMemRes) {
                        return false;
                    }
                }
                boolean emuRes = emulating();
                if (funcInfo.getFuncName().equals("sendto") ) {
                    return sendto;
                }
                if (funcInfo.getFuncName().equals("recvfrom") ) {
                    return recvfrom;
                }
                if (funcInfo.getFuncName().equals("send") ) {
                    return send;
                }
                if (funcInfo.getFuncName().equals("recv") ) {
                    return recv;
                }
                if (!emuRes) {
                    return false;
                }

                Map<Long,byte[]> conditions = testData.getConditions();
                if (conditions != null) {
                    boolean checkRes = checkConditions(conditions);
                    if (!checkRes) {
                        return false;
                    }
                }
                byte[] retVal = testData.getRetVal();
                if (retVal != null) {
                    boolean retRes = checkRet(retVal);
                    if (!retRes) {
                        return false;
                    }
                }
                Method[] methods = funcInfo.getClass().getMethods();
                for(Method method:methods) {
                    if (method.getName().startsWith("customCheck")) {
                        try {
                            boolean checkRes = (Boolean) method.invoke(funcInfo, this);
                            if (!checkRes) {
                                return false;
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            return false;
                        }
                    }
                }
            } finally {
                emuHelper.dispose();
            }
        }
        return true;
    }
}
