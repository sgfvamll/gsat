package com.gsat.tools;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.gsat.helper.BaseFinder;
import com.gsat.helper.StringHelper;
import com.gsat.utils.ColoredPrint;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.disassemble.MipsDisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;


public class FindBase extends BaseTool {

    boolean accurateMode = false;

    public FindBase() {
        this.analysisMode = 1;  /// Fast analysis
    }
    
    public static String getName() {
        return "find-base";
    }

    @Override
    Option[] getOptions() {
      return new Option[] {
        new Option("a","accurate",false,"Find in accurate mode (Slow)."),
      };
    }

    @Override
    Boolean processOptions(CommandLine commandLine) {
        accurateMode = commandLine.hasOption("a");
        return true;
    }

    @Override
    public Boolean run() {
        ColoredPrint.info("Creating strings...");
        new StringHelper(program).createMoreString();
        ColoredPrint.info("Disassembling...");
        this.doDisassemble();
        ColoredPrint.info("Finding Base...");
        BaseFinder finder = new BaseFinder(program,accurateMode);
        Long baseOffset = finder.findBase();
        String resultStr = "";
        if (baseOffset != null) {
            resultStr = String.format("base addr is 0x%x",baseOffset);
            int matched = finder.getResultMatched();
            if (finder.isHighConfidence()) {
                resultStr += String.format(" (High Confidence). (%d matched)", matched);
            } else {
                resultStr += String.format(" (MayBe) (%d matched).", matched);
            }
        } else {
            resultStr = "Can't find base addr.";
        }
        System.out.println(resultStr);
        return true;
    }

    private void doDisassemble() {
        System.out.printf("Found %d instructions before disassemble.\n", program.getListing().getNumInstructions());
        //try to createFunction after terminals.
        int pointSize = program.getDefaultPointerSize();
        Long maxOffset = program.getMaxAddress().getOffset();
        int txId = program.startTransaction("findIns");
        try {
            Address currentAddr = program.getMinAddress();
            int failedCount = 0;
            while(currentAddr != null) {
                Instruction currentIns = flatApi.getInstructionAt(currentAddr);
                boolean disasseSuccFlag = false;
                if (currentIns == null) {
                    try {
                        DisassembleCommand cmd = new DisassembleCommand(currentAddr,null,false);
                        cmd.applyTo(program,flatApi.getMonitor());
                        Address maxAddr = cmd.getDisassembledAddressSet().getMaxAddress();
                        if (maxAddr != null) {
                            failedCount = 0;
                            currentAddr = maxAddr;
                            disasseSuccFlag = true;
                        }
                    } catch (Exception e) {
                        //just ignore
                    }
                }
                if (!disasseSuccFlag) {
                    String processor = program.getMetadata().get("Processor").toLowerCase();
                    if (processor.equals("mips")) {
                        /// Try MIPS16l Mode 
                        MipsDisassembleCommand cmd = new MipsDisassembleCommand(currentAddr,null,true);
                        cmd.applyTo(program,flatApi.getMonitor());
                        AddressSet addrSet = cmd.getDisassembledAddressSet();
                        if (addrSet != null && !addrSet.isEmpty()) {
                            AddressRange range = addrSet.getAddressRanges(currentAddr, true).next();
                            failedCount = 0;
                            currentAddr = range.getMaxAddress();
                            disasseSuccFlag = true;
                        }
                    }
                }
                if (disasseSuccFlag) {
                    currentAddr = currentAddr.next();
                } else {
                    try {
                        currentAddr = currentAddr.addNoWrap(pointSize);
                    } catch (AddressOverflowException e) {
                        return;
                    }
                }
                failedCount += 1;

                if (currentAddr.getOffset() > maxOffset || failedCount > 10000) {
                    break;
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }
        System.out.printf("Found %d instructions after disassemble.\n", program.getListing().getNumInstructions());
    }
}
