package com.gsat.helper;

import java.util.*;

import com.gsat.utils.ColoredPrint;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.lang.ParamEntry;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import me.tongfei.progressbar.ProgressBar;

public class AnalysisHelper {
    private static int analysisTimeout = 1200; // seconds 

    public static Varnode varnodeFromParamEntry(ParamEntry param) {
        return new Varnode(param.getSpace().getAddress(param.getAddressBase()), param.getSize());
    }

    public static void disableSlowAnalysis(Program program) {
        int txId = program.startTransaction("OptionChanged-disableSlowAnalysis");
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        options.setBoolean("Decompiler Switch Analysis", false);
        options.setBoolean("Stack", false);
        // // Somethings extremely slow for MIPS firmwares. There may be some bugs in ClearFlowAndRepairCmd 
        options.setBoolean("Non-Returning Functions - Discovered.Repair Flow Damage", false);
        program.endTransaction(txId, true);
        disableConstantReferenceAnalysis(program);
    }

    public static void disableConstantReferenceAnalysis(Program program) {
        int txId = program.startTransaction("OptionChanged-disableConstantReferenceAnalysis");
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        options.setBoolean("MIPS Constant Reference Analyzer", false);
        options.setBoolean("ARM Constant Reference Analyzer", false);
        options.setBoolean("x86 Constant Reference Analyzer", false);
        program.endTransaction(txId, true);
    }

    public static void enableAutoAnalysisManger(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

        /// Print all analysis for debug
        List<Analyzer> analyzers = ClassSearcher.getInstances(Analyzer.class);
        String all_analyzers = "";
        for (var analyzer : analyzers) {
            Boolean isAvaiable = mgr.getAnalyzer(analyzer.getName()) != null;
            if (isAvaiable) {
                all_analyzers += "- " + analyzer.getName() + ", " + analyzer.getDescription() + ", \n";
            }
        }
        ColoredPrint.info("Enabled Analysis: \n%s", all_analyzers);

        int txId = program.startTransaction("OptionChanged-dwarf");
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        options.setBoolean("DWARF.Import Data Types", true);
        options.setBoolean("DWARF.Preload All DIEs", true);
        options.setBoolean("DWARF.Import Functions", true);
        options.setBoolean("DWARF.Create Function Signatures", true);
        program.endTransaction(txId, true);

        // disableConstantReferenceAnalysis(program);
        // int txId = program.startTransaction("OptionChanged-enableSomeAnalysis");
        // Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        // options.setBoolean("Shared Return Calls", true);
        // program.endTransaction(txId, true);

        // try {
        //     BufferedWriter out = new BufferedWriter(new FileWriter("all_analyzers.txt"));
        //     out.write(all_analyzers);
        //     out.close();
        // } catch (Exception e) {
        //     e.printStackTrace();
        // }
    }

    public static boolean autoAnalyzeProgram(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();
        mgr.reAnalyzeAll(null);
        boolean succ = true;
        // Start a new transaction in order to make changes to this domain object.
        int txId = program.startTransaction("Analysis");
        try {
            TimedTaskMonitor timedMonitor = new TimedTaskMonitor(analysisTimeout);
            // mgr.startAnalysis(new ConsoleTaskMonitor());
            mgr.startAnalysis(timedMonitor);
            if (timedMonitor.isCancelled()) {
                succ = false;
                ColoredPrint.warning("Analysis Timeout. Current Timeout: %d s", analysisTimeout);
            } else {
                GhidraProgramUtilities.setAnalyzedFlag(program, true);
                // Timer should be explicitly cancelled. Otherwise, it will prevent the program to continue. 
                timedMonitor.timer.cancel();
            }
        } finally {
            program.endTransaction(txId, true);
        }
        return succ;
    }

    // Decompiler Parameter ID
    public static void doDecompilerParameterIDAnalysis(Program program) {
        ColoredPrint.info("Trying to decompile parameter ID. ");
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        int txId = program.startTransaction("Analysis");
        try {
            Analyzer analyzer = mgr.getAnalyzer("Decompiler Parameter ID");
            AddressSetView programAddressSetView = (AddressSetView) program.getMemory();
            mgr.scheduleOneTimeAnalysis(analyzer, programAddressSetView);
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY);
        } finally {
            program.endTransaction(txId, true);
        }
    }

    public static void doAggressiveInstructionFinder(Program program) {
        ColoredPrint.info("Trying to recover more instructions. ");
        long orgInstructionCount = program.getListing().getNumInstructions();
        long orgFunctionCount = program.getFunctionManager().getFunctionCount();
        long entriesCount = 0;

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        int txId = program.startTransaction("Analysis");
        try {
            Analyzer analyzer = mgr.getAnalyzer("Aggressive Instruction Finder");
            AddressSetView programAddressSetView = (AddressSetView) program.getMemory();
            mgr.scheduleOneTimeAnalysis(analyzer, programAddressSetView);
            var monitor = new AggressiveInstructionFinderTaskMonitor();
            mgr.waitForAnalysis(null, monitor);

            var entries = monitor.getEntries();
            entriesCount = entries.size();
            for (var entryStr : entries) {
                try {
                    var entry = programAddressSetView.getMinAddress().getAddress(entryStr);
                    mgr.createFunction(entry, false);
                } catch (Exception e) {
                    ColoredPrint.warning("Creating function at %s failed. ", entryStr);
                    ColoredPrint.warning(e.toString());
                    e.printStackTrace();
                }
            }
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY);
        } finally {
            program.endTransaction(txId, true);
        }

        ColoredPrint.info("Recover %d instructions. ", program.getListing().getNumInstructions() - orgInstructionCount);
        ColoredPrint.info("Recover %d entries. ", entriesCount);
        ColoredPrint.info("Recover %d functions. ", program.getFunctionManager().getFunctionCount() - orgFunctionCount);
    }

    public static boolean rebaseProgram(Program program, Address newBase) {
        int txId = program.startTransaction("Rebase");
        boolean succ = true;
        try {
            program.setImageBase(newBase, false);
        } catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException e) {
            e.printStackTrace();
            ColoredPrint.error("Setting Image Base Failed. New Base: {%x}, Old Base: {%x}. ", newBase.getOffset(),
                    program.getImageBase().getOffset());
            succ = false;
        }
        program.endTransaction(txId, succ);
        return succ;
    }

    public static void disasmBody(Program program, AddressSetView body, boolean enableAnalysis) {
        /// Create function if not valid. 
        int txId = program.startTransaction("CreateFunction");
        AddressSetView toBeDecompiled = body;
        while (true) {
            DisassembleCommand cmd = new DisassembleCommand(toBeDecompiled, toBeDecompiled, true);
            cmd.enableCodeAnalysis(enableAnalysis);
            cmd.applyTo(program, TaskMonitor.DUMMY);
            AddressSetView decompiled = cmd.getDisassembledAddressSet();
            toBeDecompiled = toBeDecompiled.subtract(decompiled);
            if (toBeDecompiled.isEmpty() || decompiled.isEmpty())
                break;
        }
        program.endTransaction(txId, true);
    }

    public static void recoverMoreFunctions(Program program) {
        ColoredPrint.info(
                String.format("Found %d functions. ", program.getFunctionManager().getFunctionCount()));
        ColoredPrint.info("Trying to recover more functions. ");
        FlatProgramAPI flatApi = new FlatProgramAPI(program);
        InstructionIterator instIter = program.getListing().getInstructions(true);
        int createCount = 0;
        boolean first = true;
        while (instIter.hasNext() && !flatApi.getMonitor().isCancelled()) {
            Instruction instruction = instIter.next();
            // Try finding an instruction that is not in any function after terminal
            // instructions or unconditional jumps.
            if (!first && !instruction.getFlowType().isTerminal()
                    && !(instruction.getFlowType() == FlowType.UNCONDITIONAL_JUMP)) {
                continue;
            }
            // Skip instructions in delay slots.
            for (int i = 0; i < instruction.getDelaySlotDepth(); i += 1) {
                instruction = program.getListing().getInstructionAfter(instruction.getMaxAddress());
            }
            Instruction funcBeginInstr;
            if (first) {
                first = false;
                funcBeginInstr = instruction;
            } else {
                funcBeginInstr = program.getListing().getInstructionAfter(instruction.getMaxAddress());
            }
            if (funcBeginInstr == null) {
                continue;
            }
            Address funcAddr = funcBeginInstr.getAddress();
            Function func = program.getFunctionManager().getFunctionContaining(funcAddr);
            if (func != null) {
                continue;
            }

            // Get code block entry for this address (which is more likely to be a function
            // entry).
            PartitionCodeSubModel partitionBlockModel = new PartitionCodeSubModel(program);
            Address address;
            try {
                CodeBlock[] blocks = partitionBlockModel.getCodeBlocksContaining(funcAddr, flatApi.getMonitor());
                if (blocks.length != 1) {
                    continue;
                }
                address = blocks[0].getFirstStartAddress();
            } catch (CancelledException e) {
                ColoredPrint.warning(
                        "Receive CancelledException when getCodeBlocks in recoverMoreFunctions. ");
                e.printStackTrace();
                continue;
            }

            Function newFunc = null;
            int txId = program.startTransaction("createMoreFunc");
            try {
                newFunc = flatApi.createFunction(address, null);
                program.endTransaction(txId, true);
            } catch (Exception e) {
                System.out.printf("Try to create function failed at 0x%x. ", address.getOffset());
                program.endTransaction(txId, false);
            }
            if (newFunc != null) {
                createCount += 1;
            }
        }
        ColoredPrint.info(String.format("Create %d more functions. ", createCount));
        ColoredPrint.info(
                String.format("Found %d functions. ", program.getFunctionManager().getFunctionCount()));
    }

    private static class AggressiveInstructionFinderTaskMonitor extends TaskMonitorAdapter {
        ArrayList<String> entries = new ArrayList<>();

        @Override
        public void setMessage(String message) {
            String finderPrefix = "Aggressive Instruction Finder : ";
            if (message.startsWith(finderPrefix)) {
                String entryStr = message.substring(finderPrefix.length());
                entries.add(entryStr);
            }
        }

        public ArrayList<String> getEntries() {
            return entries;
        }
    }

    public static class TimedTaskMonitor extends TaskMonitorAdapter {

        private Timer timer = new Timer();

        TimedTaskMonitor(int timeoutSecs) {
            super(true);
            timer.schedule(new TimeOutTask(), timeoutSecs * 1000);
        }

        private class TimeOutTask extends TimerTask {
            @Override
            public void run() {
                TimedTaskMonitor.this.cancel();
            }
        }

        @Override
        public void cancel() {
            timer.cancel(); // Terminate the timer thread
            super.cancel();
        }
    }

    // public static class ProcessBarMonitor extends TaskMonitorAdapter {
    //     ProgressBar pb = new ProgressBar("Finding", 100);

    //     @Override
    //     public void setMessage(String msg) {

    //     }

    //     public void initialize(long max) {
    //         setMaximum(max);
    //     }

    //     @Override
    //     public void setMaximum(long max) {
    //         pb = new ProgressBar("Finding", max);
    //     }

    //     @Override
    //     public long getMaximum() {
    //         return pb.getMax();
    //     }

    //     @Override
    //     public void setProgress(long value) {
    //         pb.stepTo(value);
    //     }

    //     @Override
    //     public void incrementProgress(long incrementAmount) {
    //         pb.step();
    //     }

    // }
}
