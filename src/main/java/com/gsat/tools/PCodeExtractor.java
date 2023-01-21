package com.gsat.tools;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.json.*;

import com.gsat.utils.ColoredPrint;
import com.gsat.utils.CommonUtils;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class PCodeExtractor extends BaseTool {
    String selectedFilePath;
    String outputFormat;

    public PCodeExtractor() {
        this.analysisMode = 3; /// Normal Analysis 
    }

    public static String getName() {
        return "pcode-extractor";
    }

    @Override
    Option[] getOptions() {
        return new Option[] {
                new Option("sf", "selected_funcs", true, "Path to a file specifying the selected functions. "),
                new Option("of", "output_format", true, "One of {'ACFG', 'SoN', 'tSoN'}"),
        };
    }

    @Override
    Boolean processOptions(CommandLine commandLine) {
        try {
            selectedFilePath = BaseTool.getRequiredString(commandLine, "selected_funcs");
            outputFormat = BaseTool.getRequiredString(commandLine, "output_format");
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private DecompInterface setUpDecompiler() {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();

        decompInterface.setOptions(options);

        decompInterface.toggleCCode(false);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("normalize");
        if (!decompInterface.openProgram(program)) {
            System.out.printf("Decompiler error: %s\n", decompInterface.getLastMessage());
        }
        return decompInterface;
    }

    static private Address getAddressWithOffset(AddressFactory addressFactory, String address, long offset) {
        if (address.startsWith("0x")) {
            address = address.substring(2);
        }
        return addressFactory
                .getAddress("0x" + Long.toHexString(Long.parseLong(address, 16) + offset));
    }

    static private boolean isNopInstruction(Instruction inst) {
        if (inst.getPcode().length == 0 || inst.getMnemonicString().equals("NOP"))
            return true;
        if (inst.getPcode().length == 1) {
            PcodeOp pcodeOp = inst.getPcode()[0];
            if (pcodeOp.getMnemonic().equals("COPY")) {
                if (pcodeOp.getOutput().equals(pcodeOp.getInput(0))) {
                    return true;
                }
            }
        }
        return false;
    }

    static private Boolean checkCodeAddrSetSatisfied(AddressSetView requiredSet, AddressSetView realSet, Program program) {
        AddressSetView notIncluded = requiredSet.subtract(realSet);
        Boolean checked_good = true;
        AddressSet badSet = new AddressSet();
        for (var range : notIncluded.getAddressRanges()) {
            AddressSet remainingSet = new AddressSet(range);
            AddressSet inRangeBadSet = new AddressSet();
            for (var addr : range) {
                if (!remainingSet.contains(addr))
                    continue;
                Data data = program.getListing().getDataContaining(addr);
                if (data != null) {
                    /// Safely skip data
                    remainingSet = remainingSet.subtract(new AddressSet(data.getMinAddress(), data.getMaxAddress()));
                    continue;
                }
                Instruction inst = program.getListing().getInstructionContaining(addr);
                if (inst != null) {
                    remainingSet = remainingSet.subtract(new AddressSet(inst.getMinAddress(), inst.getMaxAddress()));
                    /// Safely skip instructions in the delay slots or that are nops
                    if (!(inst.isInDelaySlot() || isNopInstruction(inst))) {
                        inRangeBadSet.add(inst.getMinAddress(), inst.getMaxAddress());
                    }
                }
            }
            if (inRangeBadSet.getNumAddresses() >= 0x10) {
                checked_good = false;
                break;
            }
            badSet.add(inRangeBadSet);
        }
        if (badSet.getNumAddresses() > Long.max(requiredSet.intersect(realSet).getNumAddressRanges() / 10, 0x10)) {
            // Small mismatch like alignment, nops or opted instructions can be safely skipped. 
            // The gap that is less than 5% is ignored. 
            checked_good = false;
        }
        return checked_good;
    }

    private HighFunction checkedGetHFuncContaining(AddressSetView body, DecompInterface decompInterface) {
        Address startEa = body.getMinAddress();
        Address endEa = body.getMaxAddress();
        Function func = program.getFunctionManager().getFunctionAt(startEa);

        /// Check failed (1): Try disasmbling and re-create the function. 
        if (func == null || !body.subtract(func.getBody()).isEmpty()) {
            /// Create function if not valid. 
            int txId = program.startTransaction("CreateFunction");
            AddressSetView toBeDecompiled = body;
            while (true) {
                DisassembleCommand cmd = new DisassembleCommand(toBeDecompiled, toBeDecompiled,
                        false);
                cmd.applyTo(program, flatApi.getMonitor());
                AddressSetView decompiled = cmd.getDisassembledAddressSet();
                toBeDecompiled = toBeDecompiled.subtract(decompiled);
                if (toBeDecompiled.isEmpty() || decompiled.isEmpty())
                    break;
            }
            CreateFunctionCmd fcmd = new CreateFunctionCmd(null, startEa, body, SourceType.DEFAULT, false, true);
            fcmd.applyTo(program, flatApi.getMonitor());
            func = program.getListing().getFunctionAt(startEa);
            program.endTransaction(txId, true);

            if (func == null) {
                ColoredPrint.error(
                        "Create function failed (start: %x, end: %x) ",
                        startEa.getOffset(), endEa.getOffset());
                return null;
            }
        }

        /// Decompile first, decompling may fix some previous wrong analysis. 
        int decompilingTimeSecs = 600; // decompInterface.getOptions().getDefaultTimeout() == 30
        DecompileResults dresult = decompInterface
                .decompileFunction(func, decompilingTimeSecs, TaskMonitor.DUMMY);
        HighFunction hfunc = dresult.getHighFunction();

        if (hfunc == null) {
            ColoredPrint.error(
                    "Decompile function failed! Function (start: %x, end: %x, body: %s)",
                    startEa.getOffset(), endEa.getOffset(), func.getBody());
            ColoredPrint.error(dresult.getErrorMessage());
            return null;
        }

        return hfunc;
    }

    private boolean isHighFuncMatchRequiredBody(HighFunction hfunc, AddressSetView body) {
        Function func = hfunc.getFunction();
        /// Check failed (2): Try grab the decompiling info and further determine its validation. 
        if (!checkCodeAddrSetSatisfied(body, func.getBody(), program)) {
            /// func.getBody somethings is buggy. Try to get real body info from bbs here. 
            AddressSetView rawFuncBody = func.getBody();
            AddressSet realBody = new AddressSet().union(rawFuncBody);
            var bbIter = hfunc.getBasicBlocks().iterator();
            while (bbIter.hasNext()) {
                var bb = bbIter.next();
                Address maxAddress = bb.getStop();
                AddressRange range = rawFuncBody.getRangeContaining(maxAddress);
                /// Note, some instructions (at some addresses) maybe opted out and not in pcode. 
                if (range != null) {
                    maxAddress = range.getMaxAddress();
                }
                Instruction lastInst = program.getListing().getInstructionContaining(maxAddress);
                // if (bb.getStart().getOffset() == 0x0012dda3 || bb.getStart().getOffset() == 0x0012dda4) {
                //     ColoredPrint.info("debug");
                //     var pcodeIter = bb.getIterator();
                //     System.out.printf("--------- bb at %08x ---------\n", bb.getStart().getOffset());
                //     while (pcodeIter.hasNext()) {
                //         var pcode = pcodeIter.next();
                //         System.out.printf("%08x: %s\n",
                //                 pcode.getSeqnum().getTarget().getOffset(), pcode.toString());
                //     }
                // }
                if (lastInst != null) {
                    maxAddress = lastInst.getMaxAddress();
                }
                realBody.add(bb.getStart(), maxAddress);
            }
            if (!checkCodeAddrSetSatisfied(body, realBody, program)) {
                ColoredPrint.error(
                        "Function Range Mismatch (%s) <-> (%s) / (%s)", body, func.getBody(), realBody);
                return false;
            }
        }
        return true;
    }

    @Override
    public Boolean run() {
        JSONArray selectedFuncs = CommonUtils.readJson(selectedFilePath).getJSONArray("functions");
        Iterator<Object> funcInfoIter = selectedFuncs.iterator();
        AddressFactory addressFactory = program.getAddressFactory();
        DecompInterface decompInterface = setUpDecompiler();

        //// Determine the offset (between the base address in IDA and Ghidra)
        long offset = 0;
        JSONObject oneFuncInfo = (JSONObject) selectedFuncs.get(0);
        Address oneStartEa = getAddressWithOffset(addressFactory, oneFuncInfo.getString("start_ea"), offset);
        String oneFuncName = oneFuncInfo.getString("func_name");
        boolean determineOffsetSucc = false;
        for (var sym: program.getSymbolTable().getSymbols(oneFuncName)) {
            if ((sym.getAddress().getOffset() & 0xfff) == (oneStartEa.getOffset() & 0xfff)) {
                offset = sym.getAddress().getOffset() - oneStartEa.getOffset();
                determineOffsetSucc = true;
            }
        }
        if (!determineOffsetSucc) {
            //// Assume IDA always loads the PIE binary at 0 address and non-PIE binary at its defined entry. 
            Options props = program.getOptions(Program.PROGRAM_INFO);
            String orgImageBaseStr = props.getString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "0x0");
            long orgImageBase = Long.decode(orgImageBaseStr);
            if (orgImageBase != program.getImageBase().getOffset()) {
                offset = program.getImageBase().getOffset() - orgImageBase;
            }
        }

        JSONObject binOut = new JSONObject();
        ArrayList<Long> failedFuncs = new ArrayList<Long>();    /// Failed to get HighFunction
        ArrayList<Long> underrangeFuncs = new ArrayList<Long>();/// Functions that are failed to be created to cover the given body
        ArrayList<Long> overrangeFuncs = new ArrayList<Long>(); /// Functions created that cover the given body but more
        while (funcInfoIter.hasNext()) {
            JSONObject funcInfo = (JSONObject) funcInfoIter.next();
            Address startEa = getAddressWithOffset(addressFactory, funcInfo.getString("start_ea"), offset);
            Address endEa = getAddressWithOffset(addressFactory, funcInfo.getString("end_ea"), offset);
            Address maxEa = endEa.subtract(1);
            AddressSet body = addressFactory.getAddressSet(startEa, maxEa);
            HighFunction hfunc = checkedGetHFuncContaining(body, decompInterface);
            if (hfunc == null) {
                failedFuncs.add(startEa.getOffset() - offset);
                continue;
            }

            if (!isHighFuncMatchRequiredBody(hfunc, body)) {
                underrangeFuncs.add(startEa.getOffset() - offset);
            }

            if (!checkCodeAddrSetSatisfied(hfunc.getFunction().getBody(), body, program)) {
                ColoredPrint.warning(
                        "Identify more code in this function (%s) <-> (%s)", body, hfunc.getFunction().getBody());
                overrangeFuncs.add(startEa.getOffset() - offset);
            }

            JSONObject funcOut = new JSONObject();
            ArrayList<Long> nodes = new ArrayList<Long>();
            ArrayList<Long[]> edges = new ArrayList<Long[]>();
            JSONObject bbsOut = new JSONObject();
            switch (outputFormat) {
                case "ACFG": {
                    ArrayList<PcodeBlockBasic> pCodeBBs = hfunc.getBasicBlocks();
                    var bbIter = pCodeBBs.iterator();
                    while (bbIter.hasNext()) {
                        var bb = bbIter.next();
                        long ea = bb.getStart().getOffset();
                        nodes.add(ea - offset);
                        for (int i = 0; i < bb.getOutSize(); i++) {
                            long out_ea = bb.getOut(i).getStart().getOffset();
                            edges.add(new Long[] { ea - offset, out_ea - offset });
                        }
                        JSONObject bbOut = new JSONObject();
                        ArrayList<String> bbMnems = new ArrayList<String>();
                        var pcodeIter = bb.getIterator();
                        while (pcodeIter.hasNext()) {
                            var pcode = pcodeIter.next();
                            bbMnems.add(pcode.getMnemonic());
                        }
                        bbOut.put("bb_mnems", bbMnems);
                        bbsOut.put(String.format("%d", ea - offset), bbOut);
                    }
                    break;
                }
                case "SoN": {

                }
            }
            funcOut.put("nodes", nodes);
            funcOut.put("edges", edges);
            funcOut.put("basic_blocks", bbsOut);
            binOut.put(String.format("%d", startEa.getOffset() - offset), funcOut);
        }
        binOut.put("failed_functions", failedFuncs);
        binOut.put("overrange_functions", overrangeFuncs);
        binOut.put("underrange_functions", underrangeFuncs);

        if (outputFile != null) {
            CommonUtils.writeString(binOut.toString(), outputFile);
            ColoredPrint.info("[*] Results saved at %s", outputFile);
        } else {
            System.console().printf(binOut.toString(4));
        }

        return true;
    }

}
