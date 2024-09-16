package com.gsat.tools;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.json.*;

import com.gsat.helper.AnalysisHelper;
import com.gsat.sea.GraphFactory;
import com.gsat.sea.CFGFunction;
import com.gsat.sea.ISCGFunction;
import com.gsat.sea.TSCGFunction;
import com.gsat.sea.SOG;
import com.gsat.utils.ColoredPrint;
import com.gsat.utils.CommonUtils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PCodeExtractorV2 extends BaseTool {
    String cfgFilePath = null;
    String outputFormat;
    int verbose_level = 0;
    int extraction_mode = 0;
    boolean preferRawPcode = true;
    String debugged_func;
    String[] filters = null;

    public PCodeExtractorV2() {
        if (preferRawPcode)
            this.analysisMode = 1;
        else
            this.analysisMode = 3;
    }

    public static String getName() {
        return "pcode-extractor-v2";
    }

    @Override
    Option[] getOptions() {
        return new Option[] {
                new Option("opt", "opt_level", true, "Opt level of pcode. (0 or 1)"),
                new Option("pm", "extraction_mode", true, "{default, debug_one}"),
                new Option("va", "function_vaddress", true, "The function to be dumpped. "),
                new Option("c", "cfg_file", true,
                        "Path to a json file that contains all selected functions along with its CFG (i.e. *_cfg_disasm.json). "),
                new Option("of", "output_format", true, "One of {'ACFG', 'SOG', 'ALL'}"),
                new Option("v", "verbose_level", true, "`0` for mnems only and `1` for full. "),
                new Option(null, "filter", true, "filter functions by keywords (splitted by ','). "),
        };
    }

    @Override
    Boolean preProcessOptions(CommandLine commandLine) {
        if (commandLine.hasOption("program_load_mode")) {
            programLoadMode = commandLine.getOptionValue("program_load_mode");
        }
        if (commandLine.hasOption("opt_level")) {
            int opt = Integer.parseInt(commandLine.getOptionValue("opt_level"), 10);
            if (opt == 1) {
                preferRawPcode = false;
                if (!programLoadMode.equals("ghidra"))
                    this.analysisMode = 3;
            } else {
                preferRawPcode = true;
                if (!programLoadMode.equals("ghidra"))
                    this.analysisMode = 1;
            }
        }
        if (commandLine.hasOption("filter")) {
            filters = commandLine.getOptionValue("filter").split(",");
        }
        return true;
    }

    @Override
    Boolean processOptions(CommandLine commandLine) {
        try {
            outputFormat = BaseTool.getRequiredString(commandLine, "output_format");
        } catch (Exception e) {
            return false;
        }
        if (commandLine.hasOption("cfg_file")) {
            cfgFilePath = commandLine.getOptionValue("cfg_file");
        }
        if (commandLine.hasOption("verbose_level"))
            verbose_level = Integer.parseInt(commandLine.getOptionValue("verbose_level"), 10);
        if (commandLine.hasOption("extraction_mode")) {
            String mode = commandLine.getOptionValue("extraction_mode");
            if (mode.equals("debug_one")) {
                extraction_mode = 1;
            }
            debugged_func = commandLine.getOptionValue("function_vaddress");
        }
        return true;
    }

    private Long determineLoadingOffsetBySymbol(JSONObject oneFuncInfo) {
        Address oneStartEa = program.getAddressFactory().getAddress(oneFuncInfo.getString("start_ea"));
        String oneFuncName = oneFuncInfo.getString("func_name");
        for (var sym : program.getSymbolTable().getSymbols(oneFuncName)) {
            if ((sym.getAddress().getOffset() & 0xfff) == (oneStartEa.getOffset() & 0xfff)) {
                return sym.getAddress().getOffset() - oneStartEa.getOffset();
            }
        }
        return null;
    }

    private long getLoadingOffsetFromOriginalBase() {
        Options props = program.getOptions(Program.PROGRAM_INFO);
        String orgImageBaseStr = props.getString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "0x0");
        long orgImageBase = Long.decode(orgImageBaseStr);
        return program.getImageBase().getOffset() - orgImageBase;
    }

    private void dumpOneFunc(JSONObject oneCfgJson) {
        GraphFactory graphFactory = new GraphFactory(program);
        CFGFunction cfgFunction = graphFactory.constructCfgProgramFromCFGSummary(oneCfgJson, preferRawPcode);
        String dumppedCfgFunction = graphFactory.debugCfgFunction(cfgFunction);
        if (outputFile != null) {
            CommonUtils.writeString(dumppedCfgFunction, outputFile);
            ColoredPrint.info("[*] Results saved at %s", outputFile);
        } else {
            System.console().printf(dumppedCfgFunction);
        }
    }

    public JSONObject generateCFGJson() {
        JSONObject result = new JSONObject();
        JSONArray functionsArray = new JSONArray();

        BasicBlockModel bbModel = new BasicBlockModel(program);
        Listing listing = program.getListing();
        FunctionIterator funcIter = listing.getFunctions(true);

        while (funcIter.hasNext()) {
            Function function = funcIter.next();
            JSONObject functionObj = new JSONObject();
            String fname = function.getName();

            Boolean skip = filters != null;
            for (String key : filters) {
                if (fname.indexOf(key) != -1) {
                    skip = false;
                    break;
                }
            }
            if (skip) {
                continue;
            }

            functionObj.put("start_ea", "0x" + Long.toHexString(function.getEntryPoint().getOffset()));
            functionObj.put("func_name", fname);

            // Get basic blocks
            JSONArray nodesArray = new JSONArray();
            CodeBlockIterator bbIter;
            try {
                bbIter = bbModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);
                while (bbIter.hasNext()) {
                    CodeBlock bb = bbIter.next();
                    JSONArray nodeInfo = new JSONArray();
                    nodeInfo.put("0x" + Long.toHexString(bb.getMinAddress().getOffset()));
                    nodeInfo.put(bb.getNumAddresses());
                    nodesArray.put(nodeInfo);
                }
            } catch (CancelledException e) {
                e.printStackTrace();
            }
            functionObj.put("nodes", nodesArray);

            // Get control flow edges
            JSONArray edgesArray = new JSONArray();
            try {
                bbIter = bbModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);
                while (bbIter.hasNext()) {
                    CodeBlock bb = bbIter.next();
                    CodeBlockReferenceIterator destIter = bb.getDestinations(TaskMonitor.DUMMY);
                    while (destIter.hasNext()) {
                        CodeBlockReference dest = destIter.next();
                        JSONArray edgeInfo = new JSONArray();
                        edgeInfo.put(bb.getMinAddress().getOffset());
                        edgeInfo.put(dest.getDestinationAddress().getOffset());
                        edgesArray.put(edgeInfo);
                    }
                }
            } catch (CancelledException e) {
                e.printStackTrace();
            }
            functionObj.put("edges", edgesArray);

            functionsArray.put(functionObj);
        }
        result.put(program.getName(), functionsArray);
        return result;
    }

    @Override
    public Boolean run() {
        if (analysisMode != 0)
            AnalysisHelper.doDecompilerParameterIDAnalysis(program);

        if (cfgFilePath == null || !CommonUtils.fileExists(cfgFilePath)) {
            if (cfgFilePath == null) {
                try {
                    cfgFilePath = Files.createTempFile(null, null).toString();
                } catch (IOException e) {
                    ColoredPrint.error("Unable to create cfg file. ");
                    e.printStackTrace();
                    return false;
                }
            }
            JSONObject result = generateCFGJson();
            CommonUtils.writeJson(result, cfgFilePath);
        }

        JSONObject cfgJson = new JSONObject(CommonUtils.readFile(cfgFilePath));
        String idb_path = cfgJson.keys().next();
        JSONArray cfgInfos = cfgJson.getJSONArray(idb_path);

        if (cfgInfos.length() == 0) {
            ColoredPrint.warning("No functions to lift. ");
            if (outputFile != null) {
                JSONObject binOutWrap = new JSONObject();
                binOutWrap.put(idb_path, cfgInfos);
                CommonUtils.writeJson(binOutWrap, outputFile);
                ColoredPrint.info("[*] Results saved at %s", outputFile);
            }
            return true;
        }

        /// Step 1. Determine the offset (between the base address in IDA and Ghidra) and rebase. 
        Long offset = determineLoadingOffsetBySymbol((JSONObject) cfgInfos.get(0));
        if (offset == null && cfgInfos.length() > 1) {
            offset = determineLoadingOffsetBySymbol((JSONObject) cfgInfos.get(1));
        }
        if (offset == null && !programLoadMode.equals("binary")) {
            //// Assume IDA always loads the PIE binary at 0 address and non-PIE binary at its defined entry. 
            ColoredPrint.warning("Determing offset by Function Symbol failed. ");
            offset = getLoadingOffsetFromOriginalBase();
        }
        if (offset != null && offset != 0) {
            ColoredPrint.info("Rebase program to %x. ", program.getImageBase().add(-offset).getOffset());
            AnalysisHelper.rebaseProgram(program, program.getImageBase().add(-offset));
        }

        if (extraction_mode == 1) {
            for (var oneCfgInfo : cfgInfos) {
                JSONObject oneCfgJson = (JSONObject) oneCfgInfo;
                String startEa = (String) oneCfgJson.get("start_ea");
                if (!debugged_func.equals(startEa))
                    continue;
                dumpOneFunc(oneCfgJson);
                break;
            }
            return true;
        }

        long startTime = System.currentTimeMillis();
        ArrayList<String> errorFuncs = new ArrayList<>();
        GraphFactory graphFactory = new GraphFactory(program);
        JSONObject binOut = new JSONObject();
        DecompInterface decompInterface = null;
        if (outputFormat.equals("ALL")) {
            decompInterface = new DecompInterface();
    
            DecompileOptions options;
            options = new DecompileOptions();
    
            long suggestedMaxInsts = options.getMaxInstructions(); // 100000
            options.setMaxInstructions(Integer.MAX_VALUE);
            ColoredPrint.info("Changing max_instructions from 0x%x to 0x%x. ", suggestedMaxInsts, Integer.MAX_VALUE);
    
            decompInterface.setOptions(options);
    
            decompInterface.toggleCCode(true);
            if (!decompInterface.openProgram(program)) {
                System.out.printf("Decompiler error: %s\n", decompInterface.getLastMessage());
            }
        }
        for (var oneCfgInfo : cfgInfos) {
            graphFactory.clearState();
            JSONObject oneCfgJson = (JSONObject) oneCfgInfo;
            /// For debug. 
            // if (oneCfgJson.getString("start_ea").equals("0x128df0")) {
            //     ColoredPrint.info("123");
            // }
            CFGFunction cfgFunction = graphFactory.constructCfgProgramFromCFGSummary(oneCfgJson, preferRawPcode);
            if (cfgFunction == null) {
                errorFuncs.add(oneCfgJson.getString("start_ea"));
                continue;
            }
            JSONObject dumppedGraph = null;
            switch (outputFormat) {
                case "ACFG":
                    dumppedGraph = graphFactory.dumpGraph(cfgFunction, verbose_level);
                    break;
                case "SOG":
                    SOG graph = graphFactory.constructSOG(cfgFunction);
                    dumppedGraph = graphFactory.dumpGraph(graph, verbose_level);
                    break;
                case "ALL":
                    dumppedGraph = new JSONObject();
                    dumppedGraph.put("PcodeLevel", cfgFunction.pcodeLevel());
                    JSONObject g = graphFactory.dumpGraph(cfgFunction, verbose_level);
                    dumppedGraph.put("ACFG", g);
                    long liftingSOGStart = System.nanoTime();
                    SOG sog = graphFactory.constructSOG(cfgFunction);
                    long liftingSOGEnd = System.nanoTime();
                    g = graphFactory.dumpGraph(sog, verbose_level);
                    g.put("LiftingCost_ns", liftingSOGEnd - liftingSOGStart);
                    dumppedGraph.put("SOG", g);
                    ISCGFunction iscg = graphFactory.constructISCGFromSOG(cfgFunction.getAddress(), sog);
                    g = graphFactory.dumpGraph(iscg, verbose_level);
                    dumppedGraph.put("ISCG", g);
                    TSCGFunction tscg = graphFactory.constructTSCGFromSOG(cfgFunction.getAddress(), sog);
                    g = graphFactory.dumpGraph(tscg, verbose_level);
                    dumppedGraph.put("TSCG", g);
                    if (decompInterface != null) {
                        Address startEa = program.getAddressFactory().getAddress(oneCfgJson.getString("start_ea"));
                        String decompiled = graphFactory.checkedGetCCodeAt(startEa, decompInterface);
                        if (decompiled != null) {
                            dumppedGraph.put("DECOMPILED_C", decompiled);
                        }
                    }
                    break;
            }
            binOut.putOpt((String) oneCfgJson.get("start_ea"), dumppedGraph);
        }
        long endTime = System.currentTimeMillis();
        ColoredPrint.info(
                String.format("Time for extraction: %.2f secs. ", (endTime - startTime) / 1000.0));
        if (errorFuncs.size() != 0)
            ColoredPrint.warning(
                    String.format("Error count: %d. Error funcs: %s", errorFuncs.size(), errorFuncs.toString()));

        JSONObject binOutWrap = new JSONObject();
        binOutWrap.put(idb_path, binOut);
        if (outputFile != null) {
            CommonUtils.writeJson(binOutWrap, outputFile);
            ColoredPrint.info("[*] Results saved at %s", outputFile);
        } else {
            System.console().printf(binOutWrap.toString(4));
        }
        return true;
    }

}
