package com.gsat.tools;

import java.util.ArrayList;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.json.*;

import com.gsat.helper.AnalysisHelper;
import com.gsat.sea.GraphFactory;
import com.gsat.sea.CFGFunction;
import com.gsat.sea.SoNGraph;
import com.gsat.utils.ColoredPrint;
import com.gsat.utils.CommonUtils;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class PCodeExtractorV2 extends BaseTool {
    String cfgFilePath;
    String outputFormat;
    int verbose_level = 0;
    int extraction_mode = 0;
    String debugged_func;

    public PCodeExtractorV2() {
        this.analysisMode = 1; /// Fast analysis
    }

    public static String getName() {
        return "pcode-extractor-v2";
    }

    @Override
    Option[] getOptions() {
        return new Option[] {
                new Option("pm", "extraction_mode", true, "{default, debug_one}"),
                new Option("va", "function_vaddress", true, "The function to be dumpped. "),
                new Option("c", "cfg_file", true,
                        "Path to a json file that contains all selected functions along with its CFG (i.e. *_cfg_disasm.json). "),
                new Option("of", "output_format", true, "One of {'ACFG', 'SoN', 'tSoN'}"),
                new Option("v", "verbose_level", true, "`0` for mnems only and `1` for full. "),
        };
    }

    @Override
    Boolean processOptions(CommandLine commandLine) {
        try {
            cfgFilePath = BaseTool.getRequiredString(commandLine, "cfg_file");
            outputFormat = BaseTool.getRequiredString(commandLine, "output_format");
        } catch (Exception e) {
            return false;
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
        CFGFunction cfgFunction = graphFactory.constructCfgProgramFromCFGSummary(oneCfgJson);
        String dumppedCfgFunction = graphFactory.debugCfgFunction(cfgFunction);
        if (outputFile != null) {
            CommonUtils.writeString(dumppedCfgFunction, outputFile);
            ColoredPrint.info("[*] Results saved at %s", outputFile);
        } else {
            System.console().printf(dumppedCfgFunction);
        }
    }

    @Override
    public Boolean run() {
        if (analysisMode != 0)
            AnalysisHelper.doDecompilerParameterIDAnalysis(program);

        JSONObject cfgJson = new JSONObject(CommonUtils.readFile(cfgFilePath));
        String idb_path = cfgJson.keys().next();
        JSONArray cfgInfos = cfgJson.getJSONArray(idb_path);

        /// Step 1. Determine the offset (between the base address in IDA and Ghidra) and rebase. 
        Long offset = determineLoadingOffsetBySymbol((JSONObject) cfgInfos.get(0));
        if (offset == null && cfgInfos.length() > 1) {
            offset = determineLoadingOffsetBySymbol((JSONObject) cfgInfos.get(1));
        }
        if (offset == null) {
            //// Assume IDA always loads the PIE binary at 0 address and non-PIE binary at its defined entry. 
            ColoredPrint.warning("Determing offset by Function Symbol failed. ");
            offset = getLoadingOffsetFromOriginalBase();
        }
        if (offset != 0) {
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
        for (var oneCfgInfo : cfgInfos) {
            graphFactory.clearState();
            JSONObject oneCfgJson = (JSONObject) oneCfgInfo;
            CFGFunction cfgFunction = graphFactory.constructCfgProgramFromCFGSummary(oneCfgJson);
            if (cfgFunction == null) {
                errorFuncs.add(oneCfgJson.getString("start_ea"));
            }
            JSONObject dumppedGraph = null;
            switch (outputFormat) {
                case "ACFG":
                    dumppedGraph = graphFactory.dumpGraph(cfgFunction, verbose_level);
                    break;
                case "SoN":
                    SoNGraph graph = graphFactory.constructSeaOfNodes(cfgFunction);
                    dumppedGraph = graphFactory.dumpGraph(graph, verbose_level);
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
            CommonUtils.writeString(binOutWrap.toString(), outputFile);
            ColoredPrint.info("[*] Results saved at %s", outputFile);
        } else {
            System.console().printf(binOutWrap.toString(4));
        }
        return true;
    }

}
