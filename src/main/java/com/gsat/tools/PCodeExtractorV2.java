package com.gsat.tools;

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

    public PCodeExtractorV2() {
        this.analysisMode = 1; /// No builtin auto-analysis
    }

    public static String getName() {
        return "pcode-extractor-v2";
    }

    @Override
    Option[] getOptions() {
        return new Option[] {
                new Option("c", "cfg_file", true,
                        "Path to a json file that contains all selected functions along with its CFG (i.e. *_cfg_disasm.json). "),
                new Option("of", "output_format", true, "One of {'ACFG', 'SoN', 'tSoN'}"),
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

    @Override
    public Boolean run() {
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

        GraphFactory cfgFactory = new GraphFactory(program);
        JSONObject binOut = new JSONObject();
        for (var oneCfgInfo : cfgInfos) {
            JSONObject oneCfgJson = (JSONObject) oneCfgInfo;
            CFGFunction cfgFunction = cfgFactory.constructCfgProgramFromJsonInfo(oneCfgJson);
            JSONObject dumppedGraph = null;
            switch (outputFormat) {
                case "ACFG":
                    dumppedGraph = cfgFactory.dumpGraph(cfgFunction);
                    break;
                case "SoN":
                    SoNGraph graph = cfgFactory.constructSeaOfNodes(cfgFunction);
                    dumppedGraph = cfgFactory.dumpGraph(graph);
                    break;
            }
            binOut.putOpt((String) oneCfgJson.get("start_ea"), dumppedGraph);
        }

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
