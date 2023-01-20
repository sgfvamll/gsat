package com.gsat.tools;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.gsat.taint.TaintEngine;
import com.gsat.taint.TaintTrace;
import com.gsat.taint.TaintEngine.TraceMergeOption;
import com.gsat.utils.ColoredPrint;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class TaintAnalysis extends BaseTool {
    private TraceMergeOption traceMergeOption;

    TaintAnalysis() {
        this.analysisMode = 5;      
    }

    public static String getName() {
        return "taint-analysis";
    }

    public Option[] getOptions() {
        return new Option[] {
            new Option("tm","trace-merge",true,"trace merge option (none, first, last). Default is none. "),
            // new Option("tv","traces verbose",true,"trace merge option (none, first, last). Default is none. "),
        };
    }

    Boolean processOptions(CommandLine commandLine) {
        if (commandLine.hasOption("tm")) {
            switch(commandLine.getOptionValue("tm")) {
            case "none": traceMergeOption = TraceMergeOption.None; break;
            case "first": traceMergeOption = TraceMergeOption.FirstIntegerOp; break;
            case "last": traceMergeOption = TraceMergeOption.LastIntegerOp; break;
            }
        } else {
            traceMergeOption = TraceMergeOption.None;
        }
        return true;
    }

    public Boolean run() {
        TaintEngine engine;
        try {
            engine = new TaintEngine(this.program, this.flatApi, TaintEngine.Strategy.Pessimistic, traceMergeOption);
        } catch (Exception e) {
            ColoredPrint.error(e.toString());
            e.printStackTrace();
            return false;
        }
        engine.analyze();
		Options props = program.getOptions(Program.PROGRAM_INFO);
        String orgImageBaseStr = props.getString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "0x0");
        long orgImageBase = Long.decode(orgImageBaseStr);
        long offset = 0;
        if (orgImageBase != program.getImageBase().getOffset()) {
            offset = orgImageBase - program.getImageBase().getOffset();
        }
        Set<TaintTrace> traces = engine.generateTraces();
        ColoredPrint.info("Get %d traces. ", traces.size());
        String report = "";
        int count = 0;
        for (var trace: traces) {
            report += trace.reportTrace(offset, false) + "\n";
            // if (++count >= 100) break;
        }
        // String report = engine.generateReport(offset);
        System.out.println(report);
        if (this.outputFile != null) {
            BufferedWriter bw = null;
            try {
                bw = new BufferedWriter(new FileWriter(this.outputFile));
                bw.write(report);
            } catch (IOException e) {
                ColoredPrint.error("Fail to save result.");
            } finally {
                if (bw != null) {
                    try{
                        bw.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return true;
    }

}
