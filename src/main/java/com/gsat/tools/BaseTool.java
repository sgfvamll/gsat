package com.gsat.tools;

import java.io.File;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.NotImplementedException;

import com.gsat.helper.AnalysisHelper;
import com.gsat.helper.ProjectManager;
import com.gsat.utils.ColoredPrint;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;

public abstract class BaseTool {

    ProjectManager manager;
    Program program; // The program for this tool to analyze.
    String programName;
    FlatProgramAPI flatApi;

    String programLoadMode = "elf";
    String outputFile = null; // Output raw / human-readable results

    protected int analysisMode = 4;

    static String getName() {
        throw new NotImplementedException("");
    }

    abstract Option[] getOptions();

    abstract Boolean processOptions(CommandLine commandLine);
    Boolean preProcessOptions(CommandLine commandLine) {
        return true;
    }

    abstract public Boolean run();

    static String getRequiredString(CommandLine cmd, String key) throws Exception {
        if (cmd.hasOption(key)) {
            return cmd.getOptionValue(key);
        } else {
            ColoredPrint.error("Required option '%s' missed. ", key);
            throw new Exception("");
        }
    }

    static Option[] getBasicOptions() {
        return new Option[] {
                new Option("h", "help", false, "Print help. "),
                new Option("p", "project_dir", true, "Path to create project.(Default:tmpDir)"),
                new Option("n", "project_name", true, "Project name. (Default: default)"),
                new Option("s", "save_project", false, "Whether create/save the project."),
                new Option("m", "program_load_mode", true, "How to load the program. One of {binary, elf, ar-obj, ghidra}. "),
                new Option("f", "program", true,
                        "Program to be analyzed.\n program_load_mode == 'binary'/'elf'/'ar-obj' => this option should denote the file path that the tool will load.\n program_load_mode == 'ghidra' => this option denotes the program name in ghidra project. "),
                new Option("af", "analyzed_program", true,
                        "The name of the program to be analyzed when loading in ar-obj mode. "),
                new Option("am", "analysis_mode", true, "Auto-analysis mode used when loading program. Can be 0 (no auto-analysis), 1 (fast-analysis), 2 (full analysis)"), 
                new Option("l", "language_id", true, "Language id like x86:LE:32:default (for binary loading)"),
                new Option("b", "base_address", true, "Base address (for binary loading). (Default: 0) "),
                new Option("o", "output", true, "Path to save raw results."),
        };
    }

    void analyzeProgram(Program program) {
        if (analysisMode < 0) return;
        AnalysisHelper.enableAutoAnalysisManger(program);
        if (analysisMode == 0) return;
        if (analysisMode == 1) {
            AnalysisHelper.disableSlowAnalysis(program);
        }
        if (analysisMode == 2) {
            AnalysisHelper.disableConstantReferenceAnalysis(program);
        }
        boolean succ = AnalysisHelper.autoAnalyzeProgram(program);
        if (!succ && analysisMode >= 2) {
            if (analysisMode >= 3) {
                AnalysisHelper.disableConstantReferenceAnalysis(program);
                succ = AnalysisHelper.autoAnalyzeProgram(program);
            }
            if (!succ) {
                AnalysisHelper.disableSlowAnalysis(program);
                succ = AnalysisHelper.autoAnalyzeProgram(program);
            }
        }
        if (analysisMode >= 4) {
            AnalysisHelper.doAggressiveInstructionFinder(program);
            AnalysisHelper.recoverMoreFunctions(program);
        }
        if (analysisMode >= 5) {
            AnalysisHelper.doDecompilerParameterIDAnalysis(program);
        }
    }

    Boolean processBasicOptions(CommandLine commandLine) {

        if (commandLine.hasOption("help")) {
            return false;
        }

        String projectDir = null, projectName = null, programTobeAnalyzed = null;
        String languageId = null, baseAddress = null;
        Boolean saveProject = false;

        if (commandLine.hasOption("program")) {
            programName = commandLine.getOptionValue("program");
        } else {
            ColoredPrint.error("Should specify the program to be analyzed. ");
            return false;
        }
        if (commandLine.hasOption("analyzed_program")) {
            programTobeAnalyzed = commandLine.getOptionValue("analyzed_program");
        }   
        if (commandLine.hasOption("program_load_mode")) {
            programLoadMode = commandLine.getOptionValue("program_load_mode");
        }
        if (!programLoadMode.equals("ghidra")) {
            File program = new File(programName);
            if (!program.exists()) {
                ColoredPrint.error(
                        String.format("Program %s doesn't exists (%s mode). ", programName, programLoadMode));
                return false;
            }
        }
        if (commandLine.hasOption("project_dir")) {
            projectDir = commandLine.getOptionValue("project_dir");
        }
        if (commandLine.hasOption("project_name")) {
            projectName = commandLine.getOptionValue("project_name");
        }
        if (commandLine.hasOption("analysis_mode")) {
            analysisMode = Integer.parseInt(commandLine.getOptionValue("analysis_mode"));
        }
        if (commandLine.hasOption("language_id")) {
            languageId = commandLine.getOptionValue("language_id");
        } else if (programLoadMode == "binary") {
            ColoredPrint.warning("You are loading binary without giving language id. ");
        }
        if (commandLine.hasOption("base_address")) {
            baseAddress = commandLine.getOptionValue("base_address");
        }

        saveProject = commandLine.hasOption("save_project");
        if (commandLine.hasOption("output")) {
            outputFile = commandLine.getOptionValue("output");
        }

        ColoredPrint.info("Analysis Mode: %d", analysisMode);
        try {
            manager = new ProjectManager(projectDir, projectName, !saveProject);
            switch (programLoadMode) {
                case "binary":
                    program = manager.loadBinaryProgram(programName, languageId, baseAddress);
                    break;
                case "elf":
                    program = manager.loadELFProgram(programName);
                    break;
                case "ghidra":
                    program = manager.openProgram(programName);
                    break;
                case "ar-obj":
                    program = manager.loadProgramFromArArchive(programName, programTobeAnalyzed);
                    break;
            }
            // AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            if (!programLoadMode.equals("ghidra")) 
                this.analyzeProgram(program);
            flatApi = new FlatProgramAPI(program);
        } catch (Exception e) {
            ColoredPrint.error("Failed to load project / program. ");
            ColoredPrint.error(e.toString());
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public void close() {
        if (manager != null)
            manager.close();
    }
}
