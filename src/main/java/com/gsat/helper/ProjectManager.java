package com.gsat.helper;

import generic.stl.Pair;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;

import ghidra.framework.data.TransientDataManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.options.Options;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.InvalidNameException;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import org.apache.commons.io.FileUtils;

import com.gsat.utils.ColoredPrint;
import com.gsat.utils.CommonUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ProjectManager {
    private static String GhidraProjectSuffix = ".rep";

    private Project project;
    private ProjectLocator locator;
    private DomainFolder domainFolder;

    /// Managed programs that are once loaded.
    private ArrayList<Program> programs;
    /// Whether to persistently save the project in the disk.
    Boolean noWrite;
    Boolean isTemporary;

    /// Given the projectDir and projectName, try to open the project if the
    /// corresponding rep file exists.
    /// Otherwise, create a project.
    public ProjectManager(
            String projectDir, String projectName, Boolean noWrite)
            throws IOException, NotFoundException, NotOwnerException, LockException {

        this.noWrite = noWrite;

        if (projectDir == null) {
            projectDir = Files.createTempDirectory(CommonUtils.createUUID()).toString();
        }
        if (projectName == null) {
            projectName = "default";
        }

        File projectDirFile = new File(projectDir);
        if (projectDirFile.exists() && !projectDirFile.isDirectory()) {
            throw new InvalidPathException(projectDir, "Project path exists but is not a directory. ");
        } else if (!projectDirFile.exists()) {
            projectDirFile.mkdirs();
        }
        projectDir = projectDirFile.getCanonicalPath();

        HeadlessGhidraProjectManager projectManager = new HeadlessGhidraProjectManager();
        this.locator = new ProjectLocator(projectDir, projectName);

        Path repFilePath = Paths.get(projectDir, projectName + GhidraProjectSuffix);
        if (repFilePath.toFile().exists()) {
            this.project = projectManager.openProject(locator, true, false);
            this.isTemporary = false; // never clean existing projects.
        } else {
            this.project = projectManager.createProject(locator, null, false);
            this.isTemporary = noWrite; // If this project is created by us and user tell us to not write to disk, we
                                        // then clear the temp project at closing point .
        }
        this.domainFolder = project.getProjectData().getRootFolder();
        this.programs = new ArrayList<>();
    }

    public Program loadELFProgram(String programPath) 
            throws CancelledException, DuplicateNameException, InvalidNameException, VersionException, IOException {
        File programFile = new File(programPath);
        MessageLog messageLog = new MessageLog();
        Program program = AutoImporter.importByUsingBestGuess(programFile, domainFolder, programPath, messageLog, TaskMonitor.DUMMY);
        this.programs.add(program);
        return program;
    }

    public Program loadBinaryProgram(
            String programPath, String languageId, String baseAddr)
            throws CancelledException, DuplicateNameException, InvalidNameException, VersionException, IOException {
        File programFile = new File(programPath);
        MessageLog messageLog = new MessageLog();
        Program program;
        if (languageId == null || languageId.equals("")) {
            program = AutoImporter.importByUsingBestGuess(programFile, null, this, messageLog, TaskMonitor.DUMMY);
        } else {
            Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
            if (baseAddr == null || !baseAddr.equals("")) {
                baseAddr = "0x0";
            }
            List<Pair<String, String>> imageBaseOptions = Arrays.asList(
                new Pair<>(Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr", baseAddr)
            );
            program = AutoImporter.importByUsingSpecificLoaderClassAndLcs(
                    programFile, null, BinaryLoader.class, imageBaseOptions,
                    language, language.getDefaultCompilerSpec(), this, messageLog, TaskMonitor.DUMMY);
        }
        this.programs.add(program);
        if (!this.noWrite) {
            /// For program loaded by BinaryLoader, we need to manully create DomainFile. Seems not needed for elf program. 
            DomainFile df = domainFolder.createFile(program.getName(), program, TaskMonitor.DUMMY);
        }
        return program;
    }

    public Program openProgram(String programName) throws VersionException, CancelledException, IOException {
        Program program = (Program) domainFolder.getFile(programName).getDomainObject(this, true, false,
                TaskMonitor.DUMMY);
        this.programs.add(program);
        return program;
    }

    public void disableSlowAnalysis(Program program) {
        int txId = program.startTransaction("OptionChanged");
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        options.setBoolean("Decompiler Switch Analysis", false);
        options.setBoolean("Stack", false);
        options.setBoolean("Decompiler Parameter ID", false);
        /// Somethings extremely slow for MIPS firmwares. There may be some bugs in ClearFlowAndRepairCmd 
        options.setBoolean("Non-Returning Functions - Discovered.Repair Flow Damage", false);    
        options.setBoolean("MIPS Constant Reference Analyzer", false);
        options.setBoolean("ARM Constant Reference Analyzer", false);
        program.endTransaction(txId, true);
    }

    public Program autoAnalyzeProgram(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();

        //// Print all analysis for debug
        // List<Analyzer> analyzers = ClassSearcher.getInstances(Analyzer.class);
        // String all_analyzers = "";
        // for (var analyzer: analyzers) {
        //     // Boolean isAvaiable = mgr.getAnalyzer(analyzer.getName()) != null;
        //     // if (isAvaiable) {
        //         all_analyzers += analyzer.getName() + ", " + analyzer.getDescription() + ", \n";
        //     // }
        // }
        // try {
        //     BufferedWriter out = new BufferedWriter(new FileWriter("all_analyzers.txt"));
        //     out.write(all_analyzers);
        //     out.close();
        // } catch (Exception e) {
        //     e.printStackTrace();
        // }

        // Start a new transaction in order to make changes to this domain object.
        int txId = program.startTransaction("Analysis");
        try {
            mgr.reAnalyzeAll(null);
            // mgr.startAnalysis(new ConsoleTaskMonitor());
            mgr.startAnalysis(TaskMonitor.DUMMY);
            GhidraProgramUtilities.setAnalyzedFlag(program, true);
        } finally {
            program.endTransaction(txId, true);
        }
        // mgr.dispose();
        return program;
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

    public void save() throws CancelledException, IOException {
        for (Program program : this.programs) {
            program.getDomainFile().save(TaskMonitor.DUMMY);
        }
        this.project.save();
    }

    public void close() {
        ColoredPrint.info("ProjectManager Closed. ");
        try {
            if (!this.noWrite) {
                this.save();
            }
        } catch (Exception e) {
            ColoredPrint.error("Save project failed. ");
            ColoredPrint.error(e.toString());
            e.printStackTrace();
        }

        List<DomainFile> domainFileContainer = new ArrayList<>();
        TransientDataManager.getTransients(domainFileContainer);
        if (domainFileContainer.size() > 0) {
            TransientDataManager.releaseFiles(this);
        }

        this.project.close();
        
        if (this.isTemporary) {
            try {
                FileUtils.deleteDirectory(locator.getProjectDir());
                locator.getMarkerFile().delete(); // delete gpr file
            } catch (IOException e) {
                ColoredPrint.error("Delete project failed. ");
                ColoredPrint.error(e.toString());
                e.printStackTrace();
            }
        }
    }

    private static class HeadlessGhidraProjectManager extends DefaultProjectManager {
        // this exists just to allow access to the constructor
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
}
