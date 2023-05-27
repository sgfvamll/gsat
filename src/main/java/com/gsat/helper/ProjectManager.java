package com.gsat.helper;

import generic.stl.Pair;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;

import ghidra.framework.data.TransientDataManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.plugins.importer.tasks.ImportBatchTask;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.InvalidNameException;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

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
        Program program = AutoImporter.importByUsingBestGuess(programFile, domainFolder, programPath, messageLog,
                TaskMonitor.DUMMY);
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
            if (baseAddr == null || baseAddr.equals("")) {
                baseAddr = "0x0";
            }
            List<Pair<String, String>> imageBaseOptions = Arrays.asList(
                    new Pair<>(Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr", baseAddr));
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

    public Program loadProgramFromArArchive(String programPath, String analyzedObjectName)
            throws VersionException, CancelledException, IOException {
        return loadProgramAmongBatch(programPath, analyzedObjectName, "|coff:///");
    }

    public Program loadProgramAmongBatch(String programPath, String targetObjName, String objRelProtocol)
            throws VersionException, CancelledException, IOException {
        /// TODO FIXIT: Loading the same file multiple times will always open the first program created. 
        File programFile = new File(programPath);
        BatchInfo batchInfo = new BatchInfo();
        try {
            FSRL objectFsrl = FSRL.fromString(
                    "file://" + programFile.getAbsolutePath().replace("\\", "/") + objRelProtocol + targetObjName);
            ColoredPrint.info("Loading with FSRL(%s)", objectFsrl.toString());
            batchInfo.addFile(objectFsrl, TaskMonitor.DUMMY);
            Task task = new ImportBatchTask(batchInfo, domainFolder, null, true, false);
            task.run(TaskMonitor.DUMMY);
        } catch (CancelledException | IOException e) {
            e.printStackTrace();
        }
        return openProgram(targetObjName);
    }

    public Program openProgram(String folderPath, String programName)
            throws VersionException, CancelledException, IOException {
        Program program = (Program) domainFolder.getFolder(folderPath).getFile(programName).getDomainObject(this, true,
                false,
                TaskMonitor.DUMMY);
        this.programs.add(program);
        return program;
    }

    public Program openProgram(String programName) throws VersionException, CancelledException, IOException {
        Program program = (Program) domainFolder.getFile(programName).getDomainObject(this, true, false,
                TaskMonitor.DUMMY);
        this.programs.add(program);
        return program;
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

}
