package com.gsat;

import ghidra.framework.Application;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraJarApplicationLayout;

import java.io.IOException;

import com.gsat.tools.BaseTool;
import com.gsat.tools.ToolFactory;
import com.gsat.utils.ColoredPrint;

public class Main {

    public static void main(String[] args) {

        initGhidraApplication();
        long startTime=System.currentTimeMillis();

        BaseTool tool = ToolFactory.initTool(args);
        if (tool == null) { return; }
        tool.run();
        tool.close();

        long endTime=System.currentTimeMillis();
        ColoredPrint.info(
            String.format("%d seconds passed. ", (endTime-startTime)/1000) );
    }


    private static GhidraApplicationLayout getApplicationLayout() throws IOException {
        GhidraApplicationLayout layout;
        try {
            layout = new GhidraApplicationLayout();
        }
        catch (IOException e) {
            layout = new GhidraJarApplicationLayout();

        }
        return layout;
    }

    private static void initGhidraApplication() {
        ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();

        if (!Application.isInitialized()) {

            try{
                Application.initializeApplication(getApplicationLayout(), configuration);
            } catch (Exception e) {
                //Unparseable date: "01-Jan-1904 00:00:00"
                //just ignore
            }
            LoggingInitialization.initializeLoggingSystem();
        }
    }

}
