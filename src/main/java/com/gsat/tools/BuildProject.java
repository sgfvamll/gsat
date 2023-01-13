package com.gsat.tools;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

// Only load and analyze the program. 
public class BuildProject extends BaseTool {
    
    public static String getName() {
        return "build";
    }

    @Override
    Option[] getOptions() {
      return new Option[] {};
    }

    @Override
    Boolean processOptions(CommandLine commandLine) {
        return true;
    }

    @Override
    public Boolean run() {
        return true;
    }
}
