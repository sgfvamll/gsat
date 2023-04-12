package com.gsat.tools;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;

import java.lang.reflect.Method;

import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ConfigurationBuilder;

import com.gsat.utils.ColoredPrint;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;


public class ToolFactory {
  private static Map<String, Class<? extends BaseTool>> namedTools = new HashMap<>();
  
  static {
    Reflections reflections = new Reflections(new ConfigurationBuilder()
                                    .forPackages("com.gsat.tools")
                                    .addScanners(new SubTypesScanner()));
    Set<Class<? extends BaseTool>> tools = reflections.getSubTypesOf(BaseTool.class);
    for (Class<? extends BaseTool> tool: tools) {
      try {
        Method m = tool.getMethod("getName");
        String toolName = (String)m.invoke(null);
        namedTools.put(toolName, tool);
      } catch (Exception e) {
        // ColoredPrint.error(
        //   String.format("Loading %s class failed. ", tool.getSimpleName()));
        ColoredPrint.error(e.toString());
        e.printStackTrace();
      }
    }
  }

  public static BaseTool initTool(String[] args) {
    Options options = new Options();
    for (Option opt: BaseTool.getBasicOptions()) { options.addOption(opt); }
    HelpFormatter formatter = new HelpFormatter();
    if (args.length < 1) {
      ColoredPrint.error(
        String.format("No tool specifed. Available TOOLs: %s", namedTools.keySet().toString()));
      formatter.printHelp(
        "gsat TOOL [options] target", options, false);
      return null;
    }

    BaseTool tool;
    try {
      Class<? extends BaseTool> toolClz = namedTools.get(args[0]);
      tool = toolClz.getDeclaredConstructor().newInstance();
    } catch (Exception e) {
      ColoredPrint.error(
        String.format("Get %s failed. ", args[0]));
      ColoredPrint.error(
        String.format("Available tools: %s", namedTools.keySet().toString()));
      ColoredPrint.error(e.toString());
      e.printStackTrace();
      return null;
    }
    for (Option opt: tool.getOptions()) { options.addOption(opt); }
    CommandLineParser parser = new DefaultParser();
    CommandLine commandLine;
    try {
      commandLine = parser.parse(options,args);
    } catch (Exception e) {
      ColoredPrint.error(e.toString());
      formatter.printHelp(
          String.format("gsat %s [options] target", args[0]), options, false);
        return null;
    }
    if (!tool.processBasicOptions(commandLine) || 
        !tool.processOptions(commandLine)) {
        tool.close();
        formatter.printHelp(
            String.format("gsat %s [options]", args[0]), options, false);
        return null;
    }
    return tool;
  }


}
