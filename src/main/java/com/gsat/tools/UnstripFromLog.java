package com.gsat.tools;

import java.util.HashSet;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.gsat.helper.Recover;
import com.gsat.utils.ColoredPrint;
import com.gsat.utils.CommonUtils;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

public class UnstripFromLog extends BaseTool {

  interface Result extends Map<Long, HashSet<String>> {}

  Long logAddr;
  Integer paramIdx;

  Boolean update;     // Whether to update the ghidra program states after running symbol recover. 

  public static String getName() {
    return "unstrip-from-log";
  }

  @Override
  Option[] getOptions() {
    return new Option[] {
      new Option("lfe","log_func_entry",true,"Log function entrypoint in hex."),
      new Option("i","param_index",true,"Param index"),
      new Option("u","update",false,"Whether to update the ghidra program using the recovered symbols. "),
    };
  }

  @Override
  Boolean processOptions(CommandLine commandLine) {
    if (!commandLine.hasOption("lfe") || !commandLine.hasOption("i")) {
      ColoredPrint.error("The log_func_entry and the param_index options must be given. ");
      return false;
    }
    String logFuncAddr = commandLine.getOptionValue("lfe");
    try {
      if (logFuncAddr.startsWith("0x")) {
        logFuncAddr = logFuncAddr.substring(2);
      }
      logAddr = Long.parseLong(logFuncAddr, 16);
    } catch (NumberFormatException e) {
      ColoredPrint.error("log_func_entry format error, should be a function address in hex.");
      return false;
    }
    try {
      paramIdx = Integer.valueOf(commandLine.getOptionValue("i"));
    } catch(NumberFormatException e) {
      ColoredPrint.error("param_index format error, should be a digit. ");
      return false;
    }
    update = commandLine.hasOption("update");
    return true;
  }

  @Override
  public Boolean run() {
    Recover recover;
    try {
        recover = new Recover(program);
    } catch (Exception e) {
        ColoredPrint.error(e.toString());
        e.printStackTrace();
        return false;
    }
    recover.doRecover(this.logAddr, this.paramIdx);
    var results = recover.getResults();
    ColoredPrint.info(String.format("Recovered symbol size is %d\n", results.size()));
    if (results.size() == 0) { return true; }
    if (this.outputFile != null) {
      CommonUtils.dumpLongStringMap(results, this.outputFile);
    }
    if (this.update) {
      this.recoverSymbolInProgram(results);
    }
    return true;
  }

  private void recoverSymbolInProgram(Map<Long, HashSet<String>> results) {
      ColoredPrint.info("Writing recovered symbols back to the program. ");
      FlatProgramAPI flatApi = new FlatProgramAPI(program);
      for(var entry: results.entrySet()) {
        FunctionSignatureParser parser = new FunctionSignatureParser(
          program.getDataTypeManager(), new DefaultDataTypeManagerService());
        Function funcItem = flatApi.getFunctionAt(flatApi.toAddr(entry.getKey()));
        FunctionDefinitionDataType fddt = null;
        try{
            String oldFuncName = funcItem.getSignature().getName();
            String newSigStr = String.join("___",entry.getValue());
            String thisNew = newSigStr;
            String newSign = funcItem.getSignature().toString().replaceFirst(oldFuncName, thisNew);
            fddt = parser.parse(funcItem.getSignature(), newSign);
        }catch (ParseException | CancelledException e) {
          ColoredPrint.error(
            String.format("Recover symbol for %s failed. ", funcItem.getSignature().getName()));
          e.printStackTrace();
          continue;
        }
        if (fddt == null) { continue; }
        int txId = program.startTransaction("Change Func Sign");
        try {
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
              funcItem.getEntryPoint(), fddt, SourceType.USER_DEFINED,
              true,true
            );
            cmd.applyTo(program,flatApi.getMonitor());
            program.endTransaction(txId, true);
        } catch (Exception e) {
          ColoredPrint.error(String.format("Change Func Sign failed."));
          program.endTransaction(txId, false);
        }
      }
      ColoredPrint.info("End write2Project.");
  }

}
