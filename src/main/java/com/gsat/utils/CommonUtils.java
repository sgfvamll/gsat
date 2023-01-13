package com.gsat.utils;

import java.util.UUID;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import org.json.JSONObject;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class CommonUtils {

    public static String createUUID() {
        String uuid = UUID.randomUUID().toString();
        uuid = uuid.replace("-", "");

        return uuid;
    }

    public static void dumpLongStringMap(Map<Long, HashSet<String>> results, String savePath) {
        BufferedWriter bw = null;
        try {
          JSONObject obj = new JSONObject();
          for(var entry: results.entrySet()) {
            String addrKey = String.format("0x%x",entry.getKey());
            obj.put(addrKey, entry.getValue());
          }
          bw = new BufferedWriter(new FileWriter(savePath));
          bw.write(obj.toString(4));
        } catch (IOException e) {
            ColoredPrint.error("Fail to store raw result.");
            ColoredPrint.error(e.toString());
            e.printStackTrace();
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

    public static PcodeOp findFirstCall(HighFunction hfucntion) {
        ArrayList<PcodeBlockBasic> blocks = hfucntion.getBasicBlocks();
        for (PcodeBlockBasic bb:blocks) {
            Iterator<PcodeOp> iter =  bb.getIterator();
            while(iter.hasNext()) {
                PcodeOp opItem = iter.next();
                if (opItem.getOpcode() == PcodeOp.CALL) {
                    return opItem;
                }
            }
        }
        return null;
    }

    public static PcodeOp findLastCall(HighFunction hfucntion) {
        ArrayList<PcodeBlockBasic> blocks = hfucntion.getBasicBlocks();
        PcodeOp lastOp = null;
        for (PcodeBlockBasic bb:blocks) {
            Iterator<PcodeOp> iter =  bb.getIterator();
            while(iter.hasNext()) {
                PcodeOp opItem = iter.next();
                if (opItem.getOpcode() == PcodeOp.CALL) {
                    lastOp = opItem;
                }
            }
        }
        return lastOp;
    }
}
