package com.gsat.utils;

import java.util.UUID;

import java.io.File;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
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

    public static boolean fileExists(String json_fp) {
        File file = new File(json_fp);
        try {
            return Files.exists(Paths.get(file.toURI()), LinkOption.NOFOLLOW_LINKS);
        } catch (SecurityException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String readFile(String json_fp) {
        File file = new File(json_fp);
        try {
            return new String(Files.readAllBytes(Paths.get(file.toURI())));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static JSONObject readJson(String json_fp) {
        File file = new File(json_fp);
        try {
            String content = new String(Files.readAllBytes(Paths.get(file.toURI())));
            return new JSONObject(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void writeString(String Content, String savePath) {
        BufferedWriter bw = null;
        try {
            bw = new BufferedWriter(new FileWriter(savePath));
            bw.write(Content);
        } catch (IOException e) {
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

    public static void writeJson(JSONObject obj, String savePath) {
        try (final Writer writer = new FileWriter(new File(savePath))) {
            obj.write(writer);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void dumpLongStringMap(Map<Long, HashSet<String>> results, String savePath) {
        JSONObject obj = new JSONObject();
        for(var entry: results.entrySet()) {
            String addrKey = String.format("0x%x",entry.getKey());
            obj.put(addrKey, entry.getValue());
        }
        writeString(obj.toString(4), savePath);
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
