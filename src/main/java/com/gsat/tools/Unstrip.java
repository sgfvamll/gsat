package com.gsat.tools;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.json.JSONArray;

import com.gsat.helper.MatchRes;
import com.gsat.helper.Matcher;
import com.gsat.utils.ColoredPrint;

// Only load and analyze the program. 
public class Unstrip extends BaseTool {
    
    public static String getName() {
        return "unstrip";
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
        // Stage1: Function match based on given function features
        ColoredPrint.info("Emulating...");
        Matcher matcher = Matcher.getInstance(this.program);
        matcher.doMatch();

        List<MatchRes> matchResList = matcher.getMatchResults();

        if (matchResList != null) {
            if (this.outputFile != null) {
                Unstrip.storeRes(matchResList, this.outputFile);
            }
        }

        return true;
    }

    private static void storeRes(List<MatchRes> matchResList, String savePath) {
        BufferedWriter bw = null;
        try {
            JSONArray jArray = new JSONArray();
            for (MatchRes res:matchResList) {
                jArray.put(res.toJsonStr());
            }
            bw = new BufferedWriter(new FileWriter(savePath));
            bw.write(jArray.toString(4));
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
}