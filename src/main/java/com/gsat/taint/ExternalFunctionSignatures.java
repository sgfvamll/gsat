package com.gsat.taint;

import java.util.ArrayList;
import java.util.List;

public class ExternalFunctionSignatures {
    public static class FunctionTaintSignature {
        public int numParameters;
        public boolean hasReturnValue;
        public boolean hasVarags;
        public String name;
        public TaintSet[] taintSets;

        public FunctionTaintSignature(String name, int numParameters, boolean hasReturnValue, boolean hasVarags, int[][] taintSets) {
            this.name = name;
            this.numParameters = numParameters;
            this.hasReturnValue = hasReturnValue;
            this.hasVarags = hasVarags;
            this.taintSets = new TaintSet[taintSets.length];
            for (int i=0;i<taintSets.length;i++) {
                var sinkData = taintSets[i];
                this.taintSets[i] = new TaintSet(sinkData.length);
                for (int j=0;j<sinkData.length;j++) {
                    if (sinkData[j] != 0) 
                        this.taintSets[i].setBit(j);
                }
            }
        }

        public FunctionTaintSignature(String name, int numParameters, boolean hasReturnValue, int[][] taintSets) {
            this(name, numParameters, hasReturnValue, false, taintSets);
        }

        public TaintSet[] getTaintSet() {
            return taintSets;
        }
    };

    static List<FunctionTaintSignature> functionTaintSignatures;
 
    static {
        functionTaintSignatures = new ArrayList<>();
        
        functionTaintSignatures.add(new FunctionTaintSignature(
                "sscanf", 3, true, true, 
                // Sources are function parameters, and sinks are parameters with the return value. 
                // e.g. sscanf has 3 sources and 4 sinks 
                // For every sink, there is a int[] to indicate how it is impacted by the sources. 
                // the first int[] is for the return value. 
                new int[][]{{1, 1, 0}, {0, 0, 0}, {0, 0, 0}, {1, 1, 0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "memcpy", 3, true, false, 
                new int[][]{{0, 1, 1}, {0, 1, 1}, {0, 0, 0}, {0, 0, 0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "read", 3, true, false, 
                new int[][]{{1, 0, 1}, {0, 0, 0}, {1, 0, 1}, {0, 0, 0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "malloc", 1, true, false, 
                new int[][]{{0}, {0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "calloc", 2, true, false, 
                new int[][]{{0,0}, {0,0}, {0,0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "realloc", 2, true, false, 
                new int[][]{{0,0}, {0,0}, {0,0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "fseek", 3, true, false, 
                new int[][]{{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "_TIFFrealloc", 2, true, false, 
                new int[][]{{0,0}, {0,0}, {0,0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "_TIFFmalloc", 1, true, false, 
                new int[][]{{0}, {0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "png_malloc_warn", 2, true, false, 
                new int[][]{{0,0}, {0,0}, {0,0}} 
        ));
        functionTaintSignatures.add(new FunctionTaintSignature(
                "xmlMallocAtomic", 1, true, false, 
                new int[][]{{0}, {0}} 
        ));
    }

    static class FunctionNameMatcher {
        private String rawName; 
        FunctionNameMatcher(String functionName) {
            char[] funcNameChars = functionName.toCharArray();
            int startIdx = 0, endIdx = functionName.length()-1;
            if (funcNameChars[startIdx] == 'j' && funcNameChars[startIdx+1]=='_') {
                startIdx += 2;
            }
            while (funcNameChars[startIdx] == '_') startIdx += 1;
            if (funcNameChars[endIdx]=='0' && funcNameChars[endIdx-1]=='_') {
                endIdx -= 2;
            }
            while (funcNameChars[endIdx] == '_') endIdx -= 1;
            this.rawName = functionName.substring(startIdx, endIdx+1);
        }

        boolean match(String sigName) {
            return rawName.equals(sigName);
        }
    };
    
    static FunctionTaintSignature getExternalFunctionSignature(String name) {
        // List<TaintSet> results = new ArrayList<TaintSet>();
        var matcher = new FunctionNameMatcher(name);
        for (var sig: functionTaintSignatures) {
            if (matcher.match(sig.name)) {
                return sig;
            }
        }
        return null;
    }

}
