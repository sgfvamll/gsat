package com.gsat.core.identifier.functions;

import org.apache.commons.lang3.tuple.Pair;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Strchr extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        {
            FuncFeature vxFeatures = new FuncFeature();
            vxFeatures.setParamNumRange(Pair.of(2,2));
            vxFeatures.setCalledFuncNumRange(Pair.of(0,0));
            vxFeatures.setCallNumRange(Pair.of(0,0));
            vxFeatures.setHasLoop(true);
            vxFeatures.setHasRetVal(true);
            vxFeatures.setBodySizeRange(Pair.of(20,250));
            vxFeatures.setCfgEdgeRange(Pair.of(0,50));
            vxFeatures.setCfgBlockRange(Pair.of(1,30));
            ret.add(vxFeatures);
        }
        {
            FuncFeature vxFeatures = new FuncFeature();
            vxFeatures.setParamNumRange(Pair.of(2,2));
            vxFeatures.setCalledFuncNumRange(Pair.of(1,3));
            vxFeatures.setCallNumRange(Pair.of(1,3));
            vxFeatures.setHasRetVal(true);
            vxFeatures.setBodySizeRange(Pair.of(0,50));
            vxFeatures.setCfgEdgeRange(Pair.of(0,10));
            vxFeatures.setCfgBlockRange(Pair.of(1,10));
            ret.add(vxFeatures);
        }
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        {
            FuncTestData ftd = new FuncTestData();

            List<Long> args = new ArrayList<>();
            args.add((long) 0x8000);
            args.add((long) 0x63);
            ftd.setArguments(args);
    
            Map<Long,byte[]> preMem = new HashMap<>();
            preMem.put((long)0x8000,"acdce\00".getBytes());
            ftd.setPresetMem(preMem);
    
            // Big endian 2's complement represention. 
            byte[] ret_value = {
                (byte) 0x00,  (byte) 0x80,  (byte) 0x01
            };
            ftd.setRetVal(ret_value);
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"acdce\00".getBytes());
            ftd.setConditions(conditions);
            ret.add(ftd);
        }
        {
            FuncTestData ftd = new FuncTestData();

            List<Long> args = new ArrayList<>();
            args.add((long) 0x8000);
            args.add((long) 0x63);
            ftd.setArguments(args);
    
            Map<Long,byte[]> preMem = new HashMap<>();
            preMem.put((long)0x8000,"x\00abc".getBytes());
            ftd.setPresetMem(preMem);
    
            byte[] ret_value = {
                (byte) 0x00
            };
            ftd.setRetVal(ret_value);
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"x\00abc".getBytes());
            ftd.setConditions(conditions);
            ret.add(ftd);
        }
    
        return ret;
    }

    @Override
    public String getFuncName() {
        return "strchr";
    }

    @Override
    public String getFuncSign() {
        return "char * strchr(char * str, int c)";
    }
}
