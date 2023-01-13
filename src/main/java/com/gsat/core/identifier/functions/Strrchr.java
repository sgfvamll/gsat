package com.gsat.core.identifier.functions;

import org.apache.commons.lang3.tuple.Pair;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Strrchr extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(2,2));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,3));
        vxFeatures.setCallNumRange(Pair.of(0,3));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(20,150));
        vxFeatures.setCfgEdgeRange(Pair.of(0,10));
        vxFeatures.setCfgBlockRange(Pair.of(1,10));
//        vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        ret.add(vxFeatures);
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
                (byte) 0x00, (byte) 0x80,  (byte) 0x03
            };
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"acdce\00".getBytes());
            ftd.setConditions(conditions);
            ftd.setRetVal(ret_value);
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
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"x\00abc".getBytes());
            ftd.setConditions(conditions);
            ftd.setRetVal(ret_value);
            ret.add(ftd);
        }
        return ret;
    }

    @Override
    public String getFuncName() {
        return "strrchr";
    }

    @Override
    public String getFuncSign() {
        return "char * strrchr(char * str, int c)";
    }
}
