package com.gsat.core.identifier.functions;

import org.apache.commons.lang3.tuple.Pair;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Strtoul extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        {
            FuncFeature vxFeatures = new FuncFeature();
            vxFeatures.setParamNumRange(Pair.of(3,3));
            vxFeatures.setCalledFuncNumRange(Pair.of(1,5));
            vxFeatures.setCallNumRange(Pair.of(1,5));
            vxFeatures.setHasLoop(true);
            vxFeatures.setHasRetVal(true);
            vxFeatures.setBodySizeRange(Pair.of(300,600));
            vxFeatures.setCfgEdgeRange(Pair.of(40,100));
            vxFeatures.setCfgBlockRange(Pair.of(20,60));
            //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
            vxFeatures.setCriticalIndex(List.of(-1));
    //        vxFeatures.setFuncType(this.dataSink);
            ret.add(vxFeatures);
        }
        {
            FuncFeature vxFeatures = new FuncFeature();
            vxFeatures.setParamNumRange(Pair.of(3,3));
            vxFeatures.setCalledFuncNumRange(Pair.of(1,1));
            vxFeatures.setCallNumRange(Pair.of(1,1));
            vxFeatures.setHasLoop(true);
            vxFeatures.setHasRetVal(true);
            vxFeatures.setBodySizeRange(Pair.of(0, 50));
            vxFeatures.setCfgEdgeRange(Pair.of(0, 10));
            vxFeatures.setCfgBlockRange(Pair.of(1, 10));
            //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
            vxFeatures.setCriticalIndex(List.of(-1));
    //        vxFeatures.setFuncType(this.dataSink);
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
            args.add((long) 0);
            args.add((long) 0);
            ftd.setArguments(args);

            Map<Long,byte[]> preMem = new HashMap<>();
            preMem.put((long)0x8000,"0x8000000000000000\00".getBytes());
            ftd.setPresetMem(preMem);
    
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"0x8000000000000000\00".getBytes());
            byte[] ret_value = {
                (byte) 0x00, 
                (byte) 0x80,  (byte) 0x00, (byte) 0x00, (byte) 0x00, 
                (byte) 0x00,  (byte) 0x00, (byte) 0x00, (byte) 0x00, 
            };
            ftd.setRetVal(ret_value);
            ftd.setConditions(conditions);
            ret.add(ftd);
        }
        {
            FuncTestData ftd = new FuncTestData();
            List<Long> args = new ArrayList<>();
            args.add((long) 0x8000);
            args.add((long) 0);
            args.add((long) 16);
            ftd.setArguments(args);

            Map<Long,byte[]> preMem = new HashMap<>();
            preMem.put((long)0x8000,"0x1234 This is test".getBytes());
            ftd.setPresetMem(preMem);
    
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"0x1234 This is test".getBytes());
            byte[] ret_value = {
                (byte) 0x12,  (byte) 0x34
            };
            ftd.setRetVal(ret_value);
            ftd.setConditions(conditions);
            ret.add(ftd);
        }
        return ret;
    }

    @Override
    public String getFuncName() {
        return "strtoul";
    }

    @Override
    public String getFuncSign() {
        return "unsigned long strtoul(char * str, char **endptr, int base)";
    }
}
