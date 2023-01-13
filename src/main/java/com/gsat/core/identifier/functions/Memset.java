package com.gsat.core.identifier.functions;

import org.apache.commons.lang3.tuple.Pair;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Memset extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(3,3));
        vxFeatures.setCallNumRange(Pair.of(0,1));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,1));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);  
        vxFeatures.setBodySizeRange(Pair.of(0,200));
        vxFeatures.setCfgEdgeRange(Pair.of(0,25));
        vxFeatures.setCfgBlockRange(Pair.of(1,20));
        vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8000);
        args.add((long) 0x61);
        args.add((long) 5);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"\00\00abc".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"aaaaa".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "memset";
    }

    @Override
    public String getFuncSign() {
        return "void *memset(void *str, int c, int n)";
    }

    //must startswith customCheck
//    public boolean customCheckTest() {
//        System.out.println(program);
//        System.out.println(emuHelper);
//        System.out.println("in customCheckTest");
//        return true;
//    }
}
