package com.gsat.core.identifier.functions;

import org.apache.commons.lang3.tuple.Pair;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Memmove extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(3,3));
        vxFeatures.setCallNumRange(Pair.of(0,8));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,8));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(50,320));
        vxFeatures.setCfgEdgeRange(Pair.of(8,60));
        vxFeatures.setCfgBlockRange(Pair.of(6,40));
        //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(2,3));
        vxFeatures.setFuncType(this.dataSink);
        ret.add(vxFeatures);

        FuncFeature vxFeatures2 = new FuncFeature();
        vxFeatures2.setParamNumRange(Pair.of(2,3));
        vxFeatures2.setCallNumRange(Pair.of(0,1));
        vxFeatures2.setCalledFuncNumRange(Pair.of(0,1));
        vxFeatures2.setHasLoop(false);
        vxFeatures2.setHasRetVal(true);
        vxFeatures2.setBodySizeRange(Pair.of(20,50));
        vxFeatures2.setCfgEdgeRange(Pair.of(0,0));
        vxFeatures2.setCfgBlockRange(Pair.of(0,1));
        vxFeatures.setCriticalIndex(List.of(2,3));
        ret.add(vxFeatures2);

        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8003);
        args.add((long) 0x8000);
        args.add((long) 4);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"abcd\00abc".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"abcabcd".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "memmove";
    }

    @Override
    public String getFuncSign() {
        return "void * memmove(void * dst, void * src, int len)";
    }

    //must startswith customCheck
//    public boolean customCheckTest() {
//        System.out.println(program);
//        System.out.println(emuHelper);
//        System.out.println("in customCheckTest");
//        return true;
//    }
}
