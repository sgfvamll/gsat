package com.gsat.core.identifier.functions;

import org.apache.commons.lang3.tuple.Pair;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Memcpy extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(2,3));
        vxFeatures.setCallNumRange(Pair.of(0,5));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,5));
        // vxFeatures.setHasLoop(false);
        vxFeatures.setHasRetVal(true);  // TODO: hasRetVal Check may be inaccurate, maybe remove it
        vxFeatures.setBodySizeRange(Pair.of(20,300));
        vxFeatures.setCfgEdgeRange(Pair.of(0,30));
        vxFeatures.setCfgBlockRange(Pair.of(1,20));
        vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(2,3));
        vxFeatures.setFuncType(this.dataSink);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        {
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
            conditions.put((long)0x8000,"abcabca".getBytes());
            ftd.setConditions(conditions);
            ret.add(ftd);
        }
        {
            FuncTestData ftd = new FuncTestData();
            List<Long> args = new ArrayList<>();
            args.add((long) 0x8000);
            args.add((long) 0x4000);
            args.add((long) 4);
            ftd.setArguments(args);
    
            Map<Long,byte[]> preMem = new HashMap<>();
            preMem.put((long)0x8000,"1\00x23".getBytes());
            preMem.put((long)0x4000,"a\00abc".getBytes());
            ftd.setPresetMem(preMem);
    
            Map<Long,byte[]> conditions = new HashMap<>();
            conditions.put((long)0x8000,"a\00abc".getBytes());
            conditions.put((long)0x4000,"a\00abc".getBytes());
            ftd.setConditions(conditions);
            ret.add(ftd);
        }

        return ret;
    }

    @Override
    public String getFuncName() {
        return "memcpy";
    }

    @Override
    public String getFuncSign() {
        return "void * memcpy (void * destin, void * source, int n)";
    }

    //must startswith customCheck
//    public boolean customCheckTest() {
//        System.out.println(program);
//        System.out.println(emuHelper);
//        System.out.println("in customCheckTest");
//        return true;
//    }
}
