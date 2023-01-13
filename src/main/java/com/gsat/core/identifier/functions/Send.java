package com.gsat.core.identifier.functions;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

public class Send extends BaseFunc {
    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(0,5));
        vxFeatures.setCalledFuncNumRange(Pair.of(1,1));
        vxFeatures.setCallNumRange(Pair.of(1,1));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(100,400));
        vxFeatures.setCfgEdgeRange(Pair.of(10,20));
        vxFeatures.setCfgBlockRange(Pair.of(6,15));
        vxFeatures.setCriticalIndex(List.of(2));
        vxFeatures.setFuncType(this.userInterface);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 1);
        args.add((long) 0x8000);
        args.add((long) 10);
        args.add((long) 0);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"helloworld".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"helloworld".getBytes());
        ftd.setConditions(conditions);

        byte[] ret_value = {
                (byte)0,(byte)-1,(byte)-1,(byte)-1,(byte)-1
        };
        ftd.setRetVal(ret_value);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "send";
    }

    @Override
    public String getFuncSign() {
        return "ssize_t send(int sockfd, void *buf, size_t len, int flags);";
    }

    /**
     * @param emuer
     * @return
     */
//     public boolean customCheckCallInfo(BaseEmuer emuer) {
//         Function thisFunc = emuer.getFunc();
//         HighFunction highFunc = matcher.getHighFunc(thisFunc);
//         if (highFunc == null) {
//             return false;
//         }
// //        FlatProgramAPI flatApi = new FlatProgramAPI(program);

//         PcodeOp firstCallOp = CommonUtils.findLastCall(highFunc);
//         if (firstCallOp == null || firstCallOp.getNumInputs() < 2) {
//             return false;
//         }
//         Varnode thisParam = firstCallOp.getInput(1);
//         PcodeOp defOp = thisParam.getDef();
//         if(defOp == null) {
//             return false;
//         }
//         HashSet<Long> noSet = new HashSet<>();
//         if (defOp.getOpcode() == PcodeOp.MULTIEQUAL) {
//             for (int i =0; i < defOp.getNumInputs(); i++) {
//                 Varnode thisVar = defOp.getInput(i);
//                 Long thisVarVal = new FlowNode(thisVar,program).getValue();
//                 if (thisVarVal != null) {
//                     noSet.add(thisVarVal);
//                 }
//             }
//         }

//         if (noSet.size() > 1 && noSet.contains(0xeL)) {
//             return true;
//         }
//         return false;
//     }
}
