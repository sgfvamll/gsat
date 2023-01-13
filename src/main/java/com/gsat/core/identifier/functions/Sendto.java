package com.gsat.core.identifier.functions;

import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

public class Sendto extends BaseFunc {
    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(5,10));
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
        return "sendto";
    }

    @Override
    public String getFuncSign() {
        return "ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);";
    }
}
