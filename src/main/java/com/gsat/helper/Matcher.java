package com.gsat.helper;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;

import org.apache.commons.lang3.tuple.Pair;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ConfigurationBuilder;

import com.gsat.core.emur.BaseEmuer;
import com.gsat.core.emur.EmuerFactory;
import com.gsat.core.emur.LanguageId;
import com.gsat.core.identifier.BaseFunc;
import com.gsat.core.identifier.FuncFeature;
import com.gsat.core.identifier.FuncRealFeature;

import java.lang.reflect.Constructor;
import java.util.*;

public class Matcher {

    private static Matcher singleton = null;
    private Program program;
    private FlatProgramAPI flatApi;
    private Set<Class<BaseFunc>> targetClasses;
    private Map<Long,FuncRealFeature> funcRealFeatureMap;
    private DecompInterface decomplib;
    private Set<Class<?>> emuClasses;
    private List<MatchRes> matchResults;
    private Set<Long> unstripedSet;

    private Matcher(Program program) {
        this.program = program;
        this.flatApi = new FlatProgramAPI(program);
        this.funcRealFeatureMap = new HashMap<>();
        this.decomplib = setUpDecompiler();
        this.matchResults = new ArrayList<>();
        this.unstripedSet = new HashSet<>();

        Reflections reflections = new Reflections(new ConfigurationBuilder()
                                                        .forPackages("com.gsat.core.identifier.functions")
                                                        .addScanners(new SubTypesScanner())
                                                        .addScanners(new TypeAnnotationsScanner()));
        Set<Class<? extends BaseFunc>> subClasses = reflections.getSubTypesOf(BaseFunc.class);
        Set<Class<BaseFunc>> targetClasses = new HashSet<>();

        for(Class<?> item: subClasses) {
            if (BaseFunc.class.isAssignableFrom(item)) {
                Class<BaseFunc> realClass = (Class<BaseFunc>) item;
                targetClasses.add(realClass);
            }
        }
        this.targetClasses = targetClasses;
        Reflections emuReflects = new Reflections(new ConfigurationBuilder()
                                                        .forPackages("com.gsat.core.emur.emuer")
                                                        .addScanners(new SubTypesScanner())
                                                        .addScanners(new TypeAnnotationsScanner()));
 
        emuClasses = reflections.getTypesAnnotatedWith(LanguageId.class);
    }

    private Matcher() {

    }


    public static Matcher getInstance(Program program) {
        if (singleton == null) {
            singleton = new Matcher(program);
        }
        return singleton;
    }


    private void preHanleRes() {
        HashMap<String,Integer> records = new HashMap<>();

        for (MatchRes item:matchResults) {
            String funcName = item.getFuncName();
            if (!records.containsKey(funcName)) {
                records.put(funcName, 0);
                continue;
            } else {
                int count = records.get(funcName);
                records.put(funcName,count + 1);
                String newFuncName = funcName + "__" + (count + 1);
                item.setFuncName(newFuncName);
                item.setFuncSign(item.getFuncSign().replaceFirst(funcName,newFuncName));
            }
        }

        List<MatchRes> thunkList = new ArrayList<>();
        for (MatchRes item:matchResults) {
            Address funcAddr = flatApi.toAddr(item.getOffset());
            Function thisFunc = flatApi.getFunctionAt(funcAddr);
            Address[] thunks = thisFunc.getFunctionThunkAddresses(true);
            if (thunks != null) {
                for (Address thunkAddr:thunks) {
                    String thunkName = "_" + item.getFuncName();
                    String thunkSign = item.getFuncSign().replaceFirst(item.getFuncName(),thunkName);
                    var thunkFunc = program.getFunctionManager().getFunctionAt(thunkAddr);
                    // TODO: there is no thunk function in RTOS, we simply put critical index to null here
                    MatchRes thunkRes = new MatchRes(thunkAddr.getOffset(),thunkName,thunkSign, null,null, thunkFunc.getCallingFunctions(TaskMonitor.DUMMY).size());
                    thunkList.add(thunkRes);
                }
            } else {
                Address thunkAddr = null, callAddr = null;
                int numCallRef = 0;
                /// Traverse all references and step out if there is a thunk function for this function. 
                for (var ref : program.getReferenceManager().getReferencesTo(thisFunc.getEntryPoint())) {
                    if (ref.getReferenceType() == RefType.THUNK) {
                        thunkAddr = ref.getFromAddress();
                        numCallRef = 0;
                        break;
                    } else if (ref.getReferenceType().isCall()) {
                        callAddr = ref.getFromAddress();
                        numCallRef += 1;
                    }
                }
                /// Manually recognize thunk functions.
                if (numCallRef == 1) {
                    var func = program.getFunctionManager().getFunctionContaining(callAddr);
                    // var callInstrMaxAddr = program.getListing().getInstructionAt(callAddr).getMaxAddress();
                    /// If the function body is less than 6 * PointerSize and a tail call is found. Regard it as a thunk function. 
                    if (func.getBody().getNumAddresses() <= 6 * func.getBody().getMinAddress().getPointerSize()) {
                        thunkAddr = func.getEntryPoint();
                    }
                }
                if (thunkAddr != null) {
                    String thunkName = "_" + item.getFuncName();
                    String thunkSign = item.getFuncSign().replaceFirst(item.getFuncName(),thunkName);
                    var thunkFunc = program.getFunctionManager().getFunctionAt(thunkAddr);
                    // TODO: there is no thunk function in RTOS, we simply put critical index to null here
                    MatchRes thunkRes = new MatchRes(thunkAddr.getOffset(),thunkName,thunkSign, null,null, thunkFunc.getCallingFunctions(TaskMonitor.DUMMY).size());
                    thunkList.add(thunkRes);
                }
            }
        }
        matchResults.addAll(thunkList);

        Options props = program.getOptions(Program.PROGRAM_INFO);
        String orgImageBaseStr = props.getString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "0x0");
        long orgImageBase = Long.decode(orgImageBaseStr);
        var rebaseOffset = orgImageBase - program.getImageBase().getOffset();

        /// Rebase the results 
        for (var result: matchResults) {
            result.setOffset(result.getOffset()+rebaseOffset);
        }
    }

    public List<MatchRes> getMatchResults() {
        return matchResults;
    }
    public Set<Long> getunstripedSet() {
        return unstripedSet;
    }

    public void doMatch() {
        Class<BaseEmuer> thisEmuerClass = EmuerFactory.buildEmuer(program,emuClasses);
        if (thisEmuerClass == null) {
            System.out.println("No emuer found for current binary arch.");
            System.exit(1);
        }
        for (Class<BaseFunc> item:targetClasses) {
//            if (!item.getName().endsWith("Strncmp")) {
//                continue;  
//            }
            Constructor<BaseFunc> bfCon = null;
            try {
                bfCon = item.getConstructor(new Class[]{});
                BaseFunc funcInfo = bfCon.newInstance();
                /// Used for debugging. 
                // if (funcInfo.getFuncName() != "strlen") {
                //     continue;
                // }
                funcInfo.setMatcher(this);
                funcInfo.setTOTAL_FUNC_NUM(program.getFunctionManager().getFunctionCount());
                doOneMatch(funcInfo,thisEmuerClass);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
        this.preHanleRes();
    }

    private boolean preCheck(List<FuncFeature> features,FuncRealFeature realFeature) {
        return this.preCheck(features,realFeature,null,null);
    }


    private boolean
    preCheck(List<FuncFeature> features,FuncRealFeature realFeature, Function func,Long funcEntryOffset) {
//        if (funcEntryOffset != 0xf2166c0cL) {
//            return false;
//        }
        if (func != null && !funcRealFeatureMap.containsKey(funcEntryOffset)) {
            realFeature.setCalledFuncNum(func.getCalledFunctions(flatApi.getMonitor()).size());
            realFeature.setHasRetVal(!func.hasNoReturn());
            realFeature.setBodySize((int) (func.getBody().getMaxAddress().getOffset() - func.getBody().getMinAddress().getOffset()));
            realFeature.setXrefsRange(func.getCallingFunctions(flatApi.getMonitor()).size());
        }
        for (FuncFeature featureItem: features) {

            Pair<Integer,Integer> calledNumFuncRange = featureItem.getCalledFuncNumRange();
            // if (calledNumFuncRange != null) {
            //     int realCalledFuncCount = realFeature.getCalledFuncNum();
            //     if (realCalledFuncCount < calledNumFuncRange.getLeft() || realCalledFuncCount > calledNumFuncRange.getRight()) {
            //         continue;
            //     }
            // }

            Boolean hasRet = featureItem.getHasRetVal();
            // if (hasRet != null && hasRet != realFeature.getHasRetVal()) {
            //     continue;
            // }

            // Pair<Integer,Integer> bodySizeRange = featureItem.getBodySizeRange();
            // if (bodySizeRange != null) {
            //     int realSize = realFeature.getBodySize();
            //     if (realSize < bodySizeRange.getLeft() || realSize > bodySizeRange.getRight()) {
            //         continue;
            //     }
            // }

            // Pair<Integer,Integer> xrefsRange = featureItem.getXrefsRange();
            // if (xrefsRange != null) {
            //     int realXrefsCount = realFeature.getXrefsRange();
            //     if (realXrefsCount < xrefsRange.getLeft() || realXrefsCount > xrefsRange.getRight()) {
            //         continue;
            //     }
            // }
            if (func != null && !funcRealFeatureMap.containsKey(funcEntryOffset)) {
                HighFunction hfunction = null;
                try {
                    DecompileResults dRes = decomplib.decompileFunction(func, decomplib.getOptions().getDefaultTimeout(), this.flatApi.getMonitor());
                    hfunction = dRes.getHighFunction();
                }
                catch (Exception exc) {
                    exc.printStackTrace();
                }
                if (hfunction != null) {
                    // int edgeCount = 0;
                    // for (PcodeBlockBasic pbb:hfunction.getBasicBlocks()) {
                    //     edgeCount += pbb.getOutSize();
                    // }
                    // int callOpcodeNum = 0;
                    // Iterator<PcodeOpAST> opIter =  hfunction.getPcodeOps();
                    // while(opIter.hasNext()) {
                    //     PcodeOpAST opItem = opIter.next();
                    //     if (opItem.getOpcode() == PcodeOp.CALL) {
                    //         callOpcodeNum += 1;
                    //     }
                    // }
                    // realFeature.setCallNum(callOpcodeNum);
                    // realFeature.setCfgBlockNum(hfunction.getBasicBlocks().size());
                    // realFeature.setCfgEdgeNum(edgeCount);
                    realFeature.setParamNum(hfunction.getLocalSymbolMap().getNumParams());
                    // realFeature.setHasLoop(hasloop(hfunction.getBasicBlocks()));
                    funcRealFeatureMap.put(funcEntryOffset,realFeature);
                }
            }

            boolean checkPassed = highCheck(featureItem,realFeature);
            if (!checkPassed) {
                continue;
            }
            return true;
        }
        return false;
    }


    private boolean hasloop(ArrayList<PcodeBlockBasic> pbbs) {
        if (pbbs.size() < 1) {
            return false;
        }
        Set<Long> visited = new HashSet<>();
        PcodeBlockBasic firstPBB = pbbs.get(0);
        Queue<PcodeBlock> queue = new LinkedList<>();
        queue.add(firstPBB);

        while(!queue.isEmpty()) {
            PcodeBlock thisPBB = queue.poll();
            Long thisPBBEntryOffset = thisPBB.getStart().getOffset();
            if (visited.contains(thisPBBEntryOffset)) {
                return true;
            } else {
                visited.add(thisPBB.getStart().getOffset());
            }
            for(int i = 0; i < thisPBB.getOutSize();i++) {
                queue.add(thisPBB.getOut(i));
            }
        }
        return false;
    }


    private boolean highCheck(FuncFeature funcFeature, FuncRealFeature realFeature) {
        // Pair<Integer,Integer> callNumRange = funcFeature.getCallNumRange();
        // Pair<Integer,Integer> cfgBlockRange = funcFeature.getCfgBlockRange();
        // Pair<Integer,Integer> cfgEdgeRange = funcFeature.getCfgEdgeRange();
        Pair<Integer,Integer> paramNumRange = funcFeature.getParamNumRange();
        // Boolean hasLoop = funcFeature.getHasLoop();
        // if (hasLoop != null && realFeature.getHasLoop() != null && hasLoop != realFeature.getHasLoop()) {
        //     return false;
        // }
        // if (callNumRange != null && realFeature.getCallNum() != null) {
        //     if (realFeature.getCallNum() < callNumRange.getLeft() || realFeature.getCallNum() > callNumRange.getRight()) {
        //         return false;
        //     }
        // }

        if (paramNumRange != null && realFeature.getParamNum() != null) {
            if (realFeature.getParamNum() < paramNumRange.getLeft() || realFeature.getParamNum() > paramNumRange.getRight()) {
                return false;
            }
        }
        // if (cfgBlockRange != null && realFeature.getCfgBlockNum() != null) {
        //     if (realFeature.getCfgBlockNum() < cfgBlockRange.getLeft() || realFeature.getCfgBlockNum() > cfgBlockRange.getRight()) {
        //         return false;
        //     }
        // }
        // if (cfgEdgeRange != null && realFeature.getCfgEdgeNum() != null) {
        //     if (realFeature.getCfgEdgeNum() < cfgEdgeRange.getLeft() || realFeature.getCfgEdgeNum() > cfgEdgeRange.getRight()) {
        //         return false;
        //     }
        // }
        return true;
    }

    private void doOneMatch(BaseFunc funcInfo,Class<BaseEmuer> emuerClass) {
        List<FuncFeature> features = funcInfo.getFeatures();
        FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
        for (Function func:funcIter){
            long funcEntryOffset = func.getEntryPoint().getOffset();

            /// Used for debugging. 
            // if (0x000373b6 == funcEntryOffset) {
            //     System.out.print("Log\n");
            // }
            // if (0x4E3910 != funcEntryOffset) {
            //     continue;
            // }

            if (unstripedSet.contains(funcEntryOffset)) {
                continue;
            }

            if (func.isThunk()) {
                continue;
            }
            boolean checkPassed = false;
            FuncRealFeature realFuncFeature;
            if (funcRealFeatureMap.containsKey(funcEntryOffset)) {
                realFuncFeature = funcRealFeatureMap.get(funcEntryOffset);
                checkPassed = preCheck(features, realFuncFeature);
            } else {
                realFuncFeature = new FuncRealFeature();
                checkPassed = preCheck(features,realFuncFeature,func,funcEntryOffset);
            }
            if (!checkPassed) {
                continue;
            }
//            System.out.println("Precheck passed, current checking: " + func.getName());
            BaseEmuer thisEmuer = null;
            try {
                Constructor<BaseEmuer> baseEmu = emuerClass.getConstructor(new Class[]{});
                thisEmuer =  baseEmu.newInstance();
            } catch (Exception e) {
                continue;
            }
            thisEmuer.init(program,flatApi,func,funcInfo);
            boolean isMatched = thisEmuer.doEmulate();
            if (isMatched) {
                MatchRes res = new MatchRes(funcEntryOffset,funcInfo.getFuncName(),funcInfo.getFuncSign(), features.get(0).getFuncType(), features.get(0).getCriticalIndex(), realFuncFeature.getXrefsRange());
                matchResults.add(res);
                unstripedSet.add(funcEntryOffset);
//                break;
            }
        }
    }

    public HighFunction getHighFunc(Function func) {
        HighFunction hfunction = null;
        try {
            DecompileResults dRes = decomplib.decompileFunction(func, decomplib.getOptions().getDefaultTimeout(), this.flatApi.getMonitor());
            hfunction = dRes.getHighFunction();
        }
        catch (Exception exc) {
            exc.printStackTrace();
        }
        return hfunction;
    }

    public DecompiledFunction getDecompiledFunc(Function func) {
        DecompiledFunction dfunction = null;
        try {
            DecompileResults dRes = decomplib.decompileFunction(func, decomplib.getOptions().getDefaultTimeout(), this.flatApi.getMonitor());
            dfunction = dRes.getDecompiledFunction();
        }
        catch (Exception exc) {
            exc.printStackTrace();
        }
        return dfunction;
    }


    private DecompInterface setUpDecompiler() {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();

        decompInterface.setOptions(options);

        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");
        if (!decompInterface.openProgram(program)) {
            System.out.printf("Decompiler error: %s\n", decompInterface.getLastMessage());
        }
        return decompInterface;
    }
}
