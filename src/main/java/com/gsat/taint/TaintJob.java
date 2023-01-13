package com.gsat.taint;

import java.util.*;
import java.util.function.Predicate;

import com.gsat.taint.TaintEngine.Strategy;
import com.gsat.taint.sources.IntOpSource;
import com.gsat.taint.sources.MergedSource;
import com.gsat.taint.sources.TaintSource;
import com.gsat.taint.sources.TaintSource.SourceType;
import com.gsat.taint.sources.TaintSource.StorageType;
import com.gsat.utils.ColoredPrint;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Reference;

public class TaintJob {
    enum Status {
        NotInited, 
        Running,
        Suspended,
        Finished,
    };

    private TaintEngine engine;
    private HighFunction hfunc;
    /// Only local taints are propagated, global taints are mapped by local taints. 
    private List<MergedSource> localTaintSources;
    private Map<VarnodeAST, TaintSink> taintSinks;
    private Map<VarnodeAST, MergedSource> intermidiateTaintSources;
    private Map<TaintSink, TaintResult> taintResults;

    private Queue<VarnodeAST> workList;
    private Map<VarnodeAST, TaintSet> state;
    private Status status = Status.NotInited;
    /// TODO(SGFvamll): refactor status management (all managed by self). And notify TaintEngine. 
    private Queue<Pair<PcodeOpAST, VarnodeAST>> suspendedVarnodeASTs;

    private Set<PcodeOpAST> returnPcodeOpASTs;
    private long inspectedFunc = 0;

    public TaintJob(TaintEngine engine, HighFunction hfunc) {
        this.engine = engine;
        this.hfunc = hfunc;
        this.workList = new LinkedList<>();
        this.localTaintSources = new ArrayList<>();
        this.taintSinks = new HashMap<>();
        this.taintResults = new HashMap<>();
        this.suspendedVarnodeASTs = new ArrayDeque<>();
        this.intermidiateTaintSources = new HashMap<>();
        this.state = new HashMap<>();
        this.returnPcodeOpASTs = new LinkedHashSet<>();
    }

    private int getSourceId(VarnodeAST maybeSource) {
        int index = 0;
        for (var source : localTaintSources) {
            if (source.getVarNodeAST().equals(maybeSource)) {
                return index;
            }
            index += 1;
        }
        return -1;
    }

    public List<TaintSet> requestSignatureState(HashMap<VarnodeAST, List<TaintSource>> sources, List<VarnodeAST> sinks) {
        List<Integer> sourceIds = new ArrayList<Integer>();
        boolean succ = true;
        /// Add non-existing local sources and the global mappings of a local taint source. 
        for (var source : sources.keySet()) {
            Integer id = getSourceId(source);
            if (id == -1) {
                /// Add new local taint source if it does not exist. 
                id = addTaintSource(new MergedSource(
                        source, hfunc.getFunction().getEntryPoint(), SourceType.Local, StorageType.PointerOrValue));
                succ = false;
            }
            sourceIds.add(id);
            /// Add global mappings. 
            /// TODO(SGFvamll): Gloabl sources mapped from parameters should not be of type `Global` (not propagated on RETURN). 
            localTaintSources.get(id).addSources(sources.get(source));
        }
        if (!succ || status != Status.Finished)
            /// Requested results are not successfully found. Waiting for this job to be finished. 
            return null;
        /// Return the requested results. 
        List<TaintSet> outStates = new ArrayList<>();
        for (var sink : sinks) {
            var outState = new TaintSet(sourceIds.size());
            outStates.add(outState);
            var taintSetOut = state.get(sink);
            if (taintSetOut == null) continue;
            var oIdx = 0;
            for (var sourceId : sourceIds) {
                if (taintSetOut.testBit(sourceId)) {
                    outState.setBit(oIdx);
                }
                oIdx += 1;
            }
        }
        return outStates;
    }

    public String getFuctionName() {
        return hfunc.getFunction().getName();
    }

    public void addTaintSink(TaintSink sink) {
        taintSinks.put(sink.getVarNodeAST(), sink);
    }

    public int getLocalSourceID(TaintSource source) {
        int idx = 0;
        for (var src : localTaintSources) {
            /// So far, only one propagation rule used. So one local source for every VarNodeAST is enough. 
            if (src.getVarNodeAST().equals(source.getVarNodeAST()))
                return idx;
            idx += 1;
        }
        return -1;
    }

    public Status getState() {
        return status;
    }

    /// Return the id of added taint source.
    public int addTaintSource(MergedSource source) {
        if (source.getid() != -1 && localTaintSources.get(source.getid()).equals(source))
            return source.getid();
        int id = getLocalSourceID(source);
        if (id != -1)
            return id;
        id = localTaintSources.size();
        source.setid(id);
        localTaintSources.add(source);
        assert source.getVarNodeAST() != null;
        workList.add(source.getVarNodeAST());
        if (status != Status.NotInited) {
            var taintSet = new TaintSet(localTaintSources.size());
            taintSet.setBit(id);
            state.put(source.getVarNodeAST(), taintSet);
        }
        return id;
    }

    /// Add a taint source and map it to an global source
    public boolean addTaintSourceWithGlobalMapping(MergedSource localSource, TaintSource globalSource) {
        addTaintSource(localSource);
        return localSource.addSource(globalSource);
    }

    private void initState() {
        if (status != Status.NotInited) {
            return;
        }
        status = Status.Running;
        for (var taintSource : localTaintSources) {
            var taintSet = new TaintSet(localTaintSources.size());
            taintSet.setBit(taintSource.getid());
            state.put(taintSource.getVarNodeAST(), taintSet);
        }
    }

    /// Add a placeholder TaintResult to show this sink is reachable from some sources. 
    private void addTaintResult(TaintSink sink) {
        var taintResult = taintResults.get(sink);
        if (taintResult == null) {
            taintResult = new TaintResult(sink);
            taintResults.put(sink, taintResult);
            ColoredPrint.info("New taint result at the sink point 0x%x. ", sink.getAddress().getOffset());
        }
    }

    /// Collect taint results after the jobs are finished. 
    public List<TaintResult> generateTaintResults() {
        assert status == Status.Finished: String.format("%s: %s", getFuctionName(), status.toString());
        for (var sink: taintResults.keySet()) {
            var taintResult = taintResults.get(sink);
            var stateBitset = state.get(sink.getVarNodeAST());
            for (int i = 0; i < stateBitset.getBitSize(); i++) {
                if (stateBitset.testBit(i)) {
                    taintResult.addSource(localTaintSources.get(i));
                }
            }
        }
        return new ArrayList<TaintResult>(taintResults.values());
    }

    private List<TaintSource> collectLocalTaintSources(TaintSet taintSet, Predicate<TaintSource> filter) {
        var lobalSources = new ArrayList<TaintSource>();
        if (taintSet == null) return lobalSources;
        for (int i=0;i<taintSet.getBitSize();i++) {
            if (taintSet.testBit(i)) {
                var src = localTaintSources.get(i);
                if (!filter.test(src)) continue;
                lobalSources.add(src);
            }
        }
        return lobalSources;
    }

    private List<TaintSource> collectDirectGlobalTaintSources(TaintSet taintSet, Predicate<TaintSource> filter) {
        var localSources = new ArrayList<TaintSource>();
        if (taintSet == null) return localSources;
        for (int i=0;i<taintSet.getBitSize();i++) {
            if (taintSet.testBit(i)) {
                localTaintSources.get(i).collectDirectGlobalTaintSourcesOnLocal(localSources, filter);
            }
        }
        return localSources;
    }

    public void setUnSuspended() {
        assert status == Status.Suspended;
        status = Status.Running;
    }

    public void setUnFinished() {
        assert status == Status.Finished;
        status = Status.Running;
    }

    public void setFinished() {
        status = Status.Finished;
    }

    public boolean isFinished() {
        return status == Status.Finished;
    }

    public boolean isNotInited() {
        return status == Status.NotInited;
    }

    public boolean isRunning() {
        return status == Status.Running;
    }

    public Status run() {
        initState();
        assert status == Status.Running;
        while (!suspendedVarnodeASTs.isEmpty()) {
            var pairJob = suspendedVarnodeASTs.peek();
            visit(pairJob.first, pairJob.second);
            if (status == Status.Suspended)
                break;
            suspendedVarnodeASTs.remove();
        }
        while (!workList.isEmpty()) {
            if (status == Status.Suspended)
                break;
            VarnodeAST varnodeAST = workList.poll();
            var cosserpondingSink = taintSinks.get(varnodeAST);
            if (cosserpondingSink != null) {
                addTaintResult(cosserpondingSink);
            }
            var iter = varnodeAST.getDescendants();
            while (iter.hasNext()) {
                PcodeOpAST pcodeOpAST = (PcodeOpAST) iter.next();
                // if (pcodeOpAST.getSeqnum().getTarget().getOffset() == 0x10144+ 0x10000) {
                //     System.out.println(getFuctionName());
                // }
                if (status == Status.Suspended) {
                    suspendedVarnodeASTs.add(new Pair<>(pcodeOpAST, varnodeAST));
                    continue;
                }
                visit(pcodeOpAST, varnodeAST);
                if (status == Status.Suspended) {
                    suspendedVarnodeASTs.add(new Pair<>(pcodeOpAST, varnodeAST));
                }
            }
        }
        if (workList.isEmpty() && suspendedVarnodeASTs.isEmpty()) {
            status = Status.Finished;
            propagateBackOnCallGraph();
        }
        assert status == Status.Finished || status == Status.Suspended;
        return status;
    }

    private void propagateBackOnCallGraph() {
        /// TODO(SGFvamll): Need Fix.
        /// The state cossesponding to the VarNodeAST represents the init state of the parameters.  
        /// But when propagating back, we need the states of (parameter's) storages after propagation. 
        Map<Integer, TaintSource> outSources = new HashMap<>();
        Predicate<TaintSource> globalSourceFilter = souce -> souce.getSourceType() == SourceType.Global;
        for (int i=0; i< hfunc.getFunction().getParameterCount(); i++) {
            VarnodeAST node = null;
            boolean modified = false;
            Set<TaintSource> sourcesTopropagate = new HashSet<>();
            if (i == 0) {
                for (var returnPcodeOpAST: returnPcodeOpASTs) {
                    var returnVarNodeAST = (VarnodeAST) returnPcodeOpAST.getOutput();
                    if (returnVarNodeAST == null) continue;
                    TaintSet taintSet = state.get(returnVarNodeAST);
                    // Global taint sources should be propagate back to the callers. 
                    sourcesTopropagate.addAll(collectDirectGlobalTaintSources(taintSet, globalSourceFilter));
                    if (node == null) node = returnVarNodeAST;
                }
            } else {
                for (var storage: hfunc.getFunction().getParameter(i).getVariableStorage().getVarnodes()) {
                    var iter = hfunc.getVarnodes(storage.getAddress());
                    while (iter.hasNext()) {
                        var varnodeAST = iter.next();
                        if (varnodeAST.getDef() != null) continue;  /// not a parameter node 
                        TaintSet taintSet = state.get(varnodeAST);
                        sourcesTopropagate.addAll(collectDirectGlobalTaintSources(taintSet, globalSourceFilter));
                        if (node == null) node = varnodeAST;
                    }
                }
            }
            if (sourcesTopropagate.size() == 0) continue;
            MergedSource intermidiateTaintSource = intermidiateTaintSources.get(node);
            if (intermidiateTaintSource == null) {
                intermidiateTaintSource = new MergedSource(node, hfunc.getFunction().getEntryPoint(), SourceType.Default, StorageType.PointerOrValue);
                intermidiateTaintSources.put(node, intermidiateTaintSource);
                modified = true;
            }
            modified |= intermidiateTaintSource.addSources(sourcesTopropagate);
            if (modified)
                outSources.put(i, intermidiateTaintSource);
        }
        if (outSources.size() != 0)
            engine.propagateBackOnCallGraph(this.hfunc.getFunction(), outSources);
    }

    public boolean introduceGlobalTaintsAtCallSite(Reference ref, Map<Integer, TaintSource> sources) {
        PcodeOpAST callsiteOp = null;
        Address callsiteAddress = ref.getFromAddress();
        var pcodeOpASTIter = hfunc.getPcodeOps(callsiteAddress);
        boolean introduced = false;
        /// Get callsiteOp
        while (pcodeOpASTIter.hasNext()) {
            var pcodeOpAST = pcodeOpASTIter.next();
            if (pcodeOpAST.getOpcode() == PcodeOp.CALL || pcodeOpAST.getOpcode() == PcodeOp.CALLIND
                    || pcodeOpAST.getOpcode() == PcodeOp.CALLOTHER) {
                callsiteOp = pcodeOpAST;
                break;
            }
        }
        if (callsiteOp == null) return false;
        for (Map.Entry<Integer, TaintSource> entry: sources.entrySet()) {
            VarnodeAST node = null;
            if (entry.getKey() == 0) {
                node = (VarnodeAST) callsiteOp.getOutput();
            } else {
                node = (VarnodeAST) callsiteOp.getInput(entry.getKey());
            }
            if (node == null) continue;
            introduced |= addTaintSourceWithGlobalMapping(
                new MergedSource(node, callsiteAddress, SourceType.Local, StorageType.PointerOrValue), entry.getValue());
        }
        return introduced;
    }

    private TaintSet getOrCreateState(VarnodeAST key) {
        TaintSet taintSetOut = state.get(key);
        if (taintSetOut == null) {
            taintSetOut = new TaintSet(localTaintSources.size());
            state.put(key, taintSetOut);
        }
        return taintSetOut;
    }

    private void propagateOnTheInput(VarnodeAST out, VarnodeAST in) {
        TaintSet taintSetIn = state.get(in);
        TaintSet taintSetOut = getOrCreateState(out);
        boolean modified = taintSetOut.doUnion(taintSetIn);
        if (modified) {
            assert out != null;
            workList.add(out);
            if (hfunc.getFunction().getEntryPoint().getOffset() == inspectedFunc)
                ColoredPrint.info("propagate taint to %s at 0x%x", out.toString(),
                        out.getDef().getSeqnum().getTarget().getOffset());
        }
    }

    private boolean pcodeIsLoadStore(int opcode) {
        return opcode == PcodeOpAST.LOAD || opcode == PcodeOpAST.STORE;
    }

    private boolean pcodeIsCall(int opcode) {
        return opcode == PcodeOpAST.CALL;
    }

    private boolean pcodeIsLikelyPointerArthOp(int opcode) {
        List<Integer> intOpSet = Arrays.asList(
            PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, 
            PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, 
            PcodeOp.INT_LEFT, PcodeOp.INT_OR, PcodeOp.INT_AND, 
            PcodeOp.CAST, PcodeOp.COPY, PcodeOp.PIECE, PcodeOp.SUBPIECE
        );
        return intOpSet.contains(opcode);
    }

    private boolean pcodeIsIntArthOp(int opcode) {
        List<Integer> intOpSet = Arrays.asList(
            PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, 
            PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW, 
            PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, 
            PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, 
            PcodeOp.CAST, PcodeOp.COPY, PcodeOp.PIECE, PcodeOp.SUBPIECE,
            PcodeOp.INT_OR, PcodeOp.INT_AND, PcodeOp.INT_NEGATE, PcodeOp.INT_XOR, PcodeOp.INT_2COMP, 
            PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM
        );
        return intOpSet.contains(opcode);
    }

    private boolean pcodeIsCheck(int opcode) {
        List<Integer> intOpSet = Arrays.asList(
            PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL, 
            PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL
        );
        return intOpSet.contains(opcode);
    }

    private boolean nodeIsPointer(VarnodeAST out) {
        /// Determine type according to the high variable type. 
        HighVariable hout = out.getHigh();
        if (hout != null && hout instanceof Pointer) {
            return true;
        }
        LinkedList<VarnodeAST> worklist =  new LinkedList<VarnodeAST>();
        worklist.add(out);
        /// Determine type by uses. 
        while (!worklist.isEmpty()) {
            var node = worklist.poll();
            var pcodeOpASTIter = node.getDescendants();
            while (pcodeOpASTIter.hasNext()) {
                var pcodeOpAST = (PcodeOpAST) pcodeOpASTIter.next();
                var opcode = pcodeOpAST.getOpcode();
                if (pcodeIsLoadStore(opcode)) {
                    if (opcode == PcodeOp.STORE && pcodeOpAST.getInput(2).equals(node))
                        return false;
                    return true;
                }
                if (pcodeIsLikelyPointerArthOp(opcode)) {
                    // worklist.add((VarnodeAST)pcodeOpAST.getOutput());
                }
                if (pcodeIsCall(opcode)) {
                    var callee = engine.getFunctionAt(pcodeOpAST.getInput(0).getAddress());
                    if (callee == null) continue;
                    if (callee.getName().equals("oct_to_int")) {
                        /// TODO... Fix pointer type recognization. 
                        return true;
                    }
                    var idx = 1;
                    if (idx < pcodeOpAST.getNumInputs() && pcodeOpAST.getInput(idx).equals(node)) {
                        idx += 1;
                    }
                    var param = callee.getParameter(idx-1);
                    if (param != null && param.getDataType() instanceof Pointer) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean nodeIsLikelyFollowedByCheck(VarnodeAST out) {
        LinkedList<VarnodeAST> worklist =  new LinkedList<VarnodeAST>();
        worklist.add(out);
        while (!worklist.isEmpty()) {
            var node = worklist.poll();
            var pcodeOpASTIter = node.getDescendants();
            while (pcodeOpASTIter.hasNext()) {
                var pcodeOpAST = (PcodeOpAST) pcodeOpASTIter.next();
                var opcode = pcodeOpAST.getOpcode();
                if (pcodeIsCheck(opcode)) {
                    return true;
                }
                if (pcodeIsIntArthOp(opcode)) {
                    worklist.add((VarnodeAST)pcodeOpAST.getOutput());
                }
            }
        }
        return false;
    }

    private void handleIntroduceIntOpSource(PcodeOpAST pcodeOpAST, VarnodeAST out, VarnodeAST in1, VarnodeAST in2) {
        TaintSet taintSetIn1 = state.get(in1);
        TaintSet taintSetIn2 = state.get(in2);
        TaintSet taintSetOut = getOrCreateState(out);

        // if (pcodeOpAST.getSeqnum().getTarget().getOffset() == 0x21224 + 0x100000) {
        //     System.out.printf("log");
        // }
        var intermidiateTaintSource = intermidiateTaintSources.get(out);
        if (intermidiateTaintSource == null) {
            boolean isLikelyFollowedByCheck = nodeIsLikelyFollowedByCheck(out);
            var intSource = new IntOpSource(out, pcodeOpAST.getSeqnum().getTarget(), SourceType.Local, StorageType.Value, isLikelyFollowedByCheck);
            intSource.setDangerousIntPoint(pcodeOpAST);
            addTaintSource(intSource);  /// Only at the first time, need to add to the worklist. 
            intermidiateTaintSources.put(out, intSource);
            intermidiateTaintSource = intSource;
            taintSetOut.setBit(localTaintSources.size() - 1);
        }

        TaintSet mergedTaintSet = new TaintSet(localTaintSources.size());
        mergedTaintSet.doUnion(taintSetIn1);
        mergedTaintSet.doUnion(taintSetIn2);
        for (int i = 0; i < mergedTaintSet.getBitSize(); i++) {
            if (mergedTaintSet.testBit(i)) {
                intermidiateTaintSource.addSource(localTaintSources.get(i));
            }
        }
        
    }

    private void handleMaybeIntroduceIntOpSource(PcodeOpAST pcodeOpAST, VarnodeAST out, VarnodeAST in1, VarnodeAST in2) {
        if (!nodeIsPointer(out)) {
            handleIntroduceIntOpSource(pcodeOpAST, out, in1, in2);
        } else {
            /// Regarded As PTRXXX
            propagateOnFirstTwoInputs(pcodeOpAST);
        }
    }

    private void propagateOnFirstTwoInputs(PcodeOpAST pcodeOpAST) {
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(0);
        VarnodeAST in2 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        TaintSet taintSetIn1 = state.get(in1);
        TaintSet taintSetIn2 = state.get(in2);
        TaintSet taintSetOut = getOrCreateState(out);
        boolean modified = false;
        modified |= taintSetOut.doUnion(taintSetIn1);
        modified |= taintSetOut.doUnion(taintSetIn2);
        if (modified) {
            assert out != null;
            workList.add(out);
            if (hfunc.getFunction().getEntryPoint().getOffset() == inspectedFunc)
                ColoredPrint.info("propagate taint to %s at 0x%x", out.toString(),
                        out.getDef().getSeqnum().getTarget().getOffset());
        }
    }

    private void propagateOnAllInputs(VarnodeAST out, PcodeOpAST pcodeOpAST) {
        TaintSet taintSetOut = getOrCreateState(out);
        boolean modified = false;
        for (var input : pcodeOpAST.getInputs()) {
            var in = (VarnodeAST) input;
            var taintSetIn = state.get(in);
            modified |= taintSetOut.doUnion(taintSetIn);
        }
        if (modified) {
            assert out != null;
            workList.add(out);
            if (hfunc.getFunction().getEntryPoint().getOffset() == inspectedFunc)
                ColoredPrint.info("propagate taint to %s at 0x%x", out.toString(),
                        out.getDef().getSeqnum().getTarget().getOffset());
        }
    }

    private void propagateOnAllInputs(PcodeOpAST pcodeOpAST) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnAllInputs(out, pcodeOpAST);
    }

    private void visit_COPY(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_CAST(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_LOAD(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST in0 = (VarnodeAST) pcodeOpAST.getInput(0);
        assert in0.isConstant();
        /// TODO(SGFvamll): Maybe propagate taints according to storage type.
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in1);
    }

    private void visit_STORE(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST in0 = (VarnodeAST) pcodeOpAST.getInput(0);
        assert in0.isConstant();
        /// TODO(SGFvamll): Maybe propagate taints according to storage type.
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST in2 = (VarnodeAST) pcodeOpAST.getInput(2);
        propagateOnTheInput(in1, in2);
    }

    private void visit_BRANCH(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_CBRANCH(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        /// Maybe add sink
    }

    private void visit_BRANCHIND(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        /// Maybe add sink
    }

    private void propagateByStrategy(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        switch (engine.getStrategy()) {
            case Optimistic: 
                break;
            case Heuristic: {
                VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
                if (out != null) {
                    propagateOnTheInput(out, in);
                }
                break;
            }
            case Pessimistic: {
                TaintSet taintSetOut;
                if (pcodeOpAST.getOutput() != null) {
                    propagateOnAllInputs(pcodeOpAST);
                    taintSetOut = state.get((VarnodeAST)pcodeOpAST.getOutput());
                } else {
                    taintSetOut = new TaintSet(localTaintSources.size());
                    for (var input : pcodeOpAST.getInputs()) {
                        var taintSetIn = state.get((VarnodeAST) input);
                        taintSetOut.doUnion(taintSetIn);
                    }
                }
                for (int i=1; i<pcodeOpAST.getNumInputs();i++) {
                    VarnodeAST varnodeAST = (VarnodeAST) pcodeOpAST.getInput(i);
                    HighVariable hvar = varnodeAST.getHigh();
                    /// Only propagate taints to all pointer arguments. 
                    if (hvar != null && !(hvar instanceof Pointer)) continue;
                    TaintSet taintSetIn = getOrCreateState(varnodeAST);
                    if (taintSetIn.doUnion(taintSetOut)) {
                        assert varnodeAST != null;
                        workList.add(varnodeAST);
                    }
                }
                break;
            }
        }
    }

    private void handleExternalCall(PcodeOpAST pcodeOpAST, VarnodeAST in, String externalName) {
        var funcSig = ExternalFunctionSignatures.getExternalFunctionSignature(externalName);
        if (funcSig == null) {
            propagateByStrategy(pcodeOpAST, in);
            return;
        }
        TaintSet[] requestedState = funcSig.taintSets;
        /// propagate the taints according to the obtainted taint signature. 
        boolean callHasOutput = pcodeOpAST.getOutput() != null;
        int numSinks = (callHasOutput? pcodeOpAST.getNumInputs() : pcodeOpAST.getNumInputs()-1);
        assert (requestedState.length - 1) <= numSinks: String.format("%s %d < %d", externalName, requestedState.length, numSinks);
        Set<VarnodeAST> modifiedSet = new HashSet<>();
        for (int i=0;i<numSinks;i++) {
            int stateIdx = i;
            if (!funcSig.hasReturnValue && callHasOutput && i==0) {
                /// Skip the call output since there is no signature for it...
                continue;
            }
            if (funcSig.hasReturnValue && !callHasOutput) {
                stateIdx += 1;
            }
            if (stateIdx >= requestedState.length) {
                /// The Last state can be used for varargs. 
                stateIdx = requestedState.length - 1;
            }
            TaintSet bitset = requestedState[stateIdx];
            /// Translate from sink node in the callee to the node here. 
            VarnodeAST sink;
            if (pcodeOpAST.getOutput() != null) {
                if (i == 0)
                    sink = (VarnodeAST)pcodeOpAST.getOutput();
                else 
                    sink = (VarnodeAST)pcodeOpAST.getInput(i);
            } else {
                sink = (VarnodeAST)pcodeOpAST.getInput(i+1);
            }
            boolean modified = false;
            for (int j=0;j<bitset.getBitSize();j++) {
                if (bitset.testBit(j)) {
                    var inNode = pcodeOpAST.getInput(j+1);
                    TaintSet taintSetOut = getOrCreateState(sink);
                    modified |= taintSetOut.doUnion(state.get(inNode));
                }
            }
            if (modified) {
                assert sink != null;
                modifiedSet.add(sink);
            }
        }
        workList.addAll(modifiedSet);
    }

    /// TODO(SGFvamll): propagate global taints through call and the return value (for non exported parameters taints). 
    private void visit_CALL(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        /// Collect Callee inout nodes (i.e. parameter nodes and return value nodes)
        VarnodeAST calleeNode = (VarnodeAST) pcodeOpAST.getInput(0);
        Address callsiteAddress = pcodeOpAST.getSeqnum().getTarget();

        String externalName = engine.getExternalFunctionName(calleeNode.getAddress());
        if (externalName != null) {
            handleExternalCall(pcodeOpAST, in, externalName);
            return;
        }

        // if (getFuctionName().equals("th_read") && calleeNode.getAddress().getOffset() == 0x011e78) {
        //     System.out.println("log");
        // }

        var parameterNodes = engine.collectCalleeInOutNodes(calleeNode.getAddress(), pcodeOpAST.getNumInputs() - 1);
        if (parameterNodes == null) {
            /// Collecting nodes failed. Do the propagration anyway. 
            propagateByStrategy(pcodeOpAST, in);
            return;
        }
        var requestTaintSinks = new ArrayList<>(parameterNodes.keySet());

        /// Filter out interesting taint sources
        int idx = 1;
        var requestTaintSources = new LinkedHashMap<VarnodeAST, List<TaintSource>>();
        Set<Integer> sourceIdxSet = new HashSet<>(pcodeOpAST.getNumInputs() - 1);
        for (; idx < pcodeOpAST.getNumInputs(); idx++) {
            var node = (VarnodeAST) pcodeOpAST.getInput(idx);
            if (state.get(node)!=null && !state.get(node).isEmpty())
                sourceIdxSet.add(idx-1);    // -1 for the callee node
        }
        /// TODO Refactor
        for (var node: parameterNodes.keySet()) {
            if (sourceIdxSet.contains(parameterNodes.get(node))) {
                var argumentNode = (VarnodeAST) pcodeOpAST.getInput(parameterNodes.get(node)+1);
                var argumentState = state.get(argumentNode);
                var localSources = collectLocalTaintSources(argumentState, i -> true);
                if (localSources.size() != 0) {
                    MergedSource intermidiateTaintSource = intermidiateTaintSources.get(argumentNode);
                    if (intermidiateTaintSource == null) {
                        intermidiateTaintSource = new MergedSource(calleeNode, callsiteAddress, SourceType.Default, StorageType.PointerOrValue);
                        intermidiateTaintSources.put(argumentNode, intermidiateTaintSource);
                    }
                    intermidiateTaintSource.addSources(localSources);
                    localSources = Arrays.asList(intermidiateTaintSource);
                }
                requestTaintSources.put(node, localSources);
            }
        }

        /// Request the taint signature of the callee from another job. 
        List<TaintSet> requestedState = engine.requestSignatureState(
            this, calleeNode.getAddress(), requestTaintSources, requestTaintSinks);
        if (requestedState == null) {
            /// Waiting for the callee job to be finished first. 
            status = Status.Suspended;
            return;
        }
        if (requestedState.size() == 0) {
            /// Cyclic Waiting Found. Do the propagration anyway. 
            propagateByStrategy(pcodeOpAST, in);
            return;
        }
        /// propagate the taints according to the obtainted taint signature. 
        assert requestedState.size() == requestTaintSinks.size();
        Set<VarnodeAST> modifiedSet = new HashSet<>();
        boolean findReturnValue = false;
        for (int i=0;i<requestedState.size();i++) {
            TaintSet bitset = requestedState.get(i);
            /// Translate from sink node in the callee to the node here. 
            Integer sinkIdx = parameterNodes.get(requestTaintSinks.get(i));
            VarnodeAST sink;
            if (sinkIdx == -1) {
                sink = (VarnodeAST)pcodeOpAST.getOutput();
                findReturnValue = true;
            } else 
                sink = (VarnodeAST)pcodeOpAST.getInput(sinkIdx+1);
            if (sink == null) continue;
            boolean modified = false;
            var j = 0;
            for (var reqSource: requestTaintSources.keySet()) {
                if (bitset.testBit(j)) {
                    var sourceIdx = parameterNodes.get(reqSource) + 1;
                    assert sourceIdx != 0;  /// Return node should not be the source
                    var inNode = pcodeOpAST.getInput(sourceIdx);
                    TaintSet taintSetOut = getOrCreateState(sink);
                    modified |= taintSetOut.doUnion(state.get(inNode));
                }
                j += 1;
            }
            if (modified) {
                assert sink != null: String.format("%s %d", externalName, sinkIdx);
                modifiedSet.add(sink);
            }
        }
        if (!findReturnValue && pcodeOpAST.getOutput() != null && engine.getStrategy() != Strategy.Optimistic) {
            propagateOnAllInputs(pcodeOpAST);
        }
        workList.addAll(modifiedSet);
    }

    private void visit_CALLIND(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        /// TODO
        propagateByStrategy(pcodeOpAST, in);
    }

    private void visit_CALLOTHER(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        /// TODO
        propagateByStrategy(pcodeOpAST, in);
    }

    private void visit_RETURN(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        returnPcodeOpASTs.add(pcodeOpAST);
    }

    private void visit_INT_EQUAL(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_NOTEQUAL(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_LESS(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_SLESS(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_LESSEQUAL(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_SLESSEQUAL(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_ZEXT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_INT_SEXT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_INT_ADD(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(0);
        VarnodeAST in2 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        handleMaybeIntroduceIntOpSource(pcodeOpAST, out, in1, in2);
    }

    private void visit_INT_SUB(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(0);
        VarnodeAST in2 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        handleMaybeIntroduceIntOpSource(pcodeOpAST, out, in1, in2);
    }

    private void visit_INT_CARRY(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_SCARRY(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_SBORROW(PcodeOpAST pcodeOpAST, VarnodeAST in) {

    }

    private void visit_INT_2COMP(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_INT_NEGATE(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_INT_XOR(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_AND(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_OR(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_LEFT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(0);
        VarnodeAST in2 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        handleMaybeIntroduceIntOpSource(pcodeOpAST, out, in1, in2);
    }

    private void visit_INT_RIGHT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_SRIGHT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_MULT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST in1 = (VarnodeAST) pcodeOpAST.getInput(0);
        VarnodeAST in2 = (VarnodeAST) pcodeOpAST.getInput(1);
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        handleMaybeIntroduceIntOpSource(pcodeOpAST, out, in1, in2);
    }

    private void visit_INT_DIV(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_REM(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_SDIV(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_INT_SREM(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_PTRADD(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_PTRSUB(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_BOOL_NEGATE(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        /// TODO(SGFvamll): maybe prograte taints
    }

    private void visit_BOOL_XOR(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_BOOL_AND(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_BOOL_OR(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_PIECE(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_SUBPIECE(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnFirstTwoInputs(pcodeOpAST);
    }

    private void visit_POPCOUNT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        propagateOnTheInput(out, in);
    }

    private void visit_MULTIEQUAL(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        propagateOnAllInputs(pcodeOpAST);
    }

    private void visit_INDIRECT(PcodeOpAST pcodeOpAST, VarnodeAST in) {
        VarnodeAST out = (VarnodeAST) pcodeOpAST.getOutput();
        VarnodeAST in0 = (VarnodeAST) pcodeOpAST.getInput(0);
        propagateOnTheInput(out, in0);
    }

    private void visit(PcodeOpAST pcodeOpAST, VarnodeAST varnodeAST) {
        switch (pcodeOpAST.getOpcode()) {
            case PcodeOp.COPY:
                visit_COPY(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.LOAD:
                visit_LOAD(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.STORE:
                visit_STORE(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.BRANCH:
                visit_BRANCH(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.CBRANCH:
                visit_CBRANCH(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.BRANCHIND:
                visit_BRANCHIND(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.CALL:
                visit_CALL(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.CALLIND:
                visit_CALLIND(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.CALLOTHER:
                visit_CALLOTHER(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.RETURN:
                visit_RETURN(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_EQUAL:
                visit_INT_EQUAL(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_NOTEQUAL:
                visit_INT_NOTEQUAL(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_LESS:
                visit_INT_LESS(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SLESS:
                visit_INT_SLESS(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_LESSEQUAL:
                visit_INT_LESSEQUAL(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SLESSEQUAL:
                visit_INT_SLESSEQUAL(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_ZEXT:
                visit_INT_ZEXT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SEXT:
                visit_INT_SEXT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_ADD:
                visit_INT_ADD(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SUB:
                visit_INT_SUB(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_CARRY:
                visit_INT_CARRY(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SCARRY:
                visit_INT_SCARRY(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SBORROW:
                visit_INT_SBORROW(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_2COMP:
                visit_INT_2COMP(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_NEGATE:
                visit_INT_NEGATE(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_XOR:
                visit_INT_XOR(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_AND:
                visit_INT_AND(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_OR:
                visit_INT_OR(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_LEFT:
                visit_INT_LEFT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_RIGHT:
                visit_INT_RIGHT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SRIGHT:
                visit_INT_SRIGHT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_MULT:
                visit_INT_MULT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_DIV:
                visit_INT_DIV(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_REM:
                visit_INT_REM(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SDIV:
                visit_INT_SDIV(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INT_SREM:
                visit_INT_SREM(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.BOOL_NEGATE:
                visit_BOOL_NEGATE(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.BOOL_XOR:
                visit_BOOL_XOR(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.BOOL_AND:
                visit_BOOL_AND(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.BOOL_OR:
                visit_BOOL_OR(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.PIECE:
                visit_PIECE(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.SUBPIECE:
                visit_SUBPIECE(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.POPCOUNT:
                visit_POPCOUNT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.MULTIEQUAL:
                visit_MULTIEQUAL(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.INDIRECT:
                visit_INDIRECT(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.CAST:
                visit_CAST(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.PTRADD:
                visit_PTRADD(pcodeOpAST, varnodeAST);
                break;
            case PcodeOp.PTRSUB:
                visit_PTRSUB(pcodeOpAST, varnodeAST);
                break;
            default:
                ColoredPrint.info("Skipping unsupported PCode: " + pcodeOpAST, varnodeAST);
        }
    }

}
