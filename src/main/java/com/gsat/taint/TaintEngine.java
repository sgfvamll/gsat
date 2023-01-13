package com.gsat.taint;

import java.util.*;

import com.gsat.helper.DecompHelper;
import com.gsat.taint.TaintJob.Status;
import com.gsat.taint.TaintResult.TraceFilter;
import com.gsat.taint.sources.MergedSource;
import com.gsat.taint.sources.TaintSource;
import com.gsat.taint.sources.TaintSource.SourceType;
import com.gsat.taint.sources.TaintSource.StorageType;
import com.gsat.utils.ColoredPrint;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.VarnodeAST;

// /// Implement the algorithm and perform taint analysis. 
public class TaintEngine {
    public enum Strategy {
        Pessimistic,
        Optimistic,
        Heuristic,
    };

    public enum TraceMergeOption {
        None,
        FirstIntegerOp, 
        LastIntegerOp, 
    };

    FlatProgramAPI flatApi;
    Program program;
    DecompHelper decompHelper;
    private TaintSourceIdentifier sourceIdentifier;
    private TaintSinkIdentifier sinkIdentifier;

    Map<Long, TaintJob> taintJobs;
    private Queue<TaintJob> workList;
    private Map<TaintJob, Set<TaintJob>> dependencyMap;
    private Strategy strategy;
    private TraceMergeOption traceMergeOption;

    public TaintEngine(Program program, FlatProgramAPI flatApi, Strategy strategy, TraceMergeOption traceMergeOption) throws Exception {
        this.program = program;
        this.flatApi = flatApi;
        this.decompHelper = new DecompHelper(flatApi);
        this.sourceIdentifier = new TaintSourceIdentifier(program, decompHelper);
        this.sinkIdentifier = new TaintSinkIdentifier(program, decompHelper);
        this.taintJobs = new HashMap<>();
        this.dependencyMap = new HashMap<>();
        this.workList = new LinkedList<>();
        this.strategy = strategy;
        this.traceMergeOption = traceMergeOption;
    }
    
    public void setTraceMergeOption(TraceMergeOption traceMergeOption) {
        this.traceMergeOption = traceMergeOption; 
    }

    public TraceMergeOption getTraceMergeOption() {
        return this.traceMergeOption;
    }

    public Strategy getStrategy() {
        return strategy;
    }

    private List<TaintSource> getTaintSources() {
        var res = sourceIdentifier.getExportedFunctionParams();
        res.addAll(sourceIdentifier.getCallToSymbols(null));
        return res;
    }

    private List<TaintSink> getTaintSinks() {
        var res = sinkIdentifier.getCallToSymbols(null);
        return res;
    }

    private void buildTaintJobs(List<TaintSource> allTaintSources, List<TaintSink> allTaintSinks) {
        var funcManager = program.getFunctionManager();
        for (var taintSource : allTaintSources) {
            Function sourceFunction = funcManager.getFunctionContaining(taintSource.getAddress());
            Long funcEntry = sourceFunction.getEntryPoint().getOffset();
            TaintJob job = taintJobs.get(funcEntry);
            if (job == null) {
                HighFunction hfunc = decompHelper.decompileFunction(sourceFunction);
                job = new TaintJob(this, hfunc);
                taintJobs.put(funcEntry, job);
                workList.add(job);
            }
            job.addTaintSourceWithGlobalMapping(new MergedSource(taintSource.getVarNodeAST(), taintSource.getAddress(), 
                SourceType.Local, StorageType.PointerOrValue), taintSource);
        }
        for (var taintSink : allTaintSinks) {
            Function sinkFunction = funcManager.getFunctionContaining(taintSink.getAddress());
            Long funcEntry = sinkFunction.getEntryPoint().getOffset();
            TaintJob job = taintJobs.get(funcEntry);
            if (job == null) {
                HighFunction hfunc = decompHelper.decompileFunction(sinkFunction);
                job = new TaintJob(this, hfunc);
                taintJobs.put(funcEntry, job);
                job.setFinished();
            }
            job.addTaintSink(taintSink);
        }
    }

    // public String generateReport(long modifyBase) {
    //     String results = "";
    //     TraceFilter filter = new TraceFilter();
    //     filter.addFilter(TraceFilter.filterOutNotPassingDangerousIntOp);
    //     for (var job : taintJobs.values()) {
    //         for (var taintResult : job.generateTaintResults()) {
    //             results += taintResult.generateReport(filter, modifyBase);
    //         }
    //     }
    //     return results;
    // }

    public Set<TaintTrace> generateTraces() {
        Set<TaintTrace> results = new LinkedHashSet<>();
        TraceFilter filter = new TraceFilter();
        filter.addFilter(TraceFilter.filterOutNotPassingDangerousIntOp);
        for (var job : taintJobs.values()) {
            for (var taintResult : job.generateTaintResults()) {
                results.addAll(taintResult.getTraces(filter, traceMergeOption));
            }
        }
        return results;
    }

    private boolean isWaiting(TaintJob waiter, TaintJob theWaited) {
        var waitinglist = dependencyMap.get(theWaited);
        if (waitinglist == null)
            return false;
        for (var job : waitinglist) {
            if (job.equals(waiter)) {
                return true;
            }
            if (isWaiting(waiter, job)) {
                return true;
            }
        }
        return false;
    }

    public Function getFunctionAt(Address funcEntryAddr) {
        var func = program.getFunctionManager().getFunctionAt(funcEntryAddr);
        if (func == null)
            return null;
        decompHelper.decompileFunction(func);
        return func;
    }

    private Function getThunkedFunction(Address funcEntryAddr) {
        Function func = program.getFunctionManager().getFunctionAt(funcEntryAddr);
        if (func == null)
            return null;
        if (func.isThunk()) {
            func = func.getThunkedFunction(true);
        }
        return func;
    }

    public String getExternalFunctionName(Address funcEntryAddr) {
        Function func = getThunkedFunction(funcEntryAddr);
        return func.isExternal() ? func.getName() : null;
    }

    Map<VarnodeAST, Integer> collectCalleeInOutNodes(Address calleeAddr, int paramCount) {
        Function callee = getThunkedFunction(calleeAddr);
        HighFunction hcallee = decompHelper.decompileFunction(callee);
        if (hcallee == null)
            return null;
        assert callee.getParameterCount() == paramCount;
        Map<VarnodeAST, Integer> results = new HashMap<VarnodeAST, Integer>();
        int idx = 0;
        /// TODO: How to fix function parameters? Try some auto-analysis.
        /// Already try the parameter ID analysis, it works but not perfectly.
        for (var parameter : callee.getParameters()) {
            for (var paramNodeStorage : parameter.getVariableStorage().getVarnodes()) {
                var iter = hcallee.getVarnodes(paramNodeStorage.getAddress());
                while (iter.hasNext()) {
                    VarnodeAST varNodeAST = iter.next();
                    /// Note, undefined varNodeAST with the same address as a parameter is regarded as the parameter node. 
                    /// Is this completely correct?
                    if (varNodeAST.getDef() == null) {
                        results.put(varNodeAST, idx);
                    }
                }
            }
            idx += 1;
        }
        /// Collect return value nodes
        for (var retNodeStorage : callee.getReturn().getVariableStorage().getVarnodes()) {
            var iter = hcallee.getVarnodes(retNodeStorage.getAddress());
            while (iter.hasNext()) {
                VarnodeAST varNodeAST = iter.next();
                var pcodeOpASTIter = varNodeAST.getDescendants();
                while (pcodeOpASTIter.hasNext()) {
                    var pcodeOpAST = pcodeOpASTIter.next();
                    if (pcodeOpAST.getOpcode() == PcodeOp.RETURN) {
                        results.put(varNodeAST, -1);
                    }
                }
            }
        }
        return results;
    }

    /// Return value:
    ///     NULL: indicates that the requester should stop and wait for the target to finish first. 
    ///     Empty ArrayList: indicates that the target job is also waiting for the requester. 
    ///                      So this action will never succeed. 
    ///     List<TaintSet> with the size the same as `sinks`. 
    public List<TaintSet> requestSignatureState(TaintJob requester, Address funcEntryAddr, HashMap<VarnodeAST, List<TaintSource>> sources, List<VarnodeAST> sinks) {
        Function func = getThunkedFunction(funcEntryAddr);
        funcEntryAddr = func.getEntryPoint();
        var job = taintJobs.get(funcEntryAddr.getOffset());
        if (job == null) {
            HighFunction hfunc = decompHelper.decompileFunction(func);
            if (hfunc == null)
                return null;
            job = new TaintJob(this, hfunc);
            taintJobs.put(funcEntryAddr.getOffset(), job);
            workList.add(job);
        } else
        /// Resolve cycle.
        if (job.equals(requester) || isWaiting(job, requester)) {
            /// return a empty list to indicate circular waiting.
            /// TODO(SGFvamll): return current state instead.
            return new ArrayList<TaintSet>();
        }
        var outStates = job.requestSignatureState(sources, sinks);
        if (outStates == null) {
            var waitingList = dependencyMap.get(job);
            if (waitingList == null) {
                waitingList = new HashSet<>();
                dependencyMap.put(job, waitingList);
            }
            waitingList.add(requester);
            if (job.isFinished()) {
                assert !workList.contains(job);
                job.setUnFinished();
                workList.add(job);
            }
        }
        /// Debug
        for (var ajob : taintJobs.values()) {
            if ((ajob.isRunning() || ajob.isNotInited()) && !(workList.contains(ajob) || ajob.equals(requester))) {
                ColoredPrint.error("%s", ajob.getFuctionName());
            }
        }
        return outStates;
    }

    public void propagateBackOnCallGraph(Function callee, Map<Integer, TaintSource> outSources) {

        for (var ref : program.getReferenceManager().getReferencesTo(callee.getEntryPoint())) {
            if (!ref.getReferenceType().isCall())
                continue;
            var caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller == null || caller == callee)
                continue;
            var callerjob = taintJobs.get(caller.getEntryPoint().getOffset());
            HighFunction hcaller = decompHelper.decompileFunction(caller);
            if (hcaller == null)
                continue;
            if (callerjob == null) {
                callerjob = new TaintJob(this, hcaller);
                taintJobs.put(caller.getEntryPoint().getOffset(), callerjob);
                workList.add(callerjob);
            }
            boolean intriduced = callerjob.introduceGlobalTaintsAtCallSite(ref, outSources);
            if (intriduced && callerjob.isFinished()) {
                assert !workList.contains(callerjob);
                callerjob.setUnFinished();
                workList.add(callerjob);
            }
        }
    }

    public boolean analyze() {
        var allTaintSources = this.getTaintSources();
        var allTaintSinks = this.getTaintSinks();
        ColoredPrint.info("Finishing identifying sources and sinks. Totally %s sources and %d sinks. ",
                allTaintSources.size(), allTaintSinks.size());
        buildTaintJobs(allTaintSources, allTaintSinks);
        while (!workList.isEmpty()) {
            TaintJob job = workList.poll();
            // if (job.getFuctionName().equals("FUN_00016264")) {
            //     ColoredPrint.info("log");
            // }
            if (job.run() == Status.Finished) {
                /// Once a job is finished, all jobs depends on it can continue.
                var dependenciesOnThisJob = dependencyMap.get(job);
                if (dependenciesOnThisJob != null) {
                    for (var suspendedJob : dependenciesOnThisJob) {
                        suspendedJob.setUnSuspended();
                        workList.add(suspendedJob);
                    }
                    dependencyMap.remove(job);
                }
            }
        }
        return true;
    }

//     private ArrayList<VarnodeAST> identityTaintSource(HighFunction hfunc) {
//         Iterator<PcodeOpAST> ops = hfunc.getPcodeOps();
//         ArrayList<VarnodeAST> results = new ArrayList<VarnodeAST>();
//         while (ops.hasNext() && !this.flatApi.getMonitor().isCancelled()) {
//             PcodeOpAST pcodeOpAST = ops.next();
//             if (pcodeOpAST.getOpcode() == PcodeOp.INT_ADD) {
//                 results.add((VarnodeAST)pcodeOpAST.getOutput());
//             }
//         }
//         return results;
//     }

//     private void initStates(ArrayList<VarnodeAST> sources) {
//         int numSources = sources.size();
//         int id = 0;
//         for (var srcNode: sources) {
//             if (numSources > 64) {

//             } else {
//                 state.put(srcNode, new Bitmap(1l << id));
//             }
//             id += 1;
//         }
        
//     }

}
