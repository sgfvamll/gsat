package com.gsat.taint.sources;

import java.util.LinkedHashSet;
import java.util.Set;

import com.gsat.taint.TaintTrace;
import com.gsat.taint.TaintEngine.TraceMergeOption;
import com.gsat.taint.TaintResult.TraceFilter;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;

public class IntOpSource extends MergedSource {
    protected PcodeOpAST dangeroutIntegerPoint;
    protected boolean likelyFollowedByCheck;

    public IntOpSource(VarnodeAST source, Address address, SourceType type, StorageType storageType, boolean isLikelyFollowedByCheck) {
        super(source, address, type, storageType);
        this.passingDangerousIntPoint = true;
        this.likelyFollowedByCheck = isLikelyFollowedByCheck;
    }

    public Boolean isLikelyFollowedByCheck() {
        return likelyFollowedByCheck;
    }

    public void setDangerousIntPoint(PcodeOpAST pcodeOpAST) {
        this.dangeroutIntegerPoint = pcodeOpAST;
    }

    public PcodeOpAST getDangerousIntPoint() {
        return this.dangeroutIntegerPoint;
    }
    
    // @Override
    // public String reportTraces(TraceFilter filters, long modifyBase) {
    //     if (!setRecursive()) return "";
    //     boolean removed = filters.removeFilter(TraceFilter.filterOutNotPassingDangerousIntOp);
    //     String selfResult = "";
    //     for (var src: sources) {
    //         selfResult = "(" + src.reportTraces(filters, modifyBase) +")" + selfResult;
    //     }
    //     selfResult = String.format("[%s -> {0x%x}  (%s)]", selfResult, address.getOffset()+modifyBase, dangeroutIntegerPoint.toString());
    //     if (removed) filters.addFilter(TraceFilter.filterOutNotPassingDangerousIntOp);
    //     unsetRecursive();
    //     return selfResult;
    // }

    @Override
    public Set<TaintTrace> getTraces(TraceFilter filters, TraceMergeOption traceMergeOption, TaintTrace subTrace) {
        Set<TaintTrace> selfResult = new LinkedHashSet<>();
        if (!setRecursive()) return selfResult;
        boolean removed = filters.removeFilter(TraceFilter.filterOutNotPassingDangerousIntOp);
        TaintTrace thisTrace;
        if (traceMergeOption == TraceMergeOption.LastIntegerOp && !removed)
            thisTrace = subTrace;
        else
            thisTrace = new TaintTrace(this, subTrace); // IntOpSource is of type local, but should be retained. 
        for (var src: sources) {
            if (!filters.test(src)) continue;
            selfResult.addAll(src.getTraces(filters, traceMergeOption, thisTrace));
        }
        if (removed) filters.addFilter(TraceFilter.filterOutNotPassingDangerousIntOp);
        unsetRecursive();
        return selfResult;
    }

}
