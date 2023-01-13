package com.gsat.taint.sources;

import java.util.Set;
import java.util.function.Predicate;

import com.gsat.taint.TaintTrace;
import com.gsat.taint.TaintEngine.TraceMergeOption;
import com.gsat.taint.TaintResult.TraceFilter;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.VarnodeAST;

public class MergedSource extends TaintSource {
    protected Set<TaintSource> sources;

    public MergedSource(VarnodeAST source, Address address, SourceType type, StorageType storageType) {
        super(source, address, type, storageType);
        this.sources = new HashSet<>();
    }

    public boolean addSource(TaintSource source) {
        if (!sources.contains(source) && !source.equals(this)) {
            sources.add(source);
            passingDangerousIntPoint |= source.passingDangerousIntPoint;
            if (source.getSourceType() == SourceType.Global) {
                this.type = SourceType.Global;
            }
            return true;
        }
        return false;
    }

    public boolean addSources(Collection<TaintSource> sources) {
        boolean modified = false;
        for (var source: sources) {
            modified |= addSource(source);
        }
        return modified;
    }

    public Set<TaintSource> getSources() {
        return sources;
    }

    public void collectDirectGlobalTaintSourcesOnLocal(List<TaintSource> array, Predicate<TaintSource> filter) {
        assert type == SourceType.Local;
        if (!setRecursive()) return;
        for (var src: sources) {
            if (src.getSourceType() == SourceType.Local) {
                var subLocalSource = (MergedSource) src;
                subLocalSource.collectDirectGlobalTaintSourcesOnLocal(array, filter);
            } else {
                if (!filter.test(src)) continue;
                array.add(src);
            }
        }
        unsetRecursive();
    }

    // @Override
    // public String reportTraces(TraceFilter filters, long modifyBase) {
    //     if (!setRecursive()) return "";
    //     String selfResult = String.format("-> 0x%x ]", address.getOffset() + modifyBase);
    //     for (var src: sources) {
    //         if (!filters.test(src)) continue;
    //         selfResult = "(" + src.reportTraces(filters, modifyBase) +")" + selfResult;
    //     }
    //     selfResult = "[" + selfResult;
    //     unsetRecursive();
    //     return selfResult;
    // }

    public Set<TaintTrace> getTraces(TraceFilter filters, TraceMergeOption traceMergeOption, TaintTrace subTrace) {
        Set<TaintTrace> selfResult = new LinkedHashSet<>();
        if (!setRecursive()) return selfResult;
        /// Skip type-local sources. 
        TaintTrace thisTrace = subTrace;
        if (type != SourceType.Local) {
            thisTrace = new TaintTrace(this, subTrace);
        }
        for (var src: sources) {
            if (!filters.test(src)) continue;
            selfResult.addAll(src.getTraces(filters, traceMergeOption, thisTrace));
        }
        unsetRecursive();
        return selfResult;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof MergedSource)) {
            return false;
        }

        MergedSource rsource = (MergedSource) o;

        return super.equals(rsource); // && originTaintSources.equals(rsource.originTaintSources);
    }

}
