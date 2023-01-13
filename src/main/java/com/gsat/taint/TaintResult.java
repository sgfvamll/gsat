package com.gsat.taint;

import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import com.gsat.taint.TaintEngine.TraceMergeOption;
import com.gsat.taint.sources.TaintSource;

import java.util.ArrayList;
import java.util.LinkedHashSet;

public class TaintResult {
    public enum Type {
        ALL, 
        IntOpBug, 
    };

    List<TaintSource> sources;
    TaintSink sink;

    static public class TraceFilter {
        List<Predicate<TaintSource>> filters;
        public static Predicate<TaintSource> filterOutNotPassingDangerousIntOp = source -> source.isPassingDangerousIntPoint();
        public static Predicate<TaintSource> filterOutPassingDangerousIntOp = source -> !source.isPassingDangerousIntPoint();

        TraceFilter() {
            filters = new ArrayList<>();
        }
        public void addFilter(Predicate<TaintSource> filter) {
            filters.add(filter);
        }
        public boolean removeFilter(Predicate<TaintSource> filter) {
            return filters.remove(filter);
        }
        public boolean test(TaintSource source) {
            boolean result = true;
            for (var filter: filters) {
                result &= filter.test(source);
                if (!result) break;
            }
            return result;
        }
    }

    TaintResult(TaintSink sink) {
        this.sink = sink;
        this.sources = new ArrayList<>();
    }
    
    void addSource(TaintSource sources) {
        this.sources.add(sources);
    }

    void addSources(Set<TaintSource> sources) {
        this.sources.addAll(sources);
    }

    // public String generateReport(TraceFilter filters, long modifyBase) {
    //     String result = "";
    //     for (var source: sources) {
    //         if (!filters.test(source)) continue;
    //         result += String.format("%s -> 0x%x\n", source.reportTraces(filters, modifyBase), sink.getAddress().getOffset()+modifyBase);
    //     }
    //     return result;
    // }

    public Set<TaintTrace> getTraces(TraceFilter filters, TraceMergeOption traceMergeOption) {
        Set<TaintTrace> result = new LinkedHashSet<>();
        for (var source: sources) {
            TaintTrace thisTrace = new TaintTrace(new TaintSource(sink.getVarNodeAST(), sink.getAddress(), null, null), null);
            if (!filters.test(source)) continue;
            result.addAll(source.getTraces(filters, traceMergeOption, thisTrace));
        }
        return result;
    }

}

