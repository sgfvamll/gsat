package com.gsat.taint;

import com.gsat.taint.sources.IntOpSource;
import com.gsat.taint.sources.TaintSource;

public class TaintTrace {
    TaintTrace subTrace;
    TaintSource source;

    public TaintTrace(TaintSource source, TaintTrace subTrace) {
        this.source = source;
        this.subTrace = subTrace;
    }

    public void setSubTrace(TaintTrace subTrace) {
        this.subTrace = subTrace;
    }

    public String reportTrace(long baseOffset, boolean verbose) {
        String result = (subTrace != null) ? subTrace.reportTrace(baseOffset, verbose) : "";
        if (source instanceof IntOpSource) {
            var intSource = (IntOpSource) source;
            if (verbose)
                result = String.format("-> {0x%x}[%s][%s] ", source.getAddress().getOffset()+baseOffset, intSource.isLikelyFollowedByCheck(), intSource.getDangerousIntPoint()) + result;
            else 
                result = String.format("-> {0x%x}[%s] ", source.getAddress().getOffset()+baseOffset, intSource.isLikelyFollowedByCheck()) + result;
        } else {
            if (verbose)
                result = String.format("-> 0x%x [%s]", source.getAddress().getOffset()+baseOffset, source.getVarNodeAST()) + result;
            else 
                result = String.format("-> 0x%x ", source.getAddress().getOffset()+baseOffset) + result;
        }
        return result;
    }

    @Override
    public boolean equals(Object rhs) {
        if (! (rhs instanceof TaintTrace)) {
            return false;
        }
        var rtrace = (TaintTrace) rhs;
        var subeq = this.subTrace == null ? (rtrace.subTrace == null) : (this.subTrace.equals(rtrace.subTrace));
        return this.source.equals(rtrace.source) && subeq;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = source.hashCode();
        result *= prime;
        if (subTrace != null)
            result += subTrace.hashCode();
        return result;
    }

}
