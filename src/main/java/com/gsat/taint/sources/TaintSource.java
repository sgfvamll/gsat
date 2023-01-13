package com.gsat.taint.sources;

import java.util.LinkedHashSet;
import java.util.Set;

import com.gsat.taint.TaintTrace;
import com.gsat.taint.TaintEngine.TraceMergeOption;
import com.gsat.taint.TaintResult.TraceFilter;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.VarnodeAST;

public class TaintSource {
    public enum SourceType {
        Local,      // Only propagated in a function. 
        Default,    // Will not propagate on Return. 
        Global, 
    };

    public enum StorageType {
        Value,
        Pointer,
        PointerOrValue,
    };

    protected int id = -1;
    protected Address address;
    protected VarnodeAST source;
    protected SourceType type;
    protected StorageType storageType;
    protected boolean passingDangerousIntPoint = false;
    protected boolean isRecursive = false;

    public TaintSource(VarnodeAST source, Address address, SourceType type, StorageType storageType) {
        this.source = source;
        this.type = type;
        this.address = address;
        this.storageType = storageType;
    }

    public boolean isPassingDangerousIntPoint() {
        return passingDangerousIntPoint;
    }

    public SourceType getSourceType() {
        return type;
    }

    protected boolean setRecursive() {
        if (isRecursive) return false;
        return isRecursive = true;
    }

    protected void unsetRecursive() {
        isRecursive = false;
    }

    // public String reportTraces(TraceFilter filters, long modifyBase) {
    //     String selfResult = String.format("-> 0x%x ", address.getOffset() + modifyBase);
    //     selfResult = selfResult + "[[" + this.source.toString() + "]]";
    //     return selfResult;
    // }

    public Set<TaintTrace> getTraces(TraceFilter filters, TraceMergeOption traceMergeOption, TaintTrace subTrace) {
        assert this.type != SourceType.Local;
        var result = new LinkedHashSet<TaintTrace>();
        result.add(new TaintTrace(this, subTrace));
        return result;
    }

    public void setid(int id) {
        this.id = id;
    }

    public int getid() {
        return id;
    }

    public Address getAddress() {
        return address;
    }

    public VarnodeAST getVarNodeAST() {
        return this.source;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof TaintSource)) {
            return false;
        }

        TaintSource rsource = (TaintSource) o;
        return this.source == rsource.source && this.type == rsource.type && this.storageType == rsource.storageType;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = source.hashCode()*prime+address.hashCode();
        return result;
    }

}
