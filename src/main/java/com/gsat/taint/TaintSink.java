package com.gsat.taint;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.VarnodeAST;

public class TaintSink {
    public enum TaintSinkType {
        Local, 
        Default, 
    };

    private VarnodeAST sink;
    private Address address;
    private TaintSinkType type;

    public TaintSink(VarnodeAST sink, Address address, TaintSinkType type) {
        this.sink = sink; 
        this.type = type;
        this.address = address;
    }

    public VarnodeAST getVarNodeAST() {
        return this.sink;
    }

    public Address getAddress() {
        return this.address;
    }

    public boolean equals(Object o) {
		if (o == this) {
			return true;
		}
		if (!(o instanceof TaintSink)) {
			return false;
		}

		TaintSink rsink = (TaintSink) o;
        return this.sink == rsink.sink && this.type == rsink.type;
    }
}
