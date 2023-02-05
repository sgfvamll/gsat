package com.gsat.sea;

import java.util.Comparator;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public class AddressInterval implements Comparable<AddressInterval> {
    private Address minAddress;
    private long size;

    public static class VarnodeComparator implements Comparator<Varnode> {
        public int compare(Varnode o1, Varnode o2) {
            int val = o1.getAddress().compareTo(o2.getAddress());
            if (val != 0)
                return val;
            return Integer.compare(o1.getSize(), o2.getSize());
        }
    }

    public static AddressInterval fromVarnode(Varnode varnode) {
        return new AddressInterval(varnode.getAddress(), varnode.getSize());
    }

    AddressInterval(Address start, long length) {
        this.minAddress = start;
        this.size = length;
    }

    public Address getMinAddress() {
        return minAddress;
    }

    public long getLength() {
        return size;
    }

    /// Remove (in-place) first n addresses if n < size. 
    public AddressInterval removeFromStart(long n) {
        if (n >= size)
            return null;
        minAddress = minAddress.addWrap(n);
        size -= n;
        return this;
    }

    public AddressInterval[] substract(AddressInterval other) {
        Address oStart = other.getMinAddress();
        if (!minAddress.getAddressSpace().equals(oStart.getAddressSpace())) {
            return new AddressInterval[0];
        }
        long otherStartOffset = other.getMinAddress().subtract(minAddress);
        long otherEndOffset = otherStartOffset + other.getLength();
        int retsize = (otherEndOffset < size ? 1 : 0) + (otherStartOffset > 0 ? 1 : 0);
        AddressInterval[] result = new AddressInterval[retsize];
        int i = 0;
        if (otherStartOffset > 0)
            result[i++] = new AddressInterval(minAddress, otherStartOffset);
        if (otherEndOffset < size)
            result[i++] = new AddressInterval(minAddress.addWrap(otherEndOffset), size - otherEndOffset);
        return result;
    }

    public AddressInterval intersect(AddressInterval other) {
        Address oStart = other.getMinAddress();
        if (!minAddress.getAddressSpace().equals(oStart.getAddressSpace())) {
            return null;
        }
        Address min = minAddress.compareTo(oStart) < 0 ? oStart : minAddress;
        long thisEndOffset = minAddress.getOffset() + size - min.getOffset();
        long oEndOffset = oStart.getOffset() - min.getOffset() + other.getLength();
        long length = thisEndOffset < oEndOffset ? thisEndOffset : oEndOffset;
        return length > 0 ? new AddressInterval(min, length) : null;
    }

    @Override
    public int compareTo(AddressInterval o) {
        int result = minAddress.compareTo(o.getMinAddress());
        if (result == 0) {
            result = Long.compare(size, o.getLength());
        }
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof AddressInterval))
            return false;
        AddressInterval o = (AddressInterval) other;
        return size == o.size && minAddress.equals(o.minAddress);
    }

}
