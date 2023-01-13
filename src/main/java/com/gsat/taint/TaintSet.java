package com.gsat.taint;

/// Extendable BitMap
public class TaintSet {
    int bitSize;
    long[] bitset;
    static int longBitSize = Long.BYTES * 8;

    public TaintSet(int initbitSize) {
        int arraySize = (initbitSize+longBitSize-1) / longBitSize;
        bitset = new long[arraySize];
        for (int i=0;i<arraySize;i++)
        bitset[i] = 0;
        bitSize = initbitSize;
    }

    private void extendBitset(int newBitSize) {
        int newArraySize = (newBitSize+longBitSize-1) / longBitSize;
        if (newArraySize > bitset.length) {
            long[] newBitset = new long[newArraySize];
            for (int i=0;i<bitset.length;i++) {
                newBitset[i] = bitset[i];
            }
            for (int i=bitset.length;i<newBitset.length;i++) {
                newBitset[i] = 0;
            }
            bitset = newBitset;
        }
        bitSize = newBitSize;
    }

    public boolean isEmpty() {
        for (var value: bitset) {
            if (value != 0) return false;
        }
        return true;
    }

    public int getBitSize() {
        return bitSize;
    }

    public void setBit(int idx) {
        if (idx >= bitSize) {
            extendBitset(idx+1);
        }
        bitset[idx / longBitSize] |= 1l << (idx & (longBitSize-1));
    }

    public boolean testBit(int idx) {
        if (idx >= bitSize) return false;
        return ((bitset[idx / longBitSize] >> (idx & (longBitSize-1))) & 1) != 0;
    }

    public boolean doUnion(TaintSet rhs) {
        if (rhs == null) return false;

        boolean modified = false;
        if (rhs.bitSize > this.bitSize) {
            extendBitset(rhs.bitSize);
        }
        for (int i=0;i< Integer.min(bitset.length, rhs.bitset.length);i++) {
            long value = this.bitset[i] | rhs.bitset[i];
            if (value != this.bitset[i]) {
                this.bitset[i] = value;
                modified = true;
            }
        }
        return modified;
    }

    public TaintSet union(TaintSet rhs) {
        int bitSize = Integer.max(this.bitSize, rhs.bitSize);
        TaintSet result = new TaintSet(bitSize);
        int loopMax = Integer.min(this.bitset.length, rhs.bitset.length);
        for (int i=0;i<loopMax;i++) {
            result.bitset[i] = this.bitset[i] | rhs.bitset[i];
        }
        if (this.bitset.length < rhs.bitset.length) {
            for (int i=loopMax;i<rhs.bitset.length;i++) {
                result.bitset[i] = rhs.bitset[i];
            }
        } else if (this.bitset.length > rhs.bitset.length) {
            for (int i=loopMax;i<this.bitset.length;i++) {
                result.bitset[i] = this.bitset[i];
            }
        }
        return result;
    }


}
