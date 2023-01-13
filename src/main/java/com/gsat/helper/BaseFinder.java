package com.gsat.helper;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import me.tongfei.progressbar.ProgressBar;

import java.util.*;

import com.gsat.utils.ColoredPrint;

public class BaseFinder {

    private Program program;
    private FlatProgramAPI flatApi;
    private Set<Long> loadTargets;
    private Set<Long> strAddrs;
    private Listing listing;
    private int pointerSize;
    private boolean accurateMode;
    private boolean highConfidence;
    private int resultMatched;

    public BaseFinder(Program program,Boolean accurateMode) {
        this.program = program;
        this.accurateMode = accurateMode;
        this.flatApi = new FlatProgramAPI(program);
        this.listing = program.getListing();
        this.pointerSize = this.program.getDefaultPointerSize();
        this.loadTargets = new HashSet<>();
        this.strAddrs = new HashSet<>();
        this.highConfidence = false;
        this.resultMatched = -1;
    }

    public boolean isHighConfidence() {
        return highConfidence;
    }

    public int getResultMatched() {
        return resultMatched;
    }

    private Long loadPointer(long loadOffset) {
        if (loadOffset < program.getMinAddress().getOffset() || loadOffset > program.getMaxAddress().getOffset()) 
            return null;
        try {
            Long absAddr = null;
            absAddr = program.getMemory().getLong(flatApi.toAddr(loadOffset));
            //32bit
            if (this.pointerSize == 4) {
                absAddr = absAddr & 0x00000000ffffffffL;
            } else if (this.pointerSize == 8) {
                //64bit
                //to nothing
            } else if (this.pointerSize == 2) {
                absAddr = absAddr & 0x000000000000ffffL;
            } else {
                System.out.println("No support for other pointerSize");
                System.exit(1);
            }
            return absAddr;
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    private void findLoadInArm() {
        InstructionIterator insIter = listing.getInstructions(true);
        while(insIter.hasNext()) {
            Instruction ins = insIter.next();
             if (!ins.getMnemonicString().equals("ldr")) {
                continue;
            }
            byte[] insBytes;
            try {
                insBytes = ins.getBytes();
            } catch (Exception e) {
                continue;
            }
            PcodeOp opldr = null;
            Varnode loadAddr = null;
            if (insBytes.length == 2) {
                /// Thumb Mode
                int immIdx = program.getMemory().isBigEndian() ? 0 : 1;
                if ((insBytes[immIdx]>>3)!=0x09) {
                    continue;
                }
                opldr = ins.getPcode()[0];
                loadAddr = opldr.getInput(0);
            } else if (insBytes.length == 4) {
                int op1Idx = program.getMemory().isBigEndian() ? 0 : 3;
                int op2Idx = program.getMemory().isBigEndian() ? 1 : 2;
                if (insBytes[op2Idx] != (byte)0x9f || insBytes[op1Idx] != (byte)0xe5) {
                    continue;
                }
                PcodeOp[] ops = ins.getPcode();
                for(PcodeOp opItem:ops) {
                    if (opItem.getOpcode() != PcodeOp.LOAD) {
                        continue;
                    }
                    opldr = opItem;
                    loadAddr = opldr.getInput(1);
                    break;
                }
            } else {
                /// No absolute addr can be found from 64-bit ldr. 
                continue;
            }
            long loadOffset = loadAddr.getOffset();
            Long absAddr = loadPointer(loadOffset);
            if (absAddr != null) 
                loadTargets.add(absAddr);
        }
    }

    private void findLoadInMIPS() {
        InstructionIterator insIter = listing.getInstructions(true);
        Instruction lastIns = null;
        while(insIter.hasNext()) {
            Instruction ins = insIter.next();
            boolean isStackOperation = false;
            for (var inp: ins.getInputObjects()) {
                if (!(inp instanceof ghidra.program.model.lang.Register)) {
                    continue;
                }
                if (inp.toString().contains("sp") || inp.toString().contains("bp")) {
                    isStackOperation = true;
                    break;
                }
            }
            byte[] insBytes;
            try {
                insBytes = ins.getBytes();
            } catch (Exception e) {
                continue;
            }
            int endian = program.getMemory().isBigEndian() ? 0 : 1;
            if (insBytes.length == 2 && ((insBytes[endian] & 0xff) >>> 3) == 0x16) {
                long offset = (((long)insBytes[1-endian]) & 0xff) << 2;
                long pc = ins.getAddress().getOffset();
                if (lastIns.getDelaySlotDepth() != 0) {
                    pc = lastIns.getAddress().getOffset();
                }
                long loadOffset = offset + (pc & (~3l));
                Long absAddr = loadPointer(loadOffset);
                if (absAddr != null) 
                    loadTargets.add(absAddr);
            } else if (!isStackOperation && lastIns != null) {
                PcodeOp[] ops = ins.getPcode();
                PcodeOp[] lastOps = lastIns.getPcode();
                if (ops.length == 1 && lastOps.length == 1) {
                    PcodeOp thisOp = ops[0];
                    PcodeOp lastOp = lastOps[0];
                    if (thisOp.getOpcode() == PcodeOp.INT_ADD && lastOp.getOpcode() == PcodeOp.INT_LEFT
                    && thisOp.getOutput().toString().equals(lastOp.getOutput().toString())) {
                        
                        long first = lastOp.getInput(0).getOffset();
                        long second = lastOp.getInput(1).getOffset();
                        long initVal = first << second;
                        int toAddVal = (int) thisOp.getInput(1).getOffset();
                        loadTargets.add(initVal + toAddVal);
                    }
                }
            }
            lastIns = ins;
        }
    }

    private void findLoadInPowerPC() {
        InstructionIterator insIter = listing.getInstructions(true);
        Instruction lastIns = null;
        while(insIter.hasNext()) {
            Instruction ins = insIter.next();
            boolean isStackOperation = false;
            if (!isStackOperation && lastIns != null) {
                PcodeOp[] ops = ins.getPcode();
                PcodeOp[] lastOps = lastIns.getPcode();
                if (ops.length == 1 && lastOps.length == 1) {
                    PcodeOp thisOp = ops[0];
                    PcodeOp lastOp = lastOps[0];
                    if (thisOp.getOpcode() == PcodeOp.INT_ADD && lastOp.getOpcode() == PcodeOp.INT_LEFT
                    && thisOp.getOutput().toString().equals(lastOp.getOutput().toString())) {
                        
                        long first = lastOp.getInput(0).getOffset();
                        long second = lastOp.getInput(1).getOffset();
                        long initVal = first << second;
                        int toAddVal = (int) thisOp.getInput(1).getOffset();
                        loadTargets.add(initVal + toAddVal);
                    }
                }
            }
            lastIns = ins;
        }
    }

    private void findAllLoadTarget() {
        String processor = program.getMetadata().get("Processor").toLowerCase();
        if (processor.equals("powerpc")) {
            findLoadInPowerPC();
        } else if (processor.equals("mips")) {
            findLoadInMIPS();
        } else if (processor.equals("arm")) {
            findLoadInArm();
        } else {
            ColoredPrint.error("Unsupported processor: %s", processor);
        }
    }

    private void findAllStrAddrs() {
        DataIterator dataIter = listing.getData(true);
        while(dataIter.hasNext()) {
            Data dataItem = dataIter.next();
            if(dataItem.getDataType().getName().toLowerCase().equals("string")) {
                this.strAddrs.add(dataItem.getAddress().getOffset());
            }
        }
    }

    private Long findBestBase() {
        int MAX_LOAD_TARGETS_SIZE = 10000;
        int MAX_STRINGS_SIZE = 10000;
        Long baseOffset = null;
        if (loadTargets.size() == 0) {
            return baseOffset;
        }
        Map<Long,Integer> records = new HashMap<>();
        int countLoad = 0, countStr = 0;
        long pbMax = Long.max((long)loadTargets.size(), MAX_LOAD_TARGETS_SIZE)  * Long.max((long)strAddrs.size(), MAX_STRINGS_SIZE);
        try (ProgressBar pb = new ProgressBar("Finding", pbMax)) {
            for (long target:loadTargets) {
                countLoad += 1;
                countStr = 0;
                if (countLoad > MAX_LOAD_TARGETS_SIZE) {
                    break;
                }
                for(long relativeOffset:strAddrs) {
                    if (target < relativeOffset) {
                        continue;
                    }
                    countStr += 1;
                    if (countStr > MAX_STRINGS_SIZE) {
                        break;
                    }
                    long val = target - relativeOffset;
                    pb.step();
                    if (records.containsKey(val)) {
                        records.put(val, records.get(val) + 1);
                    } else {
                        records.put(val,1);
                    }
                }
            }
        } 
        List<Map.Entry<Long, Integer>> recordsList = new ArrayList<>(records.entrySet());

        Collections.sort(recordsList, new Comparator<>() {
            @Override
            public int compare(Map.Entry<Long, Integer> o1, Map.Entry<Long, Integer> o2) {
                return o2.getValue() - o1.getValue();
            }
        });
        int recordListSize = recordsList.size();
        int count = 0;
        for(int i=0; i< recordListSize;i++) {
            long thisBase = recordsList.get(i).getKey();
            if (!(thisBase % 0x400 == 0)) {
                continue;
            }
            count += 1;
            int thisVal = recordsList.get(i).getValue();
            ColoredPrint.info("%x: %x", thisBase, thisVal);
            if (count > 15) break;
        }
        long binarySize = program.getMaxAddress().getOffset() - program.getMinAddress().getOffset();
        long maxBase = (1l << 32) - binarySize;
        if (pointerSize == 64) {
            maxBase = Long.MAX_VALUE - binarySize;
        }
        for(int i=0; i< recordListSize;i++) {
            long thisBase = recordsList.get(i).getKey();
            if (thisBase < maxBase) {
                int thisVal = recordsList.get(i).getValue();
                if (i + 1 < recordListSize) {
                    int lastVal = recordsList.get(i+1).getValue();
                    if (thisVal > 3 * lastVal) {
                        this.highConfidence =true;
                    }
                }
                if (this.highConfidence || (thisBase % 0x400 == 0)) {
                    this.resultMatched = thisVal;
                    return thisBase;
                }
            }
        }
        return baseOffset;
    }

    private Long rawFindBestBase() {
        Long baseOffset = null;
        if (loadTargets.size() == 0) {
            return baseOffset;
        }
        Set<Long> targetsSet = new HashSet<>(loadTargets);
        long middle = findMiddle();
        long binarySize = program.getMaxAddress().getOffset() - program.getMinAddress().getOffset();
        long minBase = middle - binarySize;
        if (middle > 0 && minBase < 0) {
            minBase = 0;
        }
        int stepSize = 1;
        if (accurateMode) {
            minBase = minBase & 0xfffffffffffffff0L;
            stepSize = this.pointerSize;
        } else {
            minBase = minBase & 0xfffffffffffff000L;
            stepSize = 0x1000;
        }
        int maxMatch = 0;
        int pbMax = (int) ((binarySize-1)/stepSize) + 1;
        try (ProgressBar pb = new ProgressBar("Finding", pbMax)) {
            for (long i=0; i<binarySize; i += stepSize) {
                pb.step();
                int mactchCount = 0;
                long currentBase = minBase + i;
                var iter = strAddrs.iterator();
                while (iter.hasNext()) {
                    if (targetsSet.contains(iter.next() + currentBase)) {
                        mactchCount += 1;
                    }
                }
                if (mactchCount > maxMatch) {
                    if (maxMatch !=0 && mactchCount > maxMatch * 3) {
                        this.highConfidence = true;
                    } else {
                        this.highConfidence = false;
                    }
                    maxMatch = mactchCount;
                    baseOffset = currentBase;
                    this.resultMatched = mactchCount;
//                    System.out.printf("%d @0x%x\n",maxMatch,baseOffset);
                    pb.setExtraMessage(String.format("Current res...:0x%x with %d matches",baseOffset,maxMatch));
                }
            }
        }
        return baseOffset;
    }


    private Long findMiddle() {
        ArrayList<Long> loadTargetsList = new ArrayList<>(loadTargets);
        Collections.sort(loadTargetsList);
        int targetSize = loadTargetsList.size();
        if (targetSize % 2 == 0) {
            int halfPos = targetSize/2;
            return (loadTargetsList.get(halfPos) + loadTargetsList.get(halfPos + 1)) / 2;
        } else {

            return loadTargetsList.get(targetSize/2 + 1);
        }
    }
    public Long  findBase() {
        Long baseOffset = null;

        findAllLoadTarget();
        findAllStrAddrs();
        System.out.printf("find %d load target.\n",this.loadTargets.size());
        System.out.printf("find %d str addr.\n",this.strAddrs.size());
        if (!accurateMode) {
            baseOffset = rawFindBestBase();
        }
        if (accurateMode || !this.highConfidence) {
            System.out.println("Not found in fast mode. Switch to accurate mode.");
            baseOffset = findBestBase();
        }
        return baseOffset;
    }
}

