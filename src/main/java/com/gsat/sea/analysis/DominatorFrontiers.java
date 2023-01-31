package com.gsat.sea.analysis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DominatorFrontiers<T extends DAGNode<T>> {
    List<Set<Integer>> results;
    List<List<Integer>> dchildren; // children of i in the dominator tree
    List<T> nodes;
    int[] idom;
    int graphSize;

    public DominatorFrontiers(List<T> nodes, int[] idom) {
        int graphSize = nodes.size();
        assert graphSize == idom.length;
        results = new ArrayList<Set<Integer>>(graphSize);
        dchildren = new ArrayList<>(graphSize);
        for (int i = 0; i < graphSize; i++) {
            dchildren.add(new ArrayList<>());
            results.add(new HashSet<>());
        }
        for (int i = 0; i < graphSize; i++) {
            int p = idom[i];
            if (p < 0)
                continue;
            dchildren.get(p).add(i);
        }
        this.nodes = nodes;
        this.idom = idom;
        this.graphSize = graphSize;
        compute(0);
    }

    public void compute(int i) {
        Set<Integer> df = results.get(i);
        T n = nodes.get(i);
        for (var y : n.getSuccessors()) {
            if (idom[y.id()] != i)
                df.add(y.id());
        }
        for (var cId : dchildren.get(i)) {
            compute(cId);
            for (var w : results.get(cId)) {
                int tid = w;
                // Check if i dominates w. May need opting
                while (tid > 0 && tid != i) 
                    tid = idom[tid]; 
                if (tid != i)
                    df.add(w);
            }
        }
    }

    public List<Set<Integer>> get() {
        return results;
    }

    public List<List<Integer>> getChildrenListInDT() {
        return dchildren;
    }
}
