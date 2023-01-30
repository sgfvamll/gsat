package com.gsat.sea.analysis;

import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.TreeSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

public class LengauerTarjan<T extends DAGNode<T>> {
    List<T> nodes;
    int[] dfnum;
    Map<T, T> parent, semi, ancestor, best;
    List<T> vertex;
    int N = 0;
    static int NOP_DFNUM = Integer.MAX_VALUE;

    private void init(int graphSize) {
        dfnum = new int[graphSize];
        best = new HashMap<>(graphSize);
        parent = new HashMap<>(graphSize);
        semi = new HashMap<>(graphSize);
        ancestor = new HashMap<>(graphSize);
        vertex = new ArrayList<>(graphSize);
        for (int i = 0; i < graphSize; i++)
            vertex.add(null);
        Arrays.fill(dfnum, NOP_DFNUM);
    }

    private void dfs(T p, T node) {
        int n = node.id();
        assert nodes.get(n) == node;
        if (dfnum[n] != NOP_DFNUM)
            return;
        dfnum[n] = N;
        vertex.set(N, node);
        parent.put(node, p);
        N += 1;
        for (var succ : node.getSuccessors())
            dfs(node, succ);
    }

    private T AncestorWithLowestSemi(T v) {
        T a = ancestor.get(v);
        if (ancestor.get(a) != null) {
            T b = AncestorWithLowestSemi(a);
            T aa = ancestor.get(a);
            ancestor.put(v, aa != null ? aa : a);   // Path compression. 
            if (dfnum[semi.get(b).id()] < dfnum[semi.get(best.get(v)).id()])
                best.put(v, b);
        }
        return best.get(v);
        // T u = v;
        // while (ancestor.get(v) != null) {
        //     if (dfnum[semi.get(v).id()] < dfnum[semi.get(u).id()]) 
        //         u = v;
        //     v = ancestor.get(v);
        // }
        // return u;
    }

    private void link(T p, T n) {
        ancestor.put(n, p);
        best.put(n, n);
    }

    public int[] getDominators(List<T> nodes) {
        this.nodes = nodes;
        Integer graphSize = nodes.size();
        int[] idom = new int[graphSize];
        int[] sameDom = new int[graphSize];
        Map<T, Set<T>> bucket = new HashMap<>();
        Arrays.fill(idom, -1);
        init(graphSize);
        dfs(null, nodes.get(0)); // the first element is assumed root. 
        for (int i = N - 1; i >= 1; --i) {
            T n = vertex.get(i);
            T p = parent.get(n), s = p;
            for (var v : n.getPredecessors()) {
                if (dfnum[v.id()] == NOP_DFNUM) 
                    continue;
                T ss = dfnum[v.id()] <= dfnum[n.id()] ? v : semi.get(AncestorWithLowestSemi(v));
                s = dfnum[ss.id()] < dfnum[s.id()] ? ss : s;
            }
            semi.put(n, s);
            if (bucket.get(s) == null)
                bucket.put(s, new HashSet<>());
            bucket.get(s).add(n);
            link(p, n);
            if (bucket.get(p) == null) 
                continue;
            for (var v : bucket.get(p)) {
                T y = AncestorWithLowestSemi(v);
                if (semi.get(y) == semi.get(v))
                    idom[v.id()] = p.id();
                else
                    sameDom[v.id()] = y.id();
            }
            bucket.remove(p);
        }
        for (int i = 0; i < N; ++i) {
            T n = vertex.get(i);
            if (sameDom[n.id()] != 0) {
                idom[n.id()] = idom[sameDom[n.id()]];
            }
        }
        return idom;
    }

}
