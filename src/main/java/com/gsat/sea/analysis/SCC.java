package com.gsat.sea.analysis;

import java.util.Arrays;
import java.util.List;
import java.util.Stack;

public class SCC<T extends DAGNode<T>> {
    List<T> nodes;
    Stack<T> stack;
    int[] colored;
    int sccCnt = 0;

    public SCC(List<T> nodes) {
        this.nodes = nodes;
        int graphSize = nodes.size();
        stack = new Stack<>();
        colored = new int[graphSize];
        Arrays.fill(colored, 0);
        kosaraju();
    }

    private void dfs1(T node) {
        int n = node.id();
        assert nodes.get(n) == node;
        colored[n] = -1;
        for (var succ : node.getSuccessors())
            if (colored[succ.id()] == 0)
                dfs1(succ);
        stack.push(node);
    }

    private void dfs2(T node) {
        int n = node.id();
        colored[n] = sccCnt;
        for (var pred : node.getPredecessors())
            if (colored[pred.id()] == -1)
                dfs2(pred);
    }

    private void kosaraju() {
        for (int i = 0; i < nodes.size(); i++) {
            if (colored[i] == 0)
                dfs1(nodes.get(i));
        }
        while (!stack.empty()) {
            T node = stack.pop();
            if (colored[node.id()] == -1) {
                dfs2(node);
                sccCnt++;
            }
        }
    }

    public int[] getColor() {
        return colored;
    }

    public int getSccNum() {
        return sccCnt;
    }
}
