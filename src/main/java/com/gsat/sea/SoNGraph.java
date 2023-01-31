package com.gsat.sea;

import com.gsat.sea.analysis.DAGGraph;

public class SoNGraph implements DAGGraph<SoNNode> {
    SoNNode end;

    SoNGraph(SoNNode endNode) {
        end = endNode;
    }

    public SoNNode root() {
        return end;
    }
}
