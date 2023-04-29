package com.gsat.sea;

import java.util.Collection;
import java.util.ArrayList;

import com.gsat.sea.analysis.DAGGraph;

public class SoNGraph implements DAGGraph<SoNNode> {
    SoNNode end;

    SoNGraph(SoNNode endNode) {
        end = endNode;
    }

    public SoNNode root() {
        return end;
    }

    public Collection<SoNNode> workroots() {
        var r = new ArrayList<SoNNode>();
        r.add(end);
        return r;
    }
    
}
