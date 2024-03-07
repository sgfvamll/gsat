package com.gsat.sea;

import java.util.Collection;
import java.util.ArrayList;

import com.gsat.sea.analysis.DAGGraph;

public class SOG implements DAGGraph<SOGNode> {
    SOGNode end;

    SOG(SOGNode endNode) {
        end = endNode;
    }

    public SOGNode root() {
        return end;
    }

    public Collection<SOGNode> workroots() {
        var r = new ArrayList<SOGNode>();
        r.add(end);
        return r;
    }
    
}
