package com.gsat.sea.analysis;

import java.util.List;

public interface DAGNode<T extends DAGNode<T>> {
    
    int id();
    int hashCode();
    List<T> getPredecessors();
    List<T> getSuccessors();
    String[] getFeatureStrs();
}
