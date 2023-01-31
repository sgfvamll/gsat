package com.gsat.sea.analysis;

public interface DAGGraph<T extends DAGNode<T>> {
    T root();
}
