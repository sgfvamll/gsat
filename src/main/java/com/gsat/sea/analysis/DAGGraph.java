package com.gsat.sea.analysis;

import java.util.Collection;

public interface DAGGraph<T extends DAGNode<T>> {
    T root();
    Collection<T> workroots();
}
