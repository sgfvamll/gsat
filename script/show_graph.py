#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# A script to visualize SOG. 

import sys
import json
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random


# =================================================================================
# Following three functions are copied from networkx 
#       with a few customized modifications made.
# ---------------------------------------------------------------------------------
def kamada_kawai_layout(
    G, dist=None, pos=None, weight="weight", scale=1, center=None, dim=2
):
    center = np.zeros(dim)
    nNodes = len(G)
    if nNodes == 0:
        return {}

    if dist is None:
        dist = dict(nx.shortest_path_length(G, weight=weight))
    # mask for unconnected nodes
    mask_mtx = np.zeros((nNodes, nNodes), dtype=np.bool_)
    # default min distance for unconnected nodes
    dist_mtx = np.ones((nNodes, nNodes))
    for row, nr in enumerate(G):
        if nr not in dist:
            for col, _ in enumerate(G):
                mask_mtx[row][col] = True
            continue
        rdist = dist[nr]
        for col, nc in enumerate(G):
            if nc not in rdist:
                mask_mtx[row][col] = True
                continue
            dist_mtx[row][col] = rdist[nc]

    if pos is None:
        pos = {n: pt for n, pt in zip(G, np.linspace(0, 1, len(G)))}
    pos_arr = np.array([pos[n] for n in G])

    pos = _kamada_kawai_solve(dist_mtx, pos_arr, dim, mask_mtx)

    pos = nx.rescale_layout(pos, scale=scale) + center
    return dict(zip(G, pos))


def _kamada_kawai_solve(dist_mtx, pos_arr, dim, mask):
    # Anneal node locations based on the Kamada-Kawai cost-function,
    # using the supplied matrix of preferred inter-node distances,
    # and starting locations.

    import numpy as np
    import scipy as sp
    import scipy.optimize  # call as sp.optimize

    meanwt = 1e-3
    costargs = (np, 1 / (dist_mtx +
                np.eye(dist_mtx.shape[0]) * 1e-3), meanwt, dim, mask)

    optresult = sp.optimize.minimize(
        _kamada_kawai_costfn,
        pos_arr.ravel(),
        method="L-BFGS-B",
        args=costargs,
        jac=True,
    )

    return optresult.x.reshape((-1, dim))


def _kamada_kawai_costfn(pos_vec, np, invdist, meanweight, dim, mask):
    # Cost-function and gradient for Kamada-Kawai layout algorithm
    nNodes = invdist.shape[0]
    pos_arr = pos_vec.reshape((nNodes, dim))

    delta = pos_arr[:, np.newaxis, :] - pos_arr[np.newaxis, :, :]
    nodesep = np.linalg.norm(delta, axis=-1)
    direction = np.einsum("ijk,ij->ijk", delta, 1 /
                          (nodesep + np.eye(nNodes) * 1e-3))

    offset = nodesep * invdist - 1.0
    offset[np.diag_indices(nNodes)] = 0
    # (Jay) min distances (rather than opt distances) between masked pairs are ensured.
    offset[mask & (offset > 0)] = 0

    cost = 0.5 * np.sum(offset**2)
    grad = np.einsum("ij,ij,ijk->ik", invdist, offset, direction) - np.einsum(
        "ij,ij,ijk->jk", invdist, offset, direction
    )

    # Additional parabolic term to encourage mean position to be near origin:
    sumpos = np.sum(pos_arr, axis=0)
    cost += 0.5 * meanweight * np.sum(sumpos**2)
    grad += meanweight * sumpos

    return (cost, grad.ravel())
# ---------------------------------------------------------------------------------
# =================================================================================


def create_graph(nodes, edges):
    """
    Create a NetworkX direct graph from the list of nodes and edges.
    """
    G = nx.MultiDiGraph()
    for node in nodes:
        G.add_node(node)
    for edge in edges:
        if len(edge) > 2:
            G.add_edge(edge[0], edge[1], type=edge[2])
        else:
            G.add_edge(edge[0], edge[1])

    return G


# '-', '--', '-.', ':'
EDGE_STYLE_MAP = {
    1: "-",
    2: "--",
    3: ":",
    4: "-.", 
}

CONTROL_NODES = [
    "BR", "CBR", "BRIND", "RET",
    "BRANCH", "CBRANCH", "BRANCHIND", "RETURN", 
]

EFFECT_NODES = [
    "CALL", "CALLIND", "CALLOTHER", "SD", "SPACE(4f)", 
    "STORE", "LOAD", 
]

SPECIAL_NODES = [
    "END",
]


def node_color(mnem):
    # color_palette = ['#30A9DE', '#EFDC05', '#E53A40', '#090707']
    color_palette = ['#ff7473', '#ffc952', '#47b8e0', '#1f78b4']
    result = 0
    if mnem in CONTROL_NODES:
        result = 1
    elif mnem in EFFECT_NODES:
        result = 2
    elif mnem in SPECIAL_NODES:
        result = 3
    return color_palette[result]


def randAbs(low, high):
    x = random.random() * (high-low) + low
    return x if random.random() < 0.5 else -x

if __name__ == "__main__":
    graph_fp = sys.argv[1]
    filter_rule = sys.argv[2]
    specified_func = size_limit = None
    if filter_rule.startswith("0x"):
        specified_func = sys.argv[2]
    else:
        size_limit = int(sys.argv[2])
    with open(graph_fp, "r") as f:
        graph_data = json.load(f)
    graph_data = graph_data[list(graph_data.keys())[0]]
    min_nodes = 100000
    for fva, func_data in graph_data.items():
        func_data = func_data['SOG']
        nodes = func_data['nodes']
        edges = func_data['edges']
        if len(nodes) < min_nodes:
            min_nodes = len(nodes)
        if size_limit is not None and len(nodes) > size_limit:
            continue
        if specified_func is not None and specified_func!=fva:
            continue

        graph = create_graph(nodes, edges)
        print(fva, graph)
        nodes_verbs = [
            (int(nid), mnem_data[0])
            for nid, mnem_data in func_data['nverbs'].items()
        ]
        labels = dict([
            (nid, str(nid) + ' ' + mnem) for nid, mnem in nodes_verbs
        ])
        node_colors = dict([
            (nid, node_color(mnem)) for nid, mnem in nodes_verbs
        ])
        end_node = [nid for nid, mnem in nodes_verbs if mnem == "END"][0]
        shortest_paths_dict = dict(nx.shortest_path_length(graph, weight=None))
        subsetkeys_dict = shortest_paths_dict[end_node]
        for node in graph:
            graph.add_node(node, subset=subsetkeys_dict[node])
        pos = nx.multipartite_layout(graph)
        for nid, npos in pos.items():
            npos[0] *= -1
            npos += np.array([randAbs(0.02, 0.07), randAbs(0.02, 0.07)])
        # pos = nx.spring_layout(graph, k=10, pos = pos, seed=42, iterations=10)
        pos = kamada_kawai_layout(
            graph, pos=pos, dist=shortest_paths_dict, weight=None)

        nodes = list(graph)
        edges = list(graph.edges(data='type'))
        node_colors = [node_colors[nid] for nid in nodes]
        print(edges)
        edge_styles = [EDGE_STYLE_MAP[ty] for u, v, ty in edges]
        plt.plot()
        nx.draw_networkx(graph, pos, labels=labels, node_size=1000,
                edgelist=edges, style=edge_styles,
                nodelist=nodes, node_color=node_colors)
        plt.show()
    print("min nodes on a graph:", min_nodes)
