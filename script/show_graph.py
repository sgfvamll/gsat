import os
import sys
import json
import matplotlib.pyplot as plt
import networkx as nx
import random

def create_graph(nodes, edges):
    """
    Create a NetworkX direct graph from the list of nodes and edges.

    Args:
        node_list: list of nodes
        edge_list: list of edges

    Return
        np.matrix: Numpy adjacency matrix
        list: nodes in the graph
    """
    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node)
    for edge in edges:
        if len(edge) > 2:
            G.add_edge(edge[0], edge[1], weight=edge[2])
        else:
            G.add_edge(edge[0], edge[1])

    return G

if __name__ == "__main__":
    graph_fp = sys.argv[1]
    with open(graph_fp, "r") as f:
        graph_data = json.load(f)
    graph_data = graph_data[list(graph_data.keys())[0]]
    min_nodes = 100000
    for fva, func_data in graph_data.items():
        nodes = func_data['nodes']
        edges = func_data['edges']
        if len(nodes) < min_nodes:
            min_nodes = len(nodes)
        if len(nodes) > 100:
            continue
        graph = create_graph(nodes, edges)
        print(fva, graph)
        labels = dict([
            (int(nid), nid+' '+mnem_data['bb_mnems'][0]) 
            for nid, mnem_data in func_data['basic_blocks'].items()
        ])
        seed = random.randint(0, 10000)
        print(seed)
        pos = nx.spring_layout(graph, k=20, iterations=1000, seed=seed)  # positions for all nodes
        plt.plot()
        nx.draw(graph, pos, labels=labels, node_size = 800)
        plt.show()  
    print(min_nodes)
