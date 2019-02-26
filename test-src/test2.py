"""
Example of how to export a graph in NetworkX to gexf with coloring.
Usable by Gelphi for example.
"""

import networkx as nx
""" Create a graph with three nodes"""
graph = nx.Graph()
graph.add_node('red')
graph.add_node('green')
graph.add_node('blue')
""" Add color data """
graph.node['red']['viz'] = {'color': {'r': 255, 'g': 0, 'b': 0, 'a': 0}}
graph.node['green']['viz'] = {'color': {'r': 0, 'g': 255, 'b': 0, 'a': 0}}
graph.node['blue']['viz'] = {'color': {'r': 0, 'g': 0, 'b': 255, 'a': 0}}
""" Write to GEXF """
# Use 1.2draft so you do not get a deprecated warning in Gelphi
nx.write_gexf(graph, "file.gexf", version="1.2draft")
