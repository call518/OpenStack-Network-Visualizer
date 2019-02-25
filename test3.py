import networkx as nx

G=nx.Graph()
G.add_node(1,color='red')
G.add_node(2,color='blue')
G.add_node(3,color='green')
color=nx.get_node_attributes(G,'color')
print(color)
nx.write_gexf(G, "file.gexf", version="1.2draft")
