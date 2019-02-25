import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
g = nx.Graph()
g.add_edge(1,2)
f = plt.figure()
nx.draw(g, ax=f.add_subplot(111))
f.savefig("graph.png")
