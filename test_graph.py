from graph import Graph
from bfs import bfs


# Create graph
graph = Graph()


# Create attack path
graph.add_edge("Internet", "SG-01")
graph.add_edge("SG-01", "VM-01")
graph.add_edge("VM-01", "IAM-ROLE-01")
graph.add_edge("IAM-ROLE-01", "DB-01")
graph.add_edge("DB-01", "Sensitive-Data")


# Find attack path
path = bfs(
    graph,
    "Internet",
    "Sensitive-Data"
)


print("\n===== ATTACK PATH =====")

if path:

    print(" -> ".join(path))

else:

    print("No attack path found")