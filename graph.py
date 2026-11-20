class Graph:

    def __init__(self):

        self.graph = {}

    def add_node(self, node):

        if node not in self.graph:

            self.graph[node] = []

    def add_edge(self, source, destination):

        self.add_node(source)
        self.add_node(destination)

        self.graph[source].append(destination)

    def get_neighbors(self, node):

        return self.graph.get(node, [])