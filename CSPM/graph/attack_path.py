from graph.graph import Graph


def build_attack_graph():

    graph = Graph()

    graph.add_edge(
        "Internet",
        "SG-01"
    )

    graph.add_edge(
        "SG-01",
        "VM-01"
    )

    graph.add_edge(
        "VM-01",
        "IAM-ROLE-01"
    )

    graph.add_edge(
        "IAM-ROLE-01",
        "DB-01"
    )

    graph.add_edge(
        "DB-01",
        "Sensitive-Data"
    )

    return graph