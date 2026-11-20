
from graph.graph import Graph

def build_attack_graph(assets):
    graph = Graph()

    # Add every discovered cloud asset as a graph node.
    for asset in assets:
        asset_id = asset["id"]
        graph.add_node(asset_id)

    # Build relationships from the discovered configuration.
    for asset in assets:
        asset_id = asset["id"]
        config = asset.get("configuration", {})
        category = str(asset.get("category", "")).lower()
        asset_type = str(asset.get("type", "")).lower()

        # A public storage bucket may be reachable from the Internet.
        if (
            "storage" in category
            or "storage" in asset_type
            or "bucket" in asset_id.lower()
        ):
            if config.get("public", False):
                graph.add_edge("Internet", asset_id)

        # A publicly accessible database may be reachable directly.
        if "database" in category or "database" in asset_type:
            if config.get("public", False):
                graph.add_edge("Internet", asset_id)

        # Link compute resources to their configured security groups.
        if "compute" in category or "compute" in asset_type:
            security_group = config.get("security_group")

            if security_group:
                graph.add_edge(security_group, asset_id)

    # Add Internet exposure edges for open SSH/RDP rules.
    for asset in assets:
        asset_id = asset["id"]
        config = asset.get("configuration", {})
        category = str(asset.get("category", "")).lower()
        asset_type = str(asset.get("type", "")).lower()

        if "network" not in category and "network" not in asset_type:
            continue

        rules = config.get("rules", [])

        for rule in rules:
            source = rule.get("source", "")
            port = rule.get("port")

            if source == "0.0.0.0/0" and str(port) in {"22", "3389"}:
                graph.add_edge("Internet", asset_id)

    return graph
