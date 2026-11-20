
from graph.attack_path_builder import build_attack_graph

assets = [
    {
        "id": "SG-01",
        "type": "network",
        "category": "network",
        "configuration": {
            "rules": [
                {
                    "protocol": "TCP",
                    "port": 22,
                    "source": "0.0.0.0/0"
                }
            ]
        }
    },
    {
        "id": "VM-01",
        "type": "compute",
        "category": "compute",
        "configuration": {
            "security_group": "SG-01"
        }
    },
    {
        "id": "BUCKET-01",
        "type": "storage",
        "category": "storage",
        "configuration": {
            "public": True,
            "sensitive_data": True
        }
    }
]

graph = build_attack_graph(assets)

print("Generated attack graph:")
for node, neighbors in graph.graph.items():
    print(f"{node} -> {neighbors}")
