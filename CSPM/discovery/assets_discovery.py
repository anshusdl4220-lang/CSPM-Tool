def discover_assets(cloud):

    assets = []

    categories = [
        "compute",
        "storage",
        "databases",
        "iam",
        "network"
    ]

    for category in categories:

        resources = cloud.get(category, [])

        for resource in resources:

            asset = {
                "id": resource["id"],
                "type": resource["type"],
                "category": category,
                "configuration": resource
            }

            assets.append(asset)

    return assets