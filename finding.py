def create_finding(
    asset_id,
    category,
    issue,
    severity,
    description
):

    return {
        "asset_id": asset_id,
        "category": category,
        "issue": issue,
        "severity": severity,
        "description": description
    }