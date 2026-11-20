''''from risk.risk_engine import calculate_asset_risk, get_risk_level'''

SEVERITY_SCORE = {
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90
}


# Get security information from the cloud asset
def get_asset_context(asset):

    return {
        "exposure": 100 if asset.get("public", False) else 20,

        "criticality": asset.get(
            "criticality", 5
        ) * 10,

        "sensitivity": 100 if asset.get(
            "sensitive_data", False
        ) else 20,

        "privilege": 100 if asset.get(
            "privilege", ""
        ) == "admin" else 30,

        "threat": 20
    }


# Calculate numerical risk score
def calculate_risk(
    severity,
    exposure,
    criticality,
    sensitivity,
    privilege,
    threat
):

    severity = SEVERITY_SCORE.get(
        severity,
        0
    )

    score = (
        severity * 0.25 +
        exposure * 0.20 +
        criticality * 0.20 +
        sensitivity * 0.15 +
        privilege * 0.10 +
        threat * 0.10
    )

    return round(min(score, 100))


# Convert score to risk level
def get_risk_level(score):

    if score >= 81:
        return "CRITICAL"

    elif score >= 61:
        return "VERY HIGH"

    elif score >= 41:
        return "HIGH"

    elif score >= 21:
        return "MEDIUM"

    else:
        return "LOW"


# Complete asset risk analysis
def calculate_asset_risk(finding, asset):

    context = get_asset_context(asset)

    score = calculate_risk(
        finding["severity"],
        context["exposure"],
        context["criticality"],
        context["sensitivity"],
        context["privilege"],
        context["threat"]
    )

    return {
        "asset_id": finding["asset_id"],
        "issue": finding["issue"],
        "severity": finding["severity"],
        "risk_score": score,
        "risk_level": get_risk_level(score)
    }
