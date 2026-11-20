
"""
CSPM Compliance Mapper
Maps security findings to relevant compliance controls.
"""

COMPLIANCE_RULES = [
    {
        "keywords": ["public", "storage", "bucket"],
        "framework": "CIS Controls",
        "control_id": "3.3",
        "control_name": "Protect Data",
    },
    {
        "keywords": ["iam", "permission", "privilege", "access"],
        "framework": "NIST CSF",
        "control_id": "PR.AA",
        "control_name": "Identity Management and Access Control",
    },
    {
        "keywords": ["firewall", "port", "network", "security group"],
        "framework": "NIST CSF",
        "control_id": "PR.IR",
        "control_name": "Technology Infrastructure Resilience",
    },
    {
        "keywords": ["encryption", "unencrypted", "plaintext"],
        "framework": "NIST CSF",
        "control_id": "PR.DS",
        "control_name": "Data Security",
    },
]


def map_finding_to_compliance(finding):
    """Map one CSPM finding to applicable compliance controls."""

    searchable_text = " ".join(
        str(finding.get(field, ""))
        for field in ("category", "issue", "description")
    ).lower()

    matches = []

    for rule in COMPLIANCE_RULES:
        if any(keyword in searchable_text for keyword in rule["keywords"]):
            matches.append({
                "asset_id": finding.get("asset_id"),
                "issue": finding.get("issue", "Unknown issue"),
                "severity": finding.get("severity", "Unknown"),
                "framework": rule["framework"],
                "control_id": rule["control_id"],
                "control_name": rule["control_name"],
                "status": "FAIL",
            })

    return matches


def map_findings_to_compliance(findings):
    """Map a list of findings and return all matching controls."""

    results = []

    for finding in findings:
        results.extend(map_finding_to_compliance(finding))

    return results
