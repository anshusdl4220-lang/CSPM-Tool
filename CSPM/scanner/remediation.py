
def get_remediation(issue):
    """Return a recommended fix for a security finding."""

    recommendations = {
        "mfa disabled": {
            "action": "Enable multi-factor authentication (MFA).",
            "priority": "HIGH"
        },
        "excessive privilege": {
            "action": "Apply least privilege and remove unnecessary admin access.",
            "priority": "HIGH"
        },
        "public storage": {
            "action": "Block public access unless explicitly required.",
            "priority": "CRITICAL"
        },
        "encryption disabled": {
            "action": "Enable encryption at rest and configure key management.",
            "priority": "HIGH"
        },
        "public database": {
            "action": "Remove public database exposure and restrict access to trusted networks.",
            "priority": "CRITICAL"
        },
        "ssh open to internet": {
            "action": "Restrict SSH access to approved IP addresses or a secure management network.",
            "priority": "HIGH"
        },
        "database encryption disabled": {
            "action": "Enable database encryption at rest and review encryption key settings.",
            "priority": "HIGH"
        }
    }

    normalized_issue = str(issue or "").strip().lower()

    for keyword, recommendation in recommendations.items():
        if keyword in normalized_issue:
            return recommendation

    return {
        "action": "Review the finding details and apply the appropriate security control.",
        "priority": "MEDIUM"
    }
