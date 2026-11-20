import json


def load_security_events(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def detect_threats(events):

    findings = []

    for event in events:

        event_type = event.get("event")
        user = event.get("user", "UNKNOWN")

        if (
            event_type == "FAILED_LOGIN"
            and event.get("count", 0) >= 10
        ):
            findings.append({
                "asset_id": user,
                "category": "Threat Detection",
                "issue": "Suspicious Login Activity",
                "severity": "HIGH",
                "description": (
                    f"{event['count']} failed login attempts detected."
                )
            })

        elif event_type == "PRIVILEGE_CHANGE":
            findings.append({
                "asset_id": user,
                "category": "Threat Detection",
                "issue": "Potential Privilege Escalation",
                "severity": "HIGH",
                "description": (
                    "A privilege change was detected. "
                    "Verify whether it was authorized."
                )
            })

    return findings