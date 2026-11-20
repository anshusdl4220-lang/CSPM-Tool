
from scanner.threat_detector import (
    load_security_events,
    detect_threats
)

events = load_security_events(
    "config/security_events.json"
)

findings = detect_threats(events)

print("\n===== THREAT DETECTION =====")

for finding in findings:
    print(
        f"[{finding['severity']}] "
        f"{finding['asset_id']} - "
        f"{finding['issue']}"
    )

    print(f"Description: {finding['description']}")
