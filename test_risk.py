from risk_engine import calculate_risk, get_risk_level

score = calculate_risk(
    "CRITICAL",
    100,
    100,
    100,
    50,
    20
)

print("Risk Score:", score)
print("Risk Level:", get_risk_level(score))