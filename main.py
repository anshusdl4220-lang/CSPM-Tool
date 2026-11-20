
from discovery.config_loader import load_configuration
from discovery.assets_discovery import discover_assets

from scanner.scanner_manager import run_all_scanners
from scanner.threat_detector import (
    load_security_events,
    detect_threats
)

from risk.risk_engine import calculate_asset_risk
from dsa.hash_table import AssetTable

from database.database import (
    initialize_database,
    save_assets,
    save_findings,
    save_security_events,
    show_database_summary
)


# ==========================================
# LOAD CLOUD CONFIGURATION
# ==========================================

cloud = load_configuration("config/cloud_environment.json")

initialize_database()


# ==========================================
# STAGE 1: ASSET DISCOVERY
# ==========================================

assets = discover_assets(cloud)

# Save discovered assets to SQLite.
save_assets(assets)

# Build a hash table for asset lookup.
asset_table = AssetTable()

for asset in assets:
    asset_table.insert(asset)

print("\n===== ASSETS =====")

for asset in assets:
    print(asset["id"], "->", asset["type"])


# ==========================================
# HASH TABLE TEST
# ==========================================

print("\n===== HASH TABLE SEARCH =====")

db_asset = asset_table.search("DB-01")

if db_asset:
    print("Found:", db_asset["id"], "->", db_asset["type"])
else:
    print("Asset DB-01 not found")


# ==========================================
# STAGE 2: SECURITY SCANNING
# ==========================================

findings = run_all_scanners(cloud)

print("\n===== RAW SCANNER FINDINGS =====")

for finding in findings:
    print(
        finding.get("asset_id"),
        "|",
        finding.get("issue"),
        "|",
        finding.get("severity")
    )

print("Total raw scanner findings:", len(findings))


# Load and analyze security events.
events = load_security_events("config/security_events.json")

threat_findings = detect_threats(events)

# Persist the events.
save_security_events(events)

# Combine scanner findings and threat findings.
findings.extend(threat_findings)

print("\n===== ALL SECURITY FINDINGS =====")

for finding in findings:
    print(
        f"[{finding['severity']}] "
        f"{finding['asset_id']} - "
        f"{finding['issue']}"
    )


# ==========================================
# STAGE 3: RISK ANALYSIS
# ==========================================

print("\n===== RISK ANALYSIS =====")

risk_results = []

for finding in findings:
    asset_id = finding.get("asset_id")

    # Find the corresponding cloud asset.
    asset_data = asset_table.search(asset_id)

    if asset_data is None:
        print(
            f"WARNING: Asset {asset_id} was not found. "
            "Skipping this finding."
        )
        continue

    # The risk engine expects the asset configuration.
    asset_configuration = asset_data.get("configuration", {})

    # Calculate risk using the existing risk engine.
    result = calculate_asset_risk(
        finding,
        asset_configuration
    )

    # Preserve the original finding and add risk information.
    risk_result = {
        **finding,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"]
    }

    risk_results.append(risk_result)

    print(
        f"{asset_id} | "
        f"{finding.get('issue')} | "
        f"Risk: {result['risk_score']}/100 | "
        f"{result['risk_level']}"
    )


# ==========================================
# DEBUG: VERIFY RESULTS BEFORE SAVING
# ==========================================

print("\n===== FINDINGS BY ASSET BEFORE SAVING =====")

for finding in risk_results:
    print(
        finding.get("asset_id"),
        "|",
        finding.get("issue"),
        "|",
        finding.get("risk_score")
    )

print("Total risk results:", len(risk_results))


# ==========================================
# STAGE 4: SAVE RESULTS
# ==========================================

# Save once after all findings have been processed.
save_findings(risk_results)


# ==========================================
# DATABASE SUMMARY
# ==========================================

print("\n===== DATABASE SUMMARY =====")

show_database_summary()
