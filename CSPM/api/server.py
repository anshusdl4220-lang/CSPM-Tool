
import json
import sqlite3
from pathlib import Path
from scanner.remediation import get_remediation
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_connection
from compliance.compliance_service import analyze_compliance
from graph.attack_path_builder import build_attack_graph
from graph.bfs import bfs
from risk.risk_engine import calculate_asset_risk, get_risk_level


app = FastAPI(
    title="CSPM Security API",
    description="Cloud asset, finding, and risk assessment API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "database"
    / "cspm.db"
)


def query_database(sql, parameters=()):
    if not DB_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="Database not initialized. Run python main.py first."
        )

    try:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row

        try:
            rows = connection.execute(sql, parameters).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Database query failed."
        )


@app.get("/")
def home():
    return {
        "project": "CSPM",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/assets")
def get_assets():
    return query_database("""
        SELECT asset_id, asset_type, category, configuration
        FROM assets
        ORDER BY asset_id
    """)


@app.get("/findings")
def get_findings():
    return query_database("""
        SELECT id, asset_id, category, issue, severity,
               description, risk_score, risk_level
        FROM findings
        ORDER BY risk_score DESC
    """)


@app.get("/events")
def get_security_events():
    return query_database("""
        SELECT id, event_type, asset_id, event_data
        FROM security_events
        ORDER BY id DESC
    """)


def get_assets_for_graph():
    rows = query_database("""
        SELECT asset_id, asset_type, category, configuration
        FROM assets
        ORDER BY asset_id
    """)

    assets = []

    for item in rows:
        configuration = item.get("configuration", {})

        if isinstance(configuration, str):
            try:
                configuration = json.loads(configuration)
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Invalid JSON configuration for asset "
                        + str(item.get("asset_id"))
                    )
                )

        if not isinstance(configuration, dict):
            configuration = {}

        assets.append({
            "id": item["asset_id"],
            "type": item["asset_type"],
            "category": item["category"],
            "configuration": configuration
        })

    return assets


def get_findings_for_path():
    return query_database("""
        SELECT asset_id, category, issue, severity,
               description, risk_score, risk_level
        FROM findings
    """)


@app.get("/attack-path")
def get_attack_path():
    # 1. Load assets and build the graph.
    assets = get_assets_for_graph()
    graph = build_attack_graph(assets)

    asset_lookup = {
        asset["id"]: asset
        for asset in assets
    }

    # 2. Load security findings.
    findings = get_findings_for_path()

    findings_by_asset = {}

    for finding in findings:
        asset_id = finding.get("asset_id")

        if asset_id:
            findings_by_asset.setdefault(asset_id, []).append(finding)

    # 3. Collect graph edges.
    edges = []

    for source, neighbors in graph.graph.items():
        for neighbor in neighbors:
            edges.append({
                "source": source,
                "target": neighbor
            })

    # 4. Find Internet-to-asset paths and score them.
    paths = []

    for asset in assets:
        target = asset["id"]
        path = bfs(graph, "Internet", target)

        if not path or len(path) < 2:
            continue

        assets_in_path = []
        path_risks = []

        for node in path:
            asset_data = asset_lookup.get(node)

            if asset_data is None:
                continue

            assets_in_path.append({
                "asset_id": node,
                "asset_type": asset_data.get("type"),
                "category": asset_data.get("category")
            })

            configuration = asset_data.get("configuration", {})

            for finding in findings_by_asset.get(node, []):
                # Calculate using the existing risk engine.
                result = calculate_asset_risk(
                    finding,
                    configuration
                )
                path_risks.append(result)

        # Use the highest finding score, not the sum.
        path_score = max(
            (item["risk_score"] for item in path_risks),
            default=0
        )

        paths.append({
            "target": target,
            "path": path,
            "path_length": len(path) - 1,
            "assets_in_path": assets_in_path,
            "risk_score": path_score,
            "risk_level": get_risk_level(path_score),
            "findings": path_risks
        })

    # 5. Return the graph and scored paths.
    return {
        "nodes": list(graph.graph.keys()),
        "edges": edges,
        "paths": paths
    }

@app.get("/remediations")
def get_remediations():
    findings = get_findings()

    results = []

    for finding in findings:
        recommendation = get_remediation(finding.get("issue"))

        results.append({
            "asset_id": finding.get("asset_id"),
            "issue": finding.get("issue"),
            "severity": finding.get("severity"),
            "risk_score": finding.get("risk_score"),
            "risk_level": finding.get("risk_level"),
            "recommended_action": recommendation["action"],
            "remediation_priority": recommendation["priority"]
        })

    return results
    
@app.get("/compliance")
def get_compliance_results():
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                asset_id,
                issue,
                severity,
                framework,
                control_id,
                control_name,
                status,
                created_at
            FROM compliance_results
            ORDER BY id DESC
            """
        ).fetchall()

        columns = [
            "id",
            "asset_id",
            "issue",
            "severity",
            "framework",
            "control_id",
            "control_name",
            "status",
            "created_at",
        ]

        return [dict(zip(columns, row)) for row in rows]
    
@app.post("/compliance/analyze")
def run_compliance_analysis():
    findings = get_findings()
    results = analyze_compliance(findings)

    return {
        "message": "Compliance analysis completed",
        "findings_analyzed": len(findings),
        "compliance_results": len(results),
        "results": results,
    }




