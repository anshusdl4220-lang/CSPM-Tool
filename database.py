
import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).with_name("cspm.db")


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():

    with get_connection() as connection:

        connection.executescript("""
            CREATE TABLE IF NOT EXISTS compliance_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT,
            issue TEXT NOT NULL,
            severity TEXT,
            framework TEXT NOT NULL,
            control_id TEXT NOT NULL,
            control_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'FAIL',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                asset_type TEXT NOT NULL,
                category TEXT,
                configuration TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                category TEXT,
                issue TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                FOREIGN KEY (asset_id)
                    REFERENCES assets(asset_id)
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                asset_id TEXT,
                event_data TEXT NOT NULL
            );
        """)


def save_assets(assets):

    with get_connection() as connection:

        for asset in assets:

            connection.execute("""
                INSERT INTO assets
                (asset_id, asset_type, category, configuration)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    asset_type = excluded.asset_type,
                    category = excluded.category,
                    configuration = excluded.configuration
            """, (
                asset["id"],
                asset["type"],
                asset.get("category"),
                json.dumps(asset["configuration"])
            ))




def save_findings(findings):
    with get_connection() as connection:
        for finding in findings:
            connection.execute("""
                INSERT INTO findings (
                    asset_id,
                    category,
                    issue,
                    severity,
                    description,
                    risk_score,
                    risk_level
                )
                SELECT ?, ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM findings
                    WHERE asset_id = ?
                      AND category IS ?
                      AND issue = ?
                      AND severity = ?
                      AND description = ?
                )
            """, (
                finding["asset_id"],
                finding.get("category"),
                finding["issue"],
                finding["severity"],
                finding.get("description", ""),
                finding.get("risk_score"),
                finding.get("risk_level"),
                finding["asset_id"],
                finding.get("category"),
                finding["issue"],
                finding["severity"],
                finding.get("description", "")
            ))




def save_security_events(events):

    with get_connection() as connection:

        for event in events:

            connection.execute("""
                INSERT INTO security_events
                (event_type, asset_id, event_data)
                VALUES (?, ?, ?)
            """, (
                event.get("event", "UNKNOWN"),
                event.get("user", event.get("asset_id")),
                json.dumps(event)
            ))


def show_database_summary():

    with get_connection() as connection:

        for table in (
            "assets",
            "findings",
            "security_events"
        ):

            count = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

            print(f"{table}: {count} records")
            

def save_compliance_results(results):
    with get_connection() as connection:
        for result in results:
            existing = connection.execute(
                """
                SELECT id
                FROM compliance_results
                WHERE asset_id = ?
                  AND issue = ?
                  AND framework = ?
                  AND control_id = ?
                LIMIT 1
                """,
                (
                    str(result.get("asset_id", "")),
                    result.get("issue", "Unknown issue"),
                    result["framework"],
                    result["control_id"],
                ),
            ).fetchone()

            values = (
                result.get("severity", "UNKNOWN"),
                result["control_name"],
                result.get("status", "FAIL"),
            )

            if existing:
                connection.execute(
                    """
                    UPDATE compliance_results
                    SET severity = ?,
                        control_name = ?,
                        status = ?,
                        created_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (*values, existing[0]),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO compliance_results (
                        asset_id, issue, severity, framework,
                        control_id, control_name, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(result.get("asset_id", "")),
                        result.get("issue", "Unknown issue"),
                        values[0],
                        result["framework"],
                        result["control_id"],
                        values[1],
                        values[2],
                    ),
                )
