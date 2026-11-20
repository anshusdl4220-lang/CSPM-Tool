
import sqlite3
from pathlib import Path

DB_PATH = Path("database/cspm.db")

if not DB_PATH.exists():
    raise FileNotFoundError(
        f"Database not found: {DB_PATH.resolve()}"
    )

connection = sqlite3.connect(DB_PATH)

try:
    # Show the number of records before cleanup.
    before = connection.execute(
        "SELECT COUNT(*) FROM findings"
    ).fetchone()[0]

    print("Findings before cleanup:", before)

    # Keep the newest record for each distinct finding.
    connection.execute("""
        DELETE FROM findings
        WHERE id NOT IN (
            SELECT MAX(id)
            FROM findings
            GROUP BY
                asset_id,
                category,
                issue,
                severity,
                description
        )
    """)

    connection.commit()

    after = connection.execute(
        "SELECT COUNT(*) FROM findings"
    ).fetchone()[0]

    print("Findings after cleanup:", after)
    print("Duplicate records removed:", before - after)

    print("\nFindings by asset:")

    rows = connection.execute("""
        SELECT asset_id, COUNT(*)
        FROM findings
        GROUP BY asset_id
        ORDER BY asset_id
    """).fetchall()

    for row in rows:
        print(row)

except Exception:
    connection.rollback()
    raise

finally:
    connection.close()
