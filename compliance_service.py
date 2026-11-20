
from compliance.compliance_mapper import map_findings_to_compliance
from database.database import (
    initialize_database,
    save_compliance_results,
)


def analyze_compliance(findings):
    """Map CSPM findings and save their compliance results."""

    initialize_database()

    results = map_findings_to_compliance(findings)

    if results:
        save_compliance_results(results)

    return results
