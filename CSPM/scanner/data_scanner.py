from scanner.finding import create_finding


def scan_data(cloud):

    findings = []

    for bucket in cloud.get("storage", []):

        if bucket["public"]:

            findings.append(
                create_finding(
                    bucket["id"],
                    "Data Protection",
                    "Public Storage",
                    "CRITICAL",
                    "Storage resource is publicly accessible."
                )
            )

        if not bucket["encrypted"]:

            findings.append(
                create_finding(
                    bucket["id"],
                    "Data Protection",
                    "Encryption Disabled",
                    "HIGH",
                    "Storage encryption is disabled."
                )
            )

    for database in cloud.get("databases", []):

        if database["public"]:

            findings.append(
                create_finding(
                    database["id"],
                    "Data Protection",
                    "Public Database",
                    "CRITICAL",
                    "Database is publicly accessible."
                )
            )

        if not database["encrypted"]:

            findings.append(
                create_finding(
                    database["id"],
                    "Data Protection",
                    "Database Encryption Disabled",
                    "HIGH",
                    "Database encryption is disabled."
                )
            )

    return findings