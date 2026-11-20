from scanner.finding import create_finding


def scan_iam(iam_resources):

    findings = []

    for user in iam_resources:

        if not user["mfa"]:

            findings.append(
                create_finding(
                    user["id"],
                    "IAM",
                    "MFA Disabled",
                    "HIGH",
                    "Multi-factor authentication is disabled."
                )
            )

        if user["privilege"] == "admin":

            findings.append(
                create_finding(
                    user["id"],
                    "IAM",
                    "Excessive Privilege",
                    "HIGH",
                    "User has administrative privileges."
                )
            )

        if user["unused"]:

            findings.append(
                create_finding(
                    user["id"],
                    "IAM",
                    "Unused Account",
                    "MEDIUM",
                    "Account appears to be unused."
                )
            )

    return findings