from scanner.finding import create_finding


def scan_network(network_resources):

    findings = []

    for security_group in network_resources:

        for rule in security_group["rules"]:

            if rule["source"] == "0.0.0.0/0":

                if rule["port"] == 22:

                    findings.append(
                        create_finding(
                            security_group["id"],
                            "Network",
                            "SSH Open to Internet",
                            "HIGH",
                            "Port 22 is accessible from the internet."
                        )
                    )

                elif rule["port"] == 3389:

                    findings.append(
                        create_finding(
                            security_group["id"],
                            "Network",
                            "RDP Open to Internet",
                            "CRITICAL",
                            "Port 3389 is accessible from the internet."
                        )
                    )

    return findings