from scanner.iam_scanner import scan_iam
from scanner.data_scanner import scan_data
from scanner.network_scanner import scan_network


def run_all_scanners(cloud):

    findings = []

    findings.extend(
        scan_iam(cloud.get("iam", []))
    )

    findings.extend(
        scan_data(cloud)
    )

    findings.extend(
        scan_network(cloud.get("network", []))
    )

    return findings