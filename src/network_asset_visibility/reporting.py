import json
from collections import Counter
from pathlib import Path


def generate_security_metrics(assets, findings):
    """Generate metrics from an inventory and security findings."""

    asset_ids = {asset["asset_id"] for asset in assets}

    if len(asset_ids) != len(assets):
        raise ValueError("Duplicate asset IDs in inventory")

    for finding in findings:
        if finding["asset_id"] not in asset_ids:
            raise ValueError(
                f"Finding references unknown asset: {finding['asset_id']}"
            )

    affected_assets = {
        finding["asset_id"] for finding in findings
    }

    severity_counts = Counter(
        finding["severity"] for finding in findings
    )

    rule_counts = Counter(
        finding["rule_id"] for finding in findings
    )

    return {
        "total_assets": len(assets),
        "affected_assets": len(affected_assets),
        "total_findings": len(findings),
        "findings_by_severity": dict(severity_counts),
        "findings_by_rule": dict(rule_counts),
    }


def export_security_report(assets, findings, output_path):
    """Export security metrics and findings to a JSON file."""

    metrics = generate_security_metrics(assets, findings)

    report = {
        "project": "Network Security & Asset Visibility",
        "data_source": "synthetic_lab",
        "metrics": metrics,
        "findings": findings,
    }

    path = Path(output_path)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    return report