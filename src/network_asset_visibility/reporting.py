"""Security metrics and JSON reporting."""

import json
from collections import Counter
from pathlib import Path

from network_asset_visibility.coverage import (
    analyze_configuration_coverage,
)
from network_asset_visibility.risk_prioritization import (
    prioritize_findings,
)


def generate_security_metrics(assets, findings, configs=None):
    """Generate metrics from inventory, findings, and optional configs."""

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

    metrics = {
        "total_assets": len(assets),
        "affected_assets": len(affected_assets),
        "total_findings": len(findings),
        "findings_by_severity": dict(severity_counts),
        "findings_by_rule": dict(rule_counts),
    }

    if configs is not None:
        metrics["configuration_coverage"] = (
            analyze_configuration_coverage(assets, configs)
        )

    return metrics


def export_security_report(
    assets,
    findings,
    output_path,
    configs=None,
    include_risk_prioritization=False,
):
    """Export security metrics and optional risk prioritization to JSON."""

    metrics = generate_security_metrics(
        assets,
        findings,
        configs=configs,
    )

    report = {
        "project": "Network Security & Asset Visibility",
        "data_source": "synthetic_lab",
        "metrics": metrics,
        "findings": findings,
    }

    if include_risk_prioritization:
        prioritized_findings = prioritize_findings(findings)

        report["risk_prioritization"] = {
            "method": "contextual_weighted_score",
            "severity_weight": 0.60,
            "asset_criticality_weight": 0.40,
            "total_prioritized_findings": len(prioritized_findings),
            "findings": prioritized_findings,
        }

    path = Path(output_path)

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return report