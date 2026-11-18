"""Data loading and transformation for the security dashboard."""

import json
import math
from collections import Counter
from pathlib import Path

from network_asset_visibility.risk_prioritization import (
    prioritize_findings,
)


RISK_LEVELS = ("critical", "high", "medium", "low")


def _validate_count(value, field):
    """Validate a non-negative integer metric."""

    if type(value) is not int or value < 0:
        raise ValueError(f"Invalid count: {field}")


def validate_security_report(report):
    """Validate the structure and consistency of a security report."""

    if not isinstance(report, dict):
        raise ValueError("Security report must be a JSON object")

    required_fields = (
        "project",
        "data_source",
        "metrics",
        "findings",
    )

    for field in required_fields:
        if field not in report:
            raise ValueError(f"Missing report field: {field}")

    metrics = report["metrics"]
    findings = report["findings"]

    if not isinstance(metrics, dict):
        raise ValueError("Metrics must be an object")

    if not isinstance(findings, list):
        raise ValueError("Findings must be a list")

    for field in (
        "total_assets",
        "affected_assets",
        "total_findings",
    ):
        _validate_count(metrics.get(field), field)

    if metrics["total_findings"] != len(findings):
        raise ValueError("Finding count mismatch")

    if metrics["affected_assets"] > metrics["total_assets"]:
        raise ValueError("Affected assets exceed total assets")

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Invalid finding")

        for field in (
            "asset_id",
            "hostname",
            "rule_id",
            "title",
            "severity",
            "asset_criticality",
        ):
            if not isinstance(finding.get(field), str):
                raise ValueError(f"Invalid finding field: {field}")

        if finding["severity"] not in RISK_LEVELS:
            raise ValueError("Invalid finding severity")

        if finding["asset_criticality"] not in RISK_LEVELS:
            raise ValueError("Invalid asset criticality")

    affected_assets = {
        finding["asset_id"] for finding in findings
    }

    if len(affected_assets) != metrics["affected_assets"]:
        raise ValueError("Affected asset count mismatch")

    # Validate optional configuration coverage.
    if "configuration_coverage" in metrics:
        coverage = metrics["configuration_coverage"]

        if not isinstance(coverage, dict):
            raise ValueError("Invalid configuration coverage")

        percentage = coverage.get("coverage_percentage")

        if (
            type(percentage) not in (int, float)
            or not math.isfinite(percentage)
            or not 0 <= percentage <= 100
        ):
            raise ValueError("Invalid coverage percentage")

    # Validate optional contextual risk prioritization.
    if "risk_prioritization" in report:
        risk = report["risk_prioritization"]

        if not isinstance(risk, dict):
            raise ValueError("Invalid risk prioritization")

        prioritized = risk.get("findings")

        if not isinstance(prioritized, list):
            raise ValueError("Invalid prioritized findings")

        _validate_count(
            risk.get("total_prioritized_findings"),
            "total_prioritized_findings",
        )

        if (
            len(prioritized) != len(findings)
            or risk["total_prioritized_findings"] != len(prioritized)
        ):
            raise ValueError("Prioritized finding count mismatch")

        for finding in prioritized:
            if not isinstance(finding, dict):
                raise ValueError("Invalid prioritized finding")

            score = finding.get("risk_score")
            priority = finding.get("risk_priority")

            if (
                type(score) not in (int, float)
                or not math.isfinite(score)
                or not 0 <= score <= 100
            ):
                raise ValueError("Invalid risk score")

            if priority not in RISK_LEVELS:
                raise ValueError("Invalid risk priority")

        # Recalculate risk to ensure report consistency.
        expected_findings = prioritize_findings(findings)

        if prioritized != expected_findings:
            raise ValueError(
                "Prioritized findings do not match "
                "the expected risk assessment"
            )

    return report


def load_security_report(report_path):
    """Load and validate a JSON security report."""

    path = Path(report_path)

    with path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    return validate_security_report(report)


def get_dashboard_summary(report):
    """Extract key security dashboard indicators."""

    metrics = report["metrics"]
    coverage = metrics.get("configuration_coverage", {})

    return {
        "total_assets": metrics["total_assets"],
        "affected_assets": metrics["affected_assets"],
        "total_findings": metrics["total_findings"],
        "coverage_percentage": coverage.get(
            "coverage_percentage"
        ),
    }


def get_severity_distribution(report):
    """Return findings grouped by severity."""

    counts = Counter(
        finding["severity"]
        for finding in report["findings"]
    )

    return {
        level: counts[level]
        for level in RISK_LEVELS
    }


def get_prioritized_findings(report):
    """Return prioritized findings when available."""

    risk = report.get("risk_prioritization", {})

    return [
        finding.copy()
        for finding in risk.get("findings", [])
    ]


def get_risk_distribution(report):
    """Return findings grouped by contextual risk priority."""

    counts = Counter(
        finding["risk_priority"]
        for finding in get_prioritized_findings(report)
    )

    return {
        level: counts[level]
        for level in RISK_LEVELS
    }


def get_asset_risk_ranking(report):
    """Rank affected assets by their highest contextual risk."""

    ranking = {}

    for finding in get_prioritized_findings(report):
        asset_id = finding["asset_id"]

        if asset_id not in ranking:
            ranking[asset_id] = {
                "asset_id": asset_id,
                "hostname": finding["hostname"],
                "asset_criticality": finding["asset_criticality"],
                "total_findings": 0,
                "max_risk_score": finding["risk_score"],
                "risk_priority": finding["risk_priority"],
            }

        asset = ranking[asset_id]
        asset["total_findings"] += 1

        if finding["risk_score"] > asset["max_risk_score"]:
            asset["max_risk_score"] = finding["risk_score"]
            asset["risk_priority"] = finding["risk_priority"]

    return sorted(
        ranking.values(),
        key=lambda asset: (
            -asset["max_risk_score"],
            asset["asset_id"],
        ),
    )