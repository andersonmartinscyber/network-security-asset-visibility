"""Tests for contextual security risk prioritization."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from network_asset_visibility.reporting import export_security_report

import unittest

from network_asset_visibility.risk_prioritization import (
    calculate_risk_score,
    classify_risk_priority,
    prioritize_findings,
)


class TestRiskPrioritization(unittest.TestCase):

    def test_critical_severity_and_critical_asset(self):
        self.assertEqual(
            calculate_risk_score("critical", "critical"),
            100.0,
        )

    def test_high_severity_and_critical_asset(self):
        self.assertEqual(
            calculate_risk_score("high", "critical"),
            85.0,
        )

    def test_medium_severity_and_medium_asset(self):
        self.assertEqual(
            calculate_risk_score("medium", "medium"),
            50.0,
        )

    def test_low_severity_and_low_asset(self):
        self.assertEqual(
            calculate_risk_score("low", "low"),
            25.0,
        )

    def test_invalid_severity(self):
        with self.assertRaises(ValueError):
            calculate_risk_score("unknown", "high")

    def test_invalid_criticality(self):
        with self.assertRaises(ValueError):
            calculate_risk_score("high", "unknown")

    def test_priority_thresholds(self):
        self.assertEqual(classify_risk_priority(85), "critical")
        self.assertEqual(classify_risk_priority(65), "high")
        self.assertEqual(classify_risk_priority(40), "medium")
        self.assertEqual(classify_risk_priority(25), "low")

    def test_invalid_scores(self):
        for score in (-1, 101, True, None, "high", float("nan")):
            with self.subTest(score=score):
                with self.assertRaises(ValueError):
                    classify_risk_priority(score)

    def test_prioritization_order(self):
        findings = [
            {
                "asset_id": "NET-002",
                "rule_id": "NET-003",
                "severity": "medium",
                "asset_criticality": "medium",
            },
            {
                "asset_id": "NET-001",
                "rule_id": "NET-001",
                "severity": "high",
                "asset_criticality": "critical",
            },
        ]

        result = prioritize_findings(findings)

        self.assertEqual(result[0]["asset_id"], "NET-001")
        self.assertEqual(result[0]["risk_score"], 85.0)
        self.assertEqual(result[0]["risk_priority"], "critical")

    def test_empty_findings(self):
        self.assertEqual(prioritize_findings([]), [])

    def test_original_findings_are_not_modified(self):
        finding = {
            "asset_id": "NET-001",
            "rule_id": "NET-001",
            "severity": "high",
            "asset_criticality": "critical",
        }

        prioritize_findings([finding])

        self.assertNotIn("risk_score", finding)
        self.assertNotIn("risk_priority", finding)


class TestRiskReportingIntegration(unittest.TestCase):
    """Validate contextual risk integration with JSON reporting."""

    def setUp(self):
        self.assets = [
            {
                "asset_id": "NET-001",
                "hostname": "CORE-SW",
                "criticality": "critical",
            },
            {
                "asset_id": "NET-002",
                "hostname": "ACCESS-SW",
                "criticality": "medium",
            },
        ]

        self.findings = [
            {
                "asset_id": "NET-002",
                "rule_id": "NET-003",
                "severity": "medium",
                "asset_criticality": "medium",
            },
            {
                "asset_id": "NET-001",
                "rule_id": "NET-001",
                "severity": "high",
                "asset_criticality": "critical",
            },
        ]

    def test_report_includes_prioritized_findings(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            report = export_security_report(
                self.assets,
                self.findings,
                path,
                include_risk_prioritization=True,
            )

            risk = report["risk_prioritization"]

            self.assertEqual(risk["total_prioritized_findings"], 2)
            self.assertEqual(risk["findings"][0]["asset_id"], "NET-001")
            self.assertEqual(risk["findings"][0]["risk_score"], 85.0)
            self.assertEqual(
                risk["findings"][0]["risk_priority"],
                "critical",
            )

    def test_legacy_report_excludes_risk_prioritization(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            report = export_security_report(
                self.assets,
                self.findings,
                path,
            )

            self.assertNotIn("risk_prioritization", report)

    def test_prioritized_report_is_valid_json(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            export_security_report(
                self.assets,
                self.findings,
                path,
                include_risk_prioritization=True,
            )

            with path.open("r", encoding="utf-8") as file:
                saved_report = json.load(file)

            self.assertEqual(
                saved_report["risk_prioritization"]["findings"][0][
                    "risk_priority"
                ],
                "critical",
            )

    def test_invalid_risk_data_prevents_report_creation(self):
        invalid_findings = [
            {
                "asset_id": "NET-001",
                "rule_id": "NET-001",
                "severity": "unknown",
                "asset_criticality": "critical",
            },
        ]

        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            with self.assertRaises(ValueError):
                export_security_report(
                    self.assets,
                    invalid_findings,
                    path,
                    include_risk_prioritization=True,
                )

            self.assertFalse(path.exists())

if __name__ == "__main__":
    unittest.main()