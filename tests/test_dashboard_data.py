"""Tests for the security dashboard data layer."""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from network_asset_visibility.dashboard_data import (
    get_asset_risk_ranking,
    get_dashboard_summary,
    get_prioritized_findings,
    get_risk_distribution,
    get_severity_distribution,
    load_security_report,
    validate_security_report,
)


class TestDashboardData(unittest.TestCase):
    """Validate dashboard data loading and transformations."""

    def setUp(self):
        """Create an independent synthetic report."""

        finding = {
            "asset_id": "NET-RT-001",
            "hostname": "BRANCH-RT-01",
            "rule_id": "NET-001",
            "title": "Insecure SNMP version",
            "severity": "high",
            "asset_criticality": "high",
        }

        prioritized = {
            **finding,
            "risk_score": 75.0,
            "risk_priority": "high",
        }

        self.report = {
            "project": "Network Security & Asset Visibility",
            "data_source": "synthetic_lab",
            "metrics": {
                "total_assets": 3,
                "affected_assets": 1,
                "total_findings": 1,
                "findings_by_severity": {"high": 1},
                "findings_by_rule": {"NET-001": 1},
                "configuration_coverage": {
                    "total_assets": 3,
                    "configured_assets": 3,
                    "unconfigured_assets": 0,
                    "coverage_percentage": 100.0,
                    "missing_by_criticality": {},
                    "missing_assets": [],
                },
            },
            "findings": [finding],
            "risk_prioritization": {
                "method": "contextual_weighted_score",
                "severity_weight": 0.60,
                "asset_criticality_weight": 0.40,
                "total_prioritized_findings": 1,
                "findings": [prioritized],
            },
        }

    def test_valid_security_report(self):
        result = validate_security_report(self.report)
        self.assertEqual(result, self.report)

    def test_missing_required_field(self):
        del self.report["metrics"]

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_invalid_report_type(self):
        with self.assertRaises(ValueError):
            validate_security_report([])

    def test_negative_metric(self):
        self.report["metrics"]["total_assets"] = -1

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_boolean_metric(self):
        self.report["metrics"]["total_assets"] = True

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_findings_count_mismatch(self):
        self.report["metrics"]["total_findings"] = 5

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_affected_assets_exceed_inventory(self):
        self.report["metrics"]["affected_assets"] = 4

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_affected_assets_count_mismatch(self):
        self.report["metrics"]["affected_assets"] = 2

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_invalid_finding_severity(self):
        self.report["findings"][0]["severity"] = "unknown"

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_invalid_asset_criticality(self):
        self.report["findings"][0]["asset_criticality"] = (
            "unknown"
        )

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_invalid_coverage_percentage(self):
        coverage = self.report["metrics"][
            "configuration_coverage"
        ]

        for value in (-1, 101, float("nan"), True):
            with self.subTest(value=value):
                coverage["coverage_percentage"] = value

                with self.assertRaises(ValueError):
                    validate_security_report(self.report)

    def test_invalid_risk_score(self):
        finding = self.report["risk_prioritization"][
            "findings"
        ][0]

        for value in (-1, 101, float("nan"), True):
            with self.subTest(value=value):
                finding["risk_score"] = value

                with self.assertRaises(ValueError):
                    validate_security_report(self.report)

    def test_invalid_risk_priority(self):
        self.report["risk_prioritization"][
            "findings"
        ][0]["risk_priority"] = "unknown"

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_prioritized_findings_count_mismatch(self):
        self.report["risk_prioritization"][
            "total_prioritized_findings"
        ] = 2

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_load_security_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            path.write_text(
                json.dumps(self.report),
                encoding="utf-8",
            )

            result = load_security_report(path)

            self.assertEqual(result, self.report)

    def test_load_missing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"

            with self.assertRaises(FileNotFoundError):
                load_security_report(path)

    def test_load_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"

            path.write_text(
                "{invalid json",
                encoding="utf-8",
            )

            with self.assertRaises(json.JSONDecodeError):
                load_security_report(path)

    def test_dashboard_summary(self):
        self.assertEqual(
            get_dashboard_summary(self.report),
            {
                "total_assets": 3,
                "affected_assets": 1,
                "total_findings": 1,
                "coverage_percentage": 100.0,
            },
        )

    def test_severity_distribution(self):
        self.assertEqual(
            get_severity_distribution(self.report),
            {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
            },
        )

    def test_risk_distribution(self):
        self.assertEqual(
            get_risk_distribution(self.report),
            {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
            },
        )

    def test_prioritized_findings(self):
        result = get_prioritized_findings(self.report)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk_score"], 75.0)
        self.assertEqual(result[0]["risk_priority"], "high")

    def test_prioritized_findings_do_not_mutate_report(self):
        original = deepcopy(self.report)

        result = get_prioritized_findings(self.report)
        result[0]["risk_score"] = 10.0

        self.assertEqual(self.report, original)

    def test_report_without_configuration_coverage(self):
        del self.report["metrics"]["configuration_coverage"]

        validate_security_report(self.report)

        summary = get_dashboard_summary(self.report)

        self.assertIsNone(summary["coverage_percentage"])

    def test_report_without_risk_prioritization(self):
        del self.report["risk_prioritization"]

        validate_security_report(self.report)

        self.assertEqual(
            get_prioritized_findings(self.report),
            [],
        )

        self.assertEqual(
            get_risk_distribution(self.report),
            {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        )

    def test_empty_findings(self):
        self.report["findings"] = []

        metrics = self.report["metrics"]
        metrics["total_findings"] = 0
        metrics["affected_assets"] = 0
        metrics["findings_by_severity"] = {}
        metrics["findings_by_rule"] = {}

        self.report["risk_prioritization"]["findings"] = []
        self.report["risk_prioritization"][
            "total_prioritized_findings"
        ] = 0

        validate_security_report(self.report)

        expected = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        self.assertEqual(
            get_severity_distribution(self.report),
            expected,
        )

        self.assertEqual(
            get_risk_distribution(self.report),
            expected,
        )

    def test_inconsistent_risk_score(self):
        self.report["risk_prioritization"][
            "findings"
        ][0]["risk_score"] = 70.0

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_inconsistent_risk_priority(self):
        self.report["risk_prioritization"][
            "findings"
        ][0]["risk_priority"] = "low"

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_prioritized_finding_identity_mismatch(self):
        self.report["risk_prioritization"][
            "findings"
        ][0]["asset_id"] = "UNKNOWN-ASSET"

        with self.assertRaises(ValueError):
            validate_security_report(self.report)

    def test_asset_risk_ranking(self):
        result = get_asset_risk_ranking(self.report)

        self.assertEqual(
            result,
            [
                {
                    "asset_id": "NET-RT-001",
                    "hostname": "BRANCH-RT-01",
                    "asset_criticality": "high",
                    "total_findings": 1,
                    "max_risk_score": 75.0,
                    "risk_priority": "high",
                }
            ],
        )

    def test_asset_risk_ranking_without_prioritization(self):
        del self.report["risk_prioritization"]

        self.assertEqual(
            get_asset_risk_ranking(self.report),
            [],
        )

    def test_asset_risk_ranking_multiple_findings(self):
        findings = self.report["risk_prioritization"][
            "findings"
        ]

        findings.append({
            **findings[0],
            "rule_id": "NET-003",
            "severity": "medium",
            "risk_score": 60.0,
            "risk_priority": "medium",
        })

        findings.append({
            **findings[0],
            "asset_id": "NET-SW-002",
            "hostname": "ACCESS-SW-01",
            "asset_criticality": "medium",
            "risk_score": 65.0,
            "risk_priority": "high",
        })

        result = get_asset_risk_ranking(self.report)

        self.assertEqual(len(result), 2)

        self.assertEqual(result[0]["asset_id"], "NET-RT-001")
        self.assertEqual(result[0]["total_findings"], 2)
        self.assertEqual(result[0]["max_risk_score"], 75.0)

        self.assertEqual(result[1]["asset_id"], "NET-SW-002")
        self.assertEqual(result[1]["total_findings"], 1)
        self.assertEqual(result[1]["max_risk_score"], 65.0)


if __name__ == "__main__":
    unittest.main()