import json
import tempfile
import unittest
from pathlib import Path

from network_asset_visibility.reporting import (
    export_security_report,
    generate_security_metrics,
)


class TestSecurityReporting(unittest.TestCase):

    def setUp(self):
        self.assets = [
            {"asset_id": "NET-001"},
            {"asset_id": "NET-002"},
        ]

        self.findings = [
            {
                "asset_id": "NET-001",
                "rule_id": "NET-001",
                "severity": "high",
            },
            {
                "asset_id": "NET-001",
                "rule_id": "NET-002",
                "severity": "high",
            },
            {
                "asset_id": "NET-002",
                "rule_id": "NET-003",
                "severity": "medium",
            },
        ]

    def test_generate_security_metrics(self):
        metrics = generate_security_metrics(
            self.assets,
            self.findings,
        )

        self.assertEqual(metrics["total_assets"], 2)
        self.assertEqual(metrics["affected_assets"], 2)
        self.assertEqual(metrics["total_findings"], 3)
        self.assertEqual(
            metrics["findings_by_severity"]["high"], 2
        )
        self.assertEqual(
            metrics["findings_by_rule"]["NET-001"], 1
        )

    def test_empty_findings(self):
        metrics = generate_security_metrics(
            self.assets,
            [],
        )

        self.assertEqual(metrics["total_findings"], 0)
        self.assertEqual(metrics["affected_assets"], 0)

    def test_unknown_asset(self):
        invalid_findings = [
            {
                "asset_id": "UNKNOWN",
                "rule_id": "NET-001",
                "severity": "high",
            }
        ]

        with self.assertRaises(ValueError):
            generate_security_metrics(
                self.assets,
                invalid_findings,
            )

    def test_duplicate_inventory_asset(self):
        assets = [
            {"asset_id": "NET-001"},
            {"asset_id": "NET-001"},
        ]

        with self.assertRaises(ValueError):
            generate_security_metrics(
                assets,
                [],
            )

    def test_export_security_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"

            report = export_security_report(
                self.assets,
                self.findings,
                output_path,
            )

            self.assertTrue(output_path.exists())
            self.assertEqual(
                report["metrics"]["total_findings"], 3
            )

            saved_report = json.loads(
                output_path.read_text(encoding="utf-8")
            )

            self.assertEqual(
                saved_report["metrics"]["affected_assets"], 2
            )

    def test_empty_inventory_and_findings(self):
        metrics = generate_security_metrics([], [])

        self.assertEqual(metrics["total_assets"], 0)
        self.assertEqual(metrics["affected_assets"], 0)
        self.assertEqual(metrics["total_findings"], 0)
        self.assertEqual(metrics["findings_by_severity"], {})
        self.assertEqual(metrics["findings_by_rule"], {})

    def test_multiple_findings_same_asset(self):
        findings = [
            {
                "asset_id": "NET-001",
                "rule_id": "NET-001",
                "severity": "high",
            },
            {
                "asset_id": "NET-001",
                "rule_id": "NET-002",
                "severity": "medium",
            },
        ]

        metrics = generate_security_metrics(
            self.assets,
            findings,
        )

        self.assertEqual(metrics["total_assets"], 2)
        self.assertEqual(metrics["affected_assets"], 1)
        self.assertEqual(metrics["total_findings"], 2)

    def test_exported_json_matches_returned_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"

            report = export_security_report(
                self.assets,
                self.findings,
                output_path,
            )

            saved_report = json.loads(
                output_path.read_text(encoding="utf-8")
            )

            self.assertEqual(saved_report, report)
            self.assertEqual(
                saved_report["data_source"],
                "synthetic_lab",
            )


if __name__ == "__main__":
    unittest.main()