"""Unit tests for asset configuration coverage."""

import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from network_asset_visibility.reporting import (
    export_security_report,
    generate_security_metrics,
)

from network_asset_visibility.coverage import (
    analyze_configuration_coverage,
)


class TestConfigurationCoverage(unittest.TestCase):

    def setUp(self):
        self.assets = [
            {
                "asset_id": "NET-SW-001",
                "hostname": "CORE-SW-01",
                "criticality": "critical",
            },
            {
                "asset_id": "NET-SW-002",
                "hostname": "ACCESS-SW-01",
                "criticality": "medium",
            },
            {
                "asset_id": "NET-FW-001",
                "hostname": "EDGE-FW-01",
                "criticality": "critical",
            },
        ]

        self.configs = [
            {"asset_id": "NET-SW-001"},
            {"asset_id": "NET-SW-002"},
            {"asset_id": "NET-FW-001"},
        ]

    def test_full_coverage(self):
        result = analyze_configuration_coverage(
            self.assets, self.configs
        )

        self.assertEqual(result["total_assets"], 3)
        self.assertEqual(result["configured_assets"], 3)
        self.assertEqual(result["unconfigured_assets"], 0)
        self.assertEqual(result["coverage_percentage"], 100.0)
        self.assertEqual(result["missing_assets"], [])

    def test_partial_coverage(self):
        result = analyze_configuration_coverage(
            self.assets, self.configs[:2]
        )

        self.assertEqual(result["configured_assets"], 2)
        self.assertEqual(result["unconfigured_assets"], 1)
        self.assertEqual(result["coverage_percentage"], 66.67)

    def test_zero_coverage(self):
        result = analyze_configuration_coverage(
            self.assets, []
        )

        self.assertEqual(result["configured_assets"], 0)
        self.assertEqual(result["unconfigured_assets"], 3)
        self.assertEqual(result["coverage_percentage"], 0.0)

    def test_empty_inventory(self):
        result = analyze_configuration_coverage([], [])

        self.assertEqual(result["total_assets"], 0)
        self.assertEqual(result["coverage_percentage"], 0.0)

    def test_unknown_configuration_asset(self):
        with self.assertRaisesRegex(ValueError, "Unknown"):
            analyze_configuration_coverage(
                self.assets,
                [{"asset_id": "UNKNOWN-001"}],
            )

    def test_duplicate_configuration_asset(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            analyze_configuration_coverage(
                self.assets,
                [
                    {"asset_id": "NET-SW-001"},
                    {"asset_id": "NET-SW-001"},
                ],
            )

    def test_duplicate_inventory_asset(self):
        duplicate_assets = self.assets + [self.assets[0]]

        with self.assertRaisesRegex(ValueError, "Duplicate"):
            analyze_configuration_coverage(
                duplicate_assets, []
            )

    def test_missing_critical_assets(self):
        result = analyze_configuration_coverage(
            self.assets,
            [{"asset_id": "NET-SW-002"}],
        )

        self.assertEqual(
            result["missing_by_criticality"]["critical"], 2
        )
        self.assertEqual(result["unconfigured_assets"], 2)

    def test_invalid_criticality(self):
        invalid_assets = [
            {
                "asset_id": "NET-001",
                "hostname": "TEST-01",
                "criticality": "unknown",
            }
        ]

        with self.assertRaisesRegex(ValueError, "Invalid criticality"):
            analyze_configuration_coverage(invalid_assets, [])

    def test_missing_assets_preserve_inventory_order(self):
        result = analyze_configuration_coverage(
            self.assets,
            [{"asset_id": "NET-SW-002"}],
        )

        self.assertEqual(
            [asset["asset_id"] for asset in result["missing_assets"]],
            ["NET-SW-001", "NET-FW-001"],
        )

class TestCoverageReportingIntegration(unittest.TestCase):

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
        self.configs = [{"asset_id": "NET-001"}]

    def test_metrics_include_configuration_coverage(self):
        metrics = generate_security_metrics(
            self.assets,
            [],
            configs=self.configs,
        )

        coverage = metrics["configuration_coverage"]

        self.assertEqual(coverage["total_assets"], 2)
        self.assertEqual(coverage["configured_assets"], 1)
        self.assertEqual(coverage["unconfigured_assets"], 1)
        self.assertEqual(coverage["coverage_percentage"], 50.0)
        self.assertEqual(
            coverage["missing_assets"][0]["asset_id"],
            "NET-002",
        )

    def test_legacy_metrics_remain_compatible(self):
        metrics = generate_security_metrics(self.assets, [])

        self.assertNotIn("configuration_coverage", metrics)
        self.assertEqual(metrics["total_assets"], 2)

    def test_json_report_includes_configuration_coverage(self):
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "security-report.json"

            report = export_security_report(
                self.assets,
                [],
                output_path,
                configs=self.configs,
            )

            with output_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                saved_report = json.load(file)

            self.assertEqual(
                saved_report,
                report,
            )
            self.assertEqual(
                saved_report["metrics"]["configuration_coverage"][
                    "coverage_percentage"
                ],
                50.0,
            )

    def test_json_export_rejects_unknown_configuration_asset(self):
        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "security-report.json"

            with self.assertRaisesRegex(ValueError, "Unknown"):
                export_security_report(
                    self.assets,
                    [],
                    output_path,
                    configs=[{"asset_id": "UNKNOWN"}],
                )

            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()