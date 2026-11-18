"""Automated UI tests for the security dashboard."""

import json
import tempfile
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest

from network_asset_visibility.risk_prioritization import (
    prioritize_findings,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = PROJECT_ROOT / "dashboard.py"


class TestDashboardApp(unittest.TestCase):
    """Validate the Streamlit dashboard behavior."""

    def setUp(self):
        """Prepare an isolated dashboard and synthetic report."""

        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)

        self.temp_path = Path(self.temp_directory.name)
        self.report_path = self.temp_path / "security-report.json"

        findings = [
            {
                "asset_id": "NET-RT-001",
                "hostname": "BRANCH-RT-01",
                "rule_id": "NET-001",
                "title": "Insecure SNMP version",
                "severity": "high",
                "asset_criticality": "high",
            },
            {
                "asset_id": "NET-RT-001",
                "hostname": "BRANCH-RT-01",
                "rule_id": "NET-003",
                "title": "SSH management disabled",
                "severity": "medium",
                "asset_criticality": "high",
            },
            {
                "asset_id": "NET-SW-002",
                "hostname": "ACCESS-SW-01",
                "rule_id": "NET-002",
                "title": "Telnet management enabled",
                "severity": "high",
                "asset_criticality": "medium",
            },
        ]

        self.report = {
            "project": "Network Security & Asset Visibility",
            "data_source": "synthetic_lab",
            "metrics": {
                "total_assets": 3,
                "affected_assets": 2,
                "total_findings": 3,
                "findings_by_severity": {
                    "high": 2,
                    "medium": 1,
                },
                "findings_by_rule": {
                    "NET-001": 1,
                    "NET-002": 1,
                    "NET-003": 1,
                },
                "configuration_coverage": {
                    "total_assets": 3,
                    "configured_assets": 3,
                    "unconfigured_assets": 0,
                    "coverage_percentage": 100.0,
                    "missing_by_criticality": {},
                    "missing_assets": [],
                },
            },
            "findings": findings,
            "risk_prioritization": {
                "method": "contextual_weighted_score",
                "severity_weight": 0.60,
                "asset_criticality_weight": 0.40,
                "total_prioritized_findings": len(findings),
                "findings": prioritize_findings(findings),
            },
        }

        self.write_report()

        # Copy the dashboard into an isolated test directory.
        self.app_path = self.temp_path / "dashboard.py"

        self.app_path.write_text(
            DASHBOARD_PATH.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        # Preserve the dashboard's visual assets.
        source_icon = (
            PROJECT_ROOT / "assets" / "security-icon.png"
        )

        if source_icon.exists():
            target_assets = self.temp_path / "assets"
            target_assets.mkdir(exist_ok=True)

            target_icon = target_assets / source_icon.name
            target_icon.write_bytes(source_icon.read_bytes())

    def write_report(self):
        """Write the synthetic report to the test directory."""

        self.report_path.write_text(
            json.dumps(self.report),
            encoding="utf-8",
        )

    def start_app(self):
        """Initialize the dashboard test instance."""

        app = AppTest.from_file(
            str(self.app_path),
            default_timeout=30,
        )

        app.run()

        self.assertEqual(
            len(app.exception),
            0,
            msg=str(app.exception),
        )

        return app

    def get_filter(self, app, label):
        """Return a multiselect widget by its label."""

        for widget in app.multiselect:
            if widget.label == label:
                return widget

        self.fail(f"Filter not found: {label}")

    def get_metrics(self, app):
        """Return dashboard metrics indexed by label."""

        return {
            metric.label: metric.value
            for metric in app.metric
        }

    def assert_finding_count(self, app, expected):
        """Validate the number of displayed findings."""

        self.assertEqual(len(app.exception), 0)

        expected_caption = (
            f"Displaying {expected} of 3 findings."
        )

        captions = [
            element.value
            for element in app.caption
        ]

        self.assertIn(expected_caption, captions)

        self.assertEqual(
            len(app.dataframe[-1].value),
            expected,
        )

    def test_application_startup(self):
        app = self.start_app()

        self.assertEqual(len(app.exception), 0)

    def test_dashboard_title(self):
        app = self.start_app()

        titles = [
            element.value
            for element in app.title
        ]

        self.assertIn(
            "Network Security Dashboard",
            titles,
        )

    def test_security_metrics(self):
        app = self.start_app()

        metrics = self.get_metrics(app)

        self.assertEqual(metrics["Total Assets"], "3")
        self.assertEqual(metrics["Affected Assets"], "2")
        self.assertEqual(metrics["Security Findings"], "3")

        self.assertEqual(
            metrics["Configuration Coverage"],
            "100.0%",
        )

    def test_severity_filter(self):
        app = self.start_app()

        self.get_filter(
            app, "Severity"
        ).set_value(["high"]).run()

        self.assert_finding_count(app, 2)

    def test_asset_filter(self):
        app = self.start_app()

        self.get_filter(
            app, "Asset"
        ).set_value(["NET-SW-002"]).run()

        self.assert_finding_count(app, 1)

    def test_risk_priority_filter(self):
        app = self.start_app()

        self.get_filter(
            app, "Risk Priority"
        ).set_value(["medium"]).run()

        self.assert_finding_count(app, 1)

    def test_combined_filters(self):
        app = self.start_app()

        self.get_filter(
            app, "Severity"
        ).set_value(["high"])

        self.get_filter(
            app, "Asset"
        ).set_value(["NET-RT-001"])

        app.run()

        self.assert_finding_count(app, 1)

    def test_empty_filter_results(self):
        app = self.start_app()

        self.get_filter(
            app, "Severity"
        ).set_value(["critical"]).run()

        self.assert_finding_count(app, 0)

    def test_global_metrics_remain_unchanged(self):
        app = self.start_app()

        original_metrics = self.get_metrics(app)

        self.get_filter(
            app, "Severity"
        ).set_value(["medium"]).run()

        self.assertEqual(
            self.get_metrics(app),
            original_metrics,
        )

        self.assert_finding_count(app, 1)

    def test_missing_report(self):
        self.report_path.unlink()

        app = self.start_app()

        self.assertTrue(
            any(
                "Security report not found" in error.value
                for error in app.error
            )
        )

    def test_missing_risk_prioritization(self):
        del self.report["risk_prioritization"]
        self.write_report()

        app = self.start_app()

        messages = [
            element.value
            for element in app.info
        ]

        self.assertIn(
            "Risk prioritization is unavailable.",
            messages,
        )

        self.assert_finding_count(app, 3)

    def test_missing_configuration_coverage(self):
        del self.report["metrics"]["configuration_coverage"]
        self.write_report()

        app = self.start_app()

        metrics = self.get_metrics(app)

        self.assertEqual(
            metrics["Configuration Coverage"],
            "N/A",
        )


if __name__ == "__main__":
    unittest.main()