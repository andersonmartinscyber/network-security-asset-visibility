import tempfile
import unittest
from pathlib import Path

from network_asset_visibility.security_assessment import (
    assess_security,
    load_security_config,
)


HEADER = (
    "asset_id,snmp_version,telnet_enabled,"
    "ssh_enabled,monitoring_enabled\n"
)


class TestSecurityAssessment(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.csv_path = Path(self.temp_dir.name) / "security.csv"

        self.assets = [
            {
                "asset_id": "NET-001",
                "hostname": "CORE-SW-01",
                "criticality": "critical",
            }
        ]

    def write_csv(self, content):
        self.csv_path.write_text(content, encoding="utf-8")

    def make_config(
        self,
        snmp_version="3",
        telnet_enabled=False,
        ssh_enabled=True,
        monitoring_enabled=True,
    ):
        return {
            "asset_id": "NET-001",
            "snmp_version": snmp_version,
            "telnet_enabled": telnet_enabled,
            "ssh_enabled": ssh_enabled,
            "monitoring_enabled": monitoring_enabled,
        }

    def test_valid_security_config(self):
        self.write_csv(
            HEADER + "NET-001,3,false,true,true\n"
        )

        configs = load_security_config(self.csv_path)

        self.assertEqual(len(configs), 1)
        self.assertFalse(configs[0]["telnet_enabled"])
        self.assertTrue(configs[0]["ssh_enabled"])

    def test_invalid_snmp_version(self):
        self.write_csv(
            HEADER + "NET-001,invalid,false,true,true\n"
        )

        with self.assertRaises(ValueError):
            load_security_config(self.csv_path)

    def test_invalid_boolean(self):
        self.write_csv(
            HEADER + "NET-001,3,maybe,true,true\n"
        )

        with self.assertRaises(ValueError):
            load_security_config(self.csv_path)

    def test_missing_columns(self):
        self.write_csv("asset_id,snmp_version\nNET-001,3\n")

        with self.assertRaises(ValueError):
            load_security_config(self.csv_path)

    def test_duplicate_asset_id(self):
        self.write_csv(
            HEADER
            + "NET-001,3,false,true,true\n"
            + "NET-001,3,false,true,true\n"
        )

        with self.assertRaises(ValueError):
            load_security_config(self.csv_path)

    def test_insecure_snmp(self):
        findings = assess_security(
            self.assets,
            [self.make_config(snmp_version="2c")],
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "NET-001")

    def test_telnet_enabled(self):
        findings = assess_security(
            self.assets,
            [self.make_config(telnet_enabled=True)],
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "NET-002")

    def test_ssh_disabled(self):
        findings = assess_security(
            self.assets,
            [self.make_config(ssh_enabled=False)],
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "NET-003")

    def test_critical_asset_without_monitoring(self):
        findings = assess_security(
            self.assets,
            [self.make_config(monitoring_enabled=False)],
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "NET-004")

    def test_secure_configuration(self):
        findings = assess_security(
            self.assets,
            [self.make_config()],
        )

        self.assertEqual(findings, [])

    def test_unknown_asset_id(self):
        config = self.make_config()
        config["asset_id"] = "UNKNOWN"

        with self.assertRaises(ValueError):
            assess_security(self.assets, [config])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_security_config(
                Path(self.temp_dir.name) / "missing.csv"
            )


if __name__ == "__main__":
    unittest.main()