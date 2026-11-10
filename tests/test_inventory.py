import tempfile
import unittest
from pathlib import Path

from network_asset_visibility.inventory import (
    load_inventory,
    summarize_inventory,
)


HEADER = (
    "asset_id,hostname,ip_address,"
    "vendor,device_type,criticality\n"
)


class TestInventory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.csv_path = Path(self.temp_dir.name) / "assets.csv"

    def write_csv(self, content):
        self.csv_path.write_text(content, encoding="utf-8")

    def test_load_valid_inventory(self):
        self.write_csv(
            HEADER
            + "NET-001,SW-01,192.0.2.10,Cisco,switch,critical\n"
        )

        assets = load_inventory(self.csv_path)

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["vendor"], "Cisco")

    def test_invalid_ip_address(self):
        self.write_csv(
            HEADER
            + "NET-001,SW-01,999.999.1.1,Cisco,switch,high\n"
        )

        with self.assertRaises(ValueError):
            load_inventory(self.csv_path)

    def test_duplicate_asset_id(self):
        self.write_csv(
            HEADER
            + "NET-001,SW-01,192.0.2.10,Cisco,switch,high\n"
            + "NET-001,SW-02,192.0.2.11,Cisco,switch,medium\n"
        )

        with self.assertRaises(ValueError):
            load_inventory(self.csv_path)

    def test_missing_required_columns(self):
        self.write_csv("asset_id,hostname\nNET-001,SW-01\n")

        with self.assertRaises(ValueError):
            load_inventory(self.csv_path)

    def test_inventory_summary(self):
        assets = [
            {
                "vendor": "Cisco",
                "device_type": "switch",
                "criticality": "critical",
            },
            {
                "vendor": "Cisco",
                "device_type": "switch",
                "criticality": "medium",
            },
        ]

        summary = summarize_inventory(assets)

        self.assertEqual(summary["total_assets"], 2)
        self.assertEqual(summary["by_vendor"]["Cisco"], 2)
        self.assertEqual(summary["by_device_type"]["switch"], 2)


if __name__ == "__main__":
    unittest.main()