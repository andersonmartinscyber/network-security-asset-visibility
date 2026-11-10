import csv
import ipaddress
from collections import Counter
from pathlib import Path


REQUIRED_COLUMNS = {
    "asset_id",
    "hostname",
    "ip_address",
    "vendor",
    "device_type",
    "criticality",
}

VALID_CRITICALITIES = {"low", "medium", "high", "critical"}


def load_inventory(file_path):
    """Load and validate a network asset inventory from CSV."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Inventory file not found: {path}")

    with path.open(
        mode="r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError("Inventory CSV is empty")

        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Duplicate CSV column names")

        missing_columns = REQUIRED_COLUMNS - set(reader.fieldnames)

        if missing_columns:
            raise ValueError(
                f"Missing required columns: {sorted(missing_columns)}"
            )

        assets = []
        seen_ids = set()
        seen_ips = set()

        for row_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Malformed CSV row {row_number}")

            asset = {
                column: row[column].strip()
                for column in REQUIRED_COLUMNS
            }

            if any(not value for value in asset.values()):
                raise ValueError(f"Empty field at row {row_number}")

            try:
                ip = ipaddress.ip_address(asset["ip_address"])
            except ValueError as error:
                raise ValueError(
                    f"Invalid IP address at row {row_number}"
                ) from error

            if ip.version != 4:
                raise ValueError(
                    f"Only IPv4 is supported at row {row_number}"
                )

            asset["ip_address"] = str(ip)
            asset["criticality"] = asset["criticality"].lower()

            if asset["criticality"] not in VALID_CRITICALITIES:
                raise ValueError(
                    f"Invalid criticality at row {row_number}"
                )

            if asset["asset_id"] in seen_ids:
                raise ValueError(
                    f"Duplicate asset ID at row {row_number}"
                )

            if asset["ip_address"] in seen_ips:
                raise ValueError(
                    f"Duplicate IP address at row {row_number}"
                )

            seen_ids.add(asset["asset_id"])
            seen_ips.add(asset["ip_address"])
            assets.append(asset)

    return assets


def summarize_inventory(assets):
    """Generate basic inventory metrics."""

    return {
        "total_assets": len(assets),
        "by_vendor": dict(
            Counter(asset["vendor"] for asset in assets)
        ),
        "by_device_type": dict(
            Counter(asset["device_type"] for asset in assets)
        ),
        "by_criticality": dict(
            Counter(asset["criticality"] for asset in assets)
        ),
    }