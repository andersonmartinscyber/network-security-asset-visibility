import csv
from pathlib import Path


REQUIRED_COLUMNS = {
    "asset_id",
    "snmp_version",
    "telnet_enabled",
    "ssh_enabled",
    "monitoring_enabled",
}

VALID_SNMP_VERSIONS = {"1", "2c", "3", "none"}
VALID_BOOLEANS = {"true": True, "false": False}


def load_security_config(file_path):
    """Load and validate declared network security configurations."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Security config file not found: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError("Security config CSV is empty")

        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Duplicate CSV column names")

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)

        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        configs = []
        seen_ids = set()

        for row_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Malformed CSV row {row_number}")

            config = {
                column: row[column].strip()
                for column in REQUIRED_COLUMNS
            }

            if any(not value for value in config.values()):
                raise ValueError(f"Empty field at row {row_number}")

            asset_id = config["asset_id"]

            if asset_id in seen_ids:
                raise ValueError(f"Duplicate asset ID at row {row_number}")

            seen_ids.add(asset_id)

            snmp_version = config["snmp_version"].lower()

            if snmp_version not in VALID_SNMP_VERSIONS:
                raise ValueError(f"Invalid SNMP version at row {row_number}")

            config["snmp_version"] = snmp_version

            for field in (
                "telnet_enabled",
                "ssh_enabled",
                "monitoring_enabled",
            ):
                value = config[field].lower()

                if value not in VALID_BOOLEANS:
                    raise ValueError(
                        f"Invalid boolean in {field} at row {row_number}"
                    )

                config[field] = VALID_BOOLEANS[value]

            configs.append(config)

    return configs


def assess_security(assets, configs):
    """Assess security risks using validated inventory and configuration data."""

    asset_map = {asset["asset_id"]: asset for asset in assets}
    findings = []

    for config in configs:
        asset_id = config["asset_id"]

        if asset_id not in asset_map:
            raise ValueError(f"Unknown asset ID: {asset_id}")

        asset = asset_map[asset_id]

        def add_finding(rule_id, title, severity):
            findings.append({
                "asset_id": asset_id,
                "hostname": asset["hostname"],
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "asset_criticality": asset["criticality"],
            })

        if config["snmp_version"] in {"1", "2c"}:
            add_finding(
                "NET-001",
                "Insecure SNMP version",
                "high",
            )

        if config["telnet_enabled"]:
            add_finding(
                "NET-002",
                "Telnet management enabled",
                "high",
            )

        if not config["ssh_enabled"]:
            add_finding(
                "NET-003",
                "SSH management disabled",
                "medium",
            )

        if (
            asset["criticality"] in {"high", "critical"}
            and not config["monitoring_enabled"]
        ):
            add_finding(
                "NET-004",
                "Critical asset without monitoring",
                "high",
            )

    return findings