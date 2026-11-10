"""Asset configuration coverage analysis."""

from collections import Counter

from network_asset_visibility.inventory import VALID_CRITICALITIES


def analyze_configuration_coverage(assets, configs):
    """Measure configuration record coverage across inventory assets.

    Coverage measures whether an asset has a declared configuration
    record. It does not indicate security compliance.
    """

    asset_map = {}

    for asset in assets:
        asset_id = asset["asset_id"]
        criticality = asset["criticality"]

        if not isinstance(asset_id, str) or not asset_id.strip():
            raise ValueError("Invalid inventory asset ID")

        if criticality not in VALID_CRITICALITIES:
            raise ValueError(
                f"Invalid criticality for asset: {asset_id}"
            )

        if asset_id in asset_map:
            raise ValueError(f"Duplicate inventory asset ID: {asset_id}")

        asset_map[asset_id] = asset

    config_ids = set()

    for config in configs:
        asset_id = config["asset_id"]

        if not isinstance(asset_id, str) or not asset_id.strip():
            raise ValueError("Invalid configuration asset ID")

        if asset_id in config_ids:
            raise ValueError(f"Duplicate configuration asset ID: {asset_id}")

        if asset_id not in asset_map:
            raise ValueError(f"Unknown configuration asset ID: {asset_id}")

        config_ids.add(asset_id)

    missing_ids = set(asset_map) - config_ids

    missing_assets = [
        {
            "asset_id": asset["asset_id"],
            "hostname": asset["hostname"],
            "criticality": asset["criticality"],
        }
        for asset in assets
        if asset["asset_id"] in missing_ids
    ]

    missing_by_criticality = Counter(
        asset["criticality"] for asset in missing_assets
    )

    total_assets = len(assets)
    configured_assets = len(config_ids)
    unconfigured_assets = len(missing_assets)

    coverage_percentage = (
        round((configured_assets / total_assets) * 100, 2)
        if total_assets
        else 0.0
    )

    return {
        "total_assets": total_assets,
        "configured_assets": configured_assets,
        "unconfigured_assets": unconfigured_assets,
        "coverage_percentage": coverage_percentage,
        "missing_by_criticality": dict(missing_by_criticality),
        "missing_assets": missing_assets,
    }