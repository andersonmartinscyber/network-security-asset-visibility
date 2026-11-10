# Asset Configuration Coverage

## 1. Overview

The Asset Configuration Coverage module measures the availability of declared security configuration records for assets registered in the network inventory.

Its primary objective is to identify visibility gaps that may prevent network assets from being evaluated by the security assessment engine.

The module is implemented in `src/network_asset_visibility/coverage.py` and integrated with `src/network_asset_visibility/reporting.py`.

## 2. Objectives

- Identify inventory assets without associated security configuration records.
- Calculate configuration coverage percentages.
- Group missing configuration records by asset criticality.
- Validate relationships between inventory assets and configuration records.
- Export configuration coverage indicators through the existing JSON reporting engine.
- Preserve compatibility with previous reporting interfaces.

## 3. Processing Logic

The module receives two datasets:

- **Asset inventory:** Network assets with unique identifiers, hostnames, and criticality classifications.
- **Security configurations:** Declared management configurations associated with asset identifiers.

Both datasets are correlated using `asset_id`.

The processing sequence is:

1. Validate inventory asset identifiers and criticality.
2. Detect duplicate inventory asset identifiers.
3. Validate configuration asset identifiers.
4. Reject duplicate configuration records.
5. Reject configuration records referencing unknown assets.
6. Identify inventory assets without configuration records.
7. Aggregate missing configurations by criticality.
8. Calculate the configuration coverage percentage.
9. Return structured metrics suitable for JSON serialization.

## 4. Coverage Calculation

The configuration coverage percentage is calculated as:

**Coverage (%) = (Configured Assets / Total Inventory Assets) × 100**

The result is rounded to two decimal places.

For an empty inventory, the module returns `0.0` to avoid division by zero. This is a defined reporting convention, not a claim that an empty inventory represents a measured coverage failure.

## 5. Generated Metrics

| Metric | Description |
|---|---|
| `total_assets` | Number of inventory assets |
| `configured_assets` | Number of assets with configuration records |
| `unconfigured_assets` | Number of assets without configuration records |
| `coverage_percentage` | Percentage of assets with configuration records |
| `missing_by_criticality` | Missing configuration counts grouped by criticality |
| `missing_assets` | Asset identifiers, hostnames, and criticality of uncovered assets |

## 6. JSON Reporting Integration

Configuration coverage is included under:

`metrics.configuration_coverage`

The reporting functions accept an optional `configs` argument.

When configuration records are provided, coverage metrics are calculated and included in the report.

When the argument is omitted, the reporting functions preserve their previous behavior.

## 7. Laboratory Validation

The current synthetic laboratory dataset contains five inventory assets and five corresponding security configuration records.

| Metric | Result |
|---|---:|
| Total assets | 5 |
| Configured assets | 5 |
| Unconfigured assets | 0 |
| Configuration coverage | 100% |
| Existing security findings | 6 |

The implementation also includes automated test scenarios with partial and missing configuration coverage.

The complete project test suite currently contains **39 passing tests**, including 14 tests introduced during Milestone 04.

## 8. Validation Scenarios

The automated tests cover:

- Full configuration coverage.
- Partial configuration coverage.
- Zero configuration coverage.
- Empty inventories.
- Unknown configuration asset identifiers.
- Duplicate configuration records.
- Duplicate inventory asset identifiers.
- Missing configuration records for critical assets.
- Invalid criticality values.
- Deterministic ordering of uncovered assets.
- Coverage integration with security metrics.
- Backward compatibility with existing reporting calls.
- JSON report persistence.
- Validation failures before report file creation.

## 9. Security Interpretation

Configuration coverage measures the availability of declared configuration records.

It does **not** verify that configurations are secure, accurate, current, or compliant with security standards.

An asset may have a configuration record and still contain insecure management settings.

Likewise, an asset without a configuration record represents an assessment visibility gap, not automatically a confirmed vulnerability.

## 10. Known Limitations

- Configuration records originate from synthetic CSV datasets.
- No live network configuration collection is performed.
- No independent verification of device configuration accuracy.
- No configuration freshness or timestamp validation.
- No device-specific baseline compliance assessment.
- No persistent historical coverage tracking.
- No automatic remediation workflow.

## 11. Future Enhancements

Potential improvements include:

- Configuration freshness analysis.
- Historical coverage trends.
- Coverage indicators by device type, vendor, and network segment.
- Dashboard visualization.
- Contextual risk prioritization for uncovered critical assets.
- Authorized integration with network monitoring and configuration management platforms.

## 12. Conclusion

Asset Configuration Coverage extends the project from identifying insecure declared configurations to identifying inventory assets that cannot yet be assessed because their configuration records are unavailable.

This improves the project's ability to demonstrate network asset visibility, assessment completeness, and security reporting practices.
