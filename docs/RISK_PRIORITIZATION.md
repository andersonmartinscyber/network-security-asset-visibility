# Security Risk Prioritization

## Overview

The Security Risk Prioritization module provides deterministic, context-aware prioritization of network security findings.

It combines finding severity and asset criticality to support consistent remediation prioritization across network assets.

The implementation uses synthetic laboratory data and does not perform active network scanning.

## Risk Scoring Methodology

The contextual risk score uses the following weighted formula:

**Risk Score = (Finding Severity × 0.60) + (Asset Criticality × 0.40)**

### Scoring Weights

| Classification | Finding Severity Weight | Asset Criticality Weight |
|---|---:|---:|
| Critical | 100 | 100 |
| High | 75 | 75 |
| Medium | 50 | 50 |
| Low | 25 | 25 |

### Risk Priority Thresholds

| Score Range | Priority |
|---|---|
| 85–100 | Critical |
| 65–84.99 | High |
| 40–64.99 | Medium |
| Below 40 | Low |

These weights and thresholds are project-specific design choices. The resulting score is not an official CVSS score or an empirically validated exploitation probability.

## Implementation

The risk prioritization functionality is implemented in:

`src/network_asset_visibility/risk_prioritization.py`

The module provides three primary functions:

- `calculate_risk_score(severity, asset_criticality)` — calculates a contextual score between 0 and 100.
- `classify_risk_priority(score)` — assigns a priority classification.
- `prioritize_findings(findings)` — enriches findings with `risk_score` and `risk_priority` and sorts them by descending score.

For findings with equal scores, the implementation uses asset ID and rule ID as deterministic tie-breakers.

The original finding dictionaries are not modified.

## JSON Reporting Integration

The existing JSON reporting module supports optional risk prioritization.

Example:

```python
report = export_security_report(
    assets,
    findings,
    "security-report.json",
    configs=configs,
    include_risk_prioritization=True,
)
```

When enabled, the report contains a `risk_prioritization` section with the scoring methodology, weights, total prioritized findings, and ordered findings.

Risk prioritization is disabled by default to preserve backward compatibility with earlier milestones.

## Synthetic Laboratory Results

The laboratory contains five network assets and six security findings.

| Asset | Rule | Severity | Risk Score | Risk Priority |
|---|---|---|---:|---|
| NET-RT-001 | NET-001 | High | 75 | High |
| NET-RT-001 | NET-002 | High | 75 | High |
| NET-RT-001 | NET-004 | High | 75 | High |
| NET-SW-002 | NET-001 | High | 65 | High |
| NET-SW-002 | NET-002 | High | 65 | High |
| NET-RT-001 | NET-003 | Medium | 60 | Medium |

### Laboratory Metrics

| Metric | Value |
|---|---:|
| Total assets | 5 |
| Total findings | 6 |
| High-severity findings | 5 |
| Medium-severity findings | 1 |
| Configuration record coverage | 100% |
| Prioritized findings | 6 |

## Testing and Validation

The project includes unit and integration tests for:

- Weighted risk score calculations
- Priority thresholds
- Invalid input handling
- Deterministic finding ordering
- Preservation of original findings
- JSON export with optional risk prioritization
- Backward compatibility with previous reporting behavior

At the time of this milestone, the complete project test suite contains **54 passing tests**.

Run the tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Limitations

- The scoring weights and thresholds are predefined rather than empirically calibrated.
- The model does not incorporate threat intelligence, exploit availability, network exposure, or compensating controls.
- Results depend on the accuracy of finding severity and asset criticality.
- Configuration record coverage does not imply compliance with security standards.
- Laboratory findings are derived from synthetic configuration data.

## Future Enhancements

Potential improvements include configurable scoring weights, asset-level risk aggregation, historical risk trends, and integration with vulnerability intelligence sources.