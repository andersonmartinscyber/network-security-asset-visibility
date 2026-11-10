# Network Security Assessment

## Overview

This module evaluates declared network device configurations
against a set of baseline security rules.

The assessment uses synthetic laboratory data and does not
connect to, scan, or modify network devices.

## Security Rules

| Rule ID | Condition | Severity | Recommendation |
|---|---|---|---|
| NET-001 | SNMPv1 or SNMPv2c configured | High | Prefer SNMPv3 with authentication and encryption |
| NET-002 | Telnet enabled | High | Disable Telnet and use encrypted management protocols |
| NET-003 | SSH disabled | Medium | Verify that an approved secure management method is available |
| NET-004 | High/critical asset without monitoring | High | Implement appropriate monitoring and alerting |

## Assessment Workflow

1. Load and validate the asset inventory.
2. Load and validate declared security configurations.
3. Match configurations to assets using asset_id.
4. Evaluate each applicable security rule.
5. Generate structured findings with asset context.

## Sample Results

The synthetic laboratory dataset contains five assets.

The current rules generate six findings:

- 5 High
- 1 Medium

These findings are illustrative and are not evidence
of vulnerabilities in a production environment.

## Limitations

- Configuration values are supplied through CSV files.
- No live network discovery is performed.
- Severity values are predefined and not CVSS scores.
- The module does not confirm exploitability.
- SSH being disabled does not necessarily mean that
  insecure administration is taking place.
- Device-specific exceptions and compensating controls
  are not yet modeled.
- The assessment does not currently verify that every
  inventory asset has a corresponding configuration record.

## Future Improvements

- Device-specific security baselines
- Asset configuration coverage indicators
- Risk prioritization based on asset criticality
- Structured JSON reporting
- Authorized SNMPv3 laboratory integration