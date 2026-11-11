# Network Security & Asset Visibility

**Python-based Network Security Engineering | Asset Inventory | Security Configuration Assessment | Configuration Coverage | Contextual Risk Prioritization | JSON Reporting**

A Security Engineering portfolio project demonstrating how structured network asset data supports infrastructure visibility, rule-based security assessment, configuration coverage measurement, contextual risk prioritization, and reproducible security reporting.

> **Project status:** Milestones 01–04 and GitHub Actions CI are integrated into `main`. Milestone 05 — Security Risk Prioritization — is implemented and validated locally on `feature/security-risk-prioritization`, pending commit, remote CI validation, and merge. The complete local test suite passes **54 tests**.

## 1. Project Overview

Network security starts with knowing which assets exist, their criticality, which security configurations have been documented, and which assets remain outside the assessment scope.

This project provides a modular, Python-based foundation for network asset inventory, declared configuration assessment, coverage analysis, contextual risk prioritization, and structured reporting. It processes synthetic CSV datasets, validates inventory and configuration records, produces security findings, calculates metrics, and exports JSON reports.

### Objectives

- Maintain a consistent, validated network asset inventory.
- Detect potentially insecure network management configurations.
- Associate findings with asset identity and criticality.
- Identify inventory assets lacking configuration records.
- Quantify configuration coverage and assessment visibility gaps.
- Produce reproducible metrics and machine-readable reports.
- Demonstrate automated testing and continuous integration practices.
- Prioritize findings using a transparent, deterministic contextual scoring model.
- Establish a foundation for dashboards and authorized network discovery.

## 2. Implemented Features

### Network Asset Inventory

- CSV-based asset ingestion.
- IPv4 address validation.
- Duplicate asset ID and IP address detection.
- Required-field and input validation.
- Asset criticality classification.
- Inventory statistics by vendor, device type, and criticality.

### Network Security Assessment

- Security configuration ingestion from CSV.
- Detection of SNMPv1 and SNMPv2c configurations.
- Detection of enabled Telnet management.
- Identification of devices with SSH management disabled.
- Identification of high- and critical-priority assets without monitoring.
- Structured findings with asset ID, hostname, rule ID, severity, and asset criticality.

### Security Metrics & JSON Reporting

- Total asset, affected asset, and finding counts.
- Finding distributions by severity and assessment rule.
- Validation of finding-to-asset references.
- Duplicate inventory asset ID detection during metric generation.
- Structured JSON export of metrics and findings.
- Explicit classification of exported data as synthetic laboratory data.

### Asset Configuration Coverage — Milestone 04

- Correlation of inventory and configuration records using `asset_id`.
- Detection of inventory assets without declared configuration records.
- Total configured and unconfigured asset counts.
- Configuration coverage percentage, rounded to two decimal places.
- Missing configuration counts grouped by asset criticality.
- Ordered details of assets missing configuration records.
- Rejection of duplicate or unknown configuration asset IDs.
- Optional integration into existing security metrics and JSON reporting functions.
- Backward compatibility when configuration records are not supplied to the reporting functions.

**Important:** Configuration coverage measures the availability of configuration records, not whether devices are securely configured or compliant.

### Security Risk Prioritization — Milestone 05

- Deterministic contextual risk scoring using finding severity (60%) and asset criticality (40%).
- Severity and criticality mapped to predefined values: critical = 100, high = 75, medium = 50, low = 25.
- Risk priority thresholds: critical >= 85, high >= 65, medium >= 40, otherwise low.
- Findings enriched with `risk_score` and `risk_priority` and ordered by descending score, with deterministic tie-breakers.
- Optional `risk_prioritization` section in JSON reports via `include_risk_prioritization=True`.
- Backward-compatible reporting when prioritization is disabled.

**Important:** Contextual risk scores are project-specific heuristics, not official CVSS scores or empirically validated exploitation probabilities.

### Automated Validation and CI

- **54 automated tests passing locally**, including 15 tests added during Milestone 05.
- Inventory, assessment, coverage, risk prioritization, and reporting validation.
- Edge cases covering duplicate records, invalid references, empty datasets, and JSON export.
- GitHub Actions workflow configured for Python 3.14 on Ubuntu.
- Successful GitHub Actions CI executions confirmed for the Milestone 04 merge on `main`. Milestone 05 has not yet been validated by remote CI.

## 3. Architecture

### Security Reporting Workflow

![Security Reporting Workflow](docs/images/reporting-flow.png)

The project processes data through these logical stages:

1. **Asset Inventory:** Load and validate inventory records.
2. **Security Configuration:** Load and validate declared management settings.
3. **Security Assessment:** Apply predefined rules and associate findings with known assets.
4. **Configuration Coverage:** Compare inventory assets with available configuration records and identify gaps.
5. **Metrics Aggregation:** Calculate asset, finding, and optional coverage indicators.
6. **Risk Prioritization (optional):** Score and order findings using severity and asset criticality.
7. **JSON Reporting:** Export structured metrics, findings, and optional risk prioritization for downstream analysis.

The existing workflow diagram illustrates the original reporting pipeline. Configuration coverage and optional risk prioritization extend this pipeline; the diagram has not yet been updated to show these additions.

The implementation runs locally, without a database, live network scanner, or external service.

## 4. Project Structure

![Project Structure](docs/images/project-structure.png)

The repository separates source modules, tests, technical documentation, and synthetic datasets.

Key files introduced or updated in Milestones 04–05:

| File | Purpose |
|---|---|
| `src/network_asset_visibility/coverage.py` | Configuration coverage calculation and validation |
| `src/network_asset_visibility/reporting.py` | Optional inclusion of coverage metrics in reports |
| `tests/test_coverage.py` | Coverage and reporting integration tests |
| `docs/CONFIGURATION_COVERAGE.md` | Technical coverage documentation |
| `src/network_asset_visibility/risk_prioritization.py` | Contextual risk scoring, classification, and ordering |
| `tests/test_risk_prioritization.py` | Risk scoring and JSON integration tests |
| `docs/RISK_PRIORITIZATION.md` | Scoring methodology, results, and limitations |

The existing project structure illustration predates Milestones 04–05 and will be updated in a subsequent documentation revision.

## 5. Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.14 | Application development and validated local runtime |
| Python Standard Library | CSV parsing, IPv4 validation, aggregation, and JSON serialization |
| `unittest` | Automated unit and integration-style tests |
| Git | Version control and feature-branch workflow |
| GitHub | Repository hosting and Pull Requests |
| GitHub Actions | Automated tests on supported repository events |
| PowerShell | Local development and execution |
| JSON | Machine-readable security reporting |

No third-party Python packages are required by the current implementation.

## 6. Getting Started

### Prerequisites

- Python 3.14 (the validated development version).
- Git.
- PowerShell for the commands below.

### Clone the Repository

```powershell
git clone https://github.com/andersonmartinscyber/network-security-asset-visibility.git
cd network-security-asset-visibility
```

> **Milestone 05 availability:** The default `main` branch includes Milestones 01–04. Milestone 05 is currently validated on the local `feature/security-risk-prioritization` branch and will become available remotely after it is pushed.

### Create and Activate a Virtual Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Configure the Python Module Path

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
```

## 7. Running Automated Tests

From the project root:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m unittest discover -s tests -v
```

### Latest Local Validation — Milestone 05 Feature Branch

```text
----------------------------------------------------------------------
Ran 54 tests in 0.053s

OK
```

| Test Module | Passing Tests |
|---|---:|
| `test_inventory.py` | 5 |
| `test_security_assessment.py` | 12 |
| `test_reporting.py` | 8 |
| `test_coverage.py` | 14 |
| `test_risk_prioritization.py` | 15 |
| **Total** | **54** |

The 54-test result was verified locally. Remote GitHub Actions validation for Milestone 05 is pending.

## 8. Running the Security Assessment

The project includes two synthetic datasets:

- `sample-data/assets.csv` — Network asset inventory.
- `sample-data/security_config.csv` — Declared security configurations.

Run the assessment from the project root:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path

@'
from network_asset_visibility.inventory import load_inventory
from network_asset_visibility.security_assessment import (
    load_security_config,
    assess_security,
)

assets = load_inventory("sample-data/assets.csv")
configs = load_security_config("sample-data/security_config.csv")
findings = assess_security(assets, configs)

for finding in findings:
    print(finding)

print(f"Total findings: {len(findings)}")
'@ | python -
```

The assessment evaluates declared configurations. No live network connections are performed.

## 9. Security Assessment Rules

| Rule ID | Security Check | Severity |
|---|---|---|
| NET-001 | SNMPv1 or SNMPv2c configured | High |
| NET-002 | Telnet management enabled | High |
| NET-003 | SSH management disabled | Medium |
| NET-004 | High/critical asset without monitoring | High |

Rule severities are predefined and do not represent CVSS calculations. Disabled SSH is a configuration review indicator, not proof that secure management access is unavailable.

See [Security Assessment Documentation](docs/SECURITY_ASSESSMENT.md) for details and limitations.

## 10. Asset Configuration Coverage

The coverage engine compares the validated inventory with declared configuration records using `asset_id`.

### Coverage Formula

**Configuration coverage (%) = (Configured assets / Total inventory assets) × 100**

The result is rounded to two decimal places. For an empty inventory, the implementation returns `0.0` as a reporting convention to avoid division by zero.

### Coverage Metrics

| Metric | Description |
|---|---|
| `total_assets` | Number of inventory assets |
| `configured_assets` | Assets with configuration records |
| `unconfigured_assets` | Assets without configuration records |
| `coverage_percentage` | Percentage of inventory assets with records |
| `missing_by_criticality` | Unconfigured asset counts by criticality |
| `missing_assets` | Details of uncovered assets in inventory order |

### Run Coverage Analysis

This command is supported on `main` (Milestone 04 and later).

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path

@'
from pprint import pprint
from network_asset_visibility.inventory import load_inventory
from network_asset_visibility.security_assessment import load_security_config
from network_asset_visibility.coverage import analyze_configuration_coverage

assets = load_inventory("sample-data/assets.csv")
configs = load_security_config("sample-data/security_config.csv")

pprint(analyze_configuration_coverage(assets, configs))
'@ | python -
```

### Validated Laboratory Result

```json
{
  "total_assets": 5,
  "configured_assets": 5,
  "unconfigured_assets": 0,
  "coverage_percentage": 100.0,
  "missing_by_criticality": {},
  "missing_assets": []
}
```

The current synthetic dataset has a configuration record for every inventory asset. Tests also exercise partial and zero coverage scenarios.

See [Asset Configuration Coverage Documentation](docs/CONFIGURATION_COVERAGE.md) for processing logic, test scenarios, and limitations. This document is included in the Milestone 04 implementation on `main`.

## 11. Generating Security Metrics & JSON Reports

The reporting module exports aggregated security metrics and individual findings. It can include configuration coverage metrics when `configs` is provided and, on the Milestone 05 feature branch, a prioritized findings section when `include_risk_prioritization=True`.

### Core Metrics

| Metric | Description |
|---|---|
| `total_assets` | Total inventory assets |
| `affected_assets` | Unique assets associated with findings |
| `total_findings` | Number of findings |
| `findings_by_severity` | Findings grouped by severity |
| `findings_by_rule` | Findings grouped by assessment rule |
| `configuration_coverage` | Optional coverage metrics when `configs` is provided |

### Generate a Report Including Coverage

This command is supported on `main` (Milestone 04 and later).

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path

@'
from pprint import pprint
from network_asset_visibility.inventory import load_inventory
from network_asset_visibility.security_assessment import (
    load_security_config,
    assess_security,
)
from network_asset_visibility.reporting import export_security_report

assets = load_inventory("sample-data/assets.csv")
configs = load_security_config("sample-data/security_config.csv")
findings = assess_security(assets, configs)

report = export_security_report(
    assets,
    findings,
    "security-report.json",
    configs=configs,
)

pprint(report["metrics"])
'@ | python -
```

The generated `security-report.json` file is excluded from Git version control through `.gitignore`.

### Example Aggregated Metrics

```json
{
  "total_assets": 5,
  "affected_assets": 2,
  "total_findings": 6,
  "findings_by_severity": {
    "high": 5,
    "medium": 1
  },
  "findings_by_rule": {
    "NET-001": 2,
    "NET-002": 2,
    "NET-003": 1,
    "NET-004": 1
  },
  "configuration_coverage": {
    "total_assets": 5,
    "configured_assets": 5,
    "unconfigured_assets": 0,
    "coverage_percentage": 100.0,
    "missing_by_criticality": {},
    "missing_assets": []
  }
}
```

The complete JSON report also includes project identification, `data_source: synthetic_lab`, and the individual findings.

Calls that omit `configs` retain the previous reporting structure without `configuration_coverage`. Calls that omit `include_risk_prioritization` retain the previous reporting structure without `risk_prioritization`.

See [Security Reporting Documentation](docs/SECURITY_REPORTING.md).

## 12. Security Risk Prioritization

Milestone 05 introduces optional, deterministic prioritization based on finding severity and asset criticality. The contextual risk score is calculated as:

**Risk Score = (Severity Weight × 0.60) + (Asset Criticality Weight × 0.40)**

| Classification | Weight |
|---|---:|
| Critical | 100 |
| High | 75 |
| Medium | 50 |
| Low | 25 |

Priority thresholds are **Critical >= 85**, **High >= 65**, **Medium >= 40**, and **Low < 40**. This score is not CVSS and is not a probability of exploitation.

### Generate a Prioritized JSON Report

Run this command on the Milestone 05 feature branch:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path

@'
from network_asset_visibility.inventory import load_inventory
from network_asset_visibility.security_assessment import (
    load_security_config,
    assess_security,
)
from network_asset_visibility.reporting import export_security_report

assets = load_inventory("sample-data/assets.csv")
configs = load_security_config("sample-data/security_config.csv")
findings = assess_security(assets, configs)

report = export_security_report(
    assets,
    findings,
    "security-report.json",
    configs=configs,
    include_risk_prioritization=True,
)

for finding in report["risk_prioritization"]["findings"]:
    print(
        finding["asset_id"],
        finding["rule_id"],
        finding["risk_score"],
        finding["risk_priority"],
    )
'@ | python -
```

The generated report includes `risk_prioritization.method`, scoring weights, the number of prioritized findings, and findings ordered by descending score. The original `findings` section remains available. The generated `security-report.json` is excluded by the repository's `.gitignore`.

See [Risk Prioritization Documentation](docs/RISK_PRIORITIZATION.md) for methodology, testing, and limitations.

## 13. Laboratory Validation Results

The current synthetic laboratory dataset contains five assets and five matching configuration records.

| Metric | Validated Result |
|---|---:|
| Total network assets | 5 |
| Assets with configuration records | 5 |
| Assets without configuration records | 0 |
| Configuration coverage | 100% |
| Assets with security findings | 2 |
| Total security findings | 6 |
| High-severity findings | 5 |
| Medium-severity findings | 1 |
| Automated tests (local) | 54 passed |
| Findings with contextual risk prioritization | 6 |
| High-priority findings | 5 |
| Medium-priority findings | 1 |

### Findings by Assessment Rule

| Rule ID | Findings |
|---|---:|
| NET-001 | 2 |
| NET-002 | 2 |
| NET-003 | 1 |
| NET-004 | 1 |
| **Total** | **6** |

**Interpretation:** A 100% configuration record coverage rate does not mean 100% security compliance. Two assets still produce security findings under the declared configuration assessment rules.

These results are generated from synthetic laboratory inputs and are not evidence of vulnerabilities in a production network.

## 14. Development Milestones

### Milestone 01 — Network Asset Inventory

**Completed and published**

- Initial project structure.
- CSV inventory ingestion.
- IPv4 and duplicate validation.
- Asset classification and inventory metrics.
- Five automated tests.
- Initial Git commit: `6f4a587`.

### Milestone 02 — Network Security Assessment

**Completed and integrated into `main`**

- Security configuration ingestion.
- Four rule-based security checks.
- Structured security findings.
- Expanded test suite: 17 passing tests.
- Technical documentation.
- Project structure illustration.
- Implementation commit: `14e9725`.

### Milestone 03 — Security Metrics & JSON Reporting

**Completed and integrated into `main`**

- Security metric aggregation.
- Unique affected asset counting.
- Finding distribution by severity and rule.
- JSON report generation.
- Eight additional automated tests.
- Expanded test suite: 25 passing tests.
- Technical reporting documentation and workflow diagram.
- Implementation commit: `2aade49`.

### CI Enhancement — GitHub Actions

**Completed and integrated into `main`**

- Automated Python 3.14 test workflow.
- Pull Request and `main` push triggers.
- Read-only repository permissions.
- Successful workflow executions observed for the CI introduction.
- Workflow commit: `7ef379d`.
- Pull Request #1 merge commit: `b6da59d`.

### Milestone 04 — Asset Configuration Coverage

**Completed and integrated into `main` via Pull Request #2 (`da600bc`)**

- Configuration coverage analysis engine.
- Missing configuration record identification.
- Coverage metrics by asset criticality.
- Duplicate and unknown asset reference validation.
- Optional JSON reporting integration.
- Backward-compatible reporting functions.
- Fourteen additional automated tests.
- Expanded local test suite: 39 passing tests.
- Technical documentation included.
- Implementation commit: `4b713d1`.
- Pull Request #2 merged with successful GitHub Actions validation.

### Milestone 05 — Security Risk Prioritization

**Implemented and validated locally; pending commit, remote CI validation, and merge**

- Weighted contextual scoring based on finding severity and asset criticality.
- Deterministic finding ranking and risk priority classification.
- Optional JSON report integration with backward compatibility.
- Fifteen additional automated tests.
- Expanded local test suite: 54 passing tests.
- Technical methodology and laboratory results documented.

## 15. Roadmap

- [x] Network asset inventory engine.
- [x] IPv4 and duplicate validation.
- [x] Asset classification and inventory metrics.
- [x] Rule-based security assessment engine.
- [x] Security metrics and JSON reporting.
- [x] GitHub Actions continuous integration for the published baseline.
- [x] Asset configuration coverage, CI validation, and merge into `main`.
- [ ] Updated architecture and project structure diagrams reflecting coverage and prioritization.
- [x] Contextual risk prioritization implementation and local tests.
- [ ] Milestone 05 remote CI validation and merge into `main`.
- [ ] Security dashboard and visualization.
- [ ] Configuration freshness analysis and historical coverage trends.
- [ ] Authorized SNMPv3 laboratory integration.
- [ ] Optional LibreNMS integration.

## 16. Known Limitations

- No live network discovery or scanning.
- No direct SNMP collection.
- Configuration data is supplied through CSV files.
- Declared configurations are not independently verified against devices.
- Configuration record presence does not prove security compliance.
- No configuration freshness or timestamp validation.
- No firmware vulnerability assessment.
- No device-specific security baseline evaluation.
- No persistent findings database or historical coverage tracking.
- No remediation tracking.
- No graphical dashboard in the current implementation.
- Contextual risk scoring is heuristic and does not incorporate exploitability, threat intelligence, network exposure, or compensating controls.
- JSON reports do not currently include schema version identifiers or execution timestamps.
- Reporting output is generated locally and is not automatically distributed.

## 17. Security and Ethical Considerations

This project is intended for educational use and authorized Security Engineering laboratories.

- All sample asset and configuration records are synthetic.
- Sample IPv4 addresses use documentation-reserved address space.
- No production credentials or sensitive infrastructure data are included.
- No network scanning or device configuration changes are performed.
- Assessment findings are based on declared data rather than independently verified device states.
- Generated reports are classified as synthetic laboratory output.
- Future network discovery capabilities will be restricted to explicitly authorized environments.

## 18. Future Development

Planned enhancements include authorized asset discovery, inventory enrichment, configuration freshness checks, configurable risk scoring, historical metrics, dashboards, automated reporting, and integration with network monitoring platforms.

The engineering objective is to demonstrate how network infrastructure information can support asset governance, security monitoring, assessment completeness, measurable security posture, and risk-informed decisions.

---

**Repository:** https://github.com/andersonmartinscyber/network-security-asset-visibility
**Current published baseline:** Milestones 01–04 and GitHub Actions CI
**Current feature-branch scope:** Milestone 05 — Security Risk Prioritization
**Latest local validation:** 54 passing tests
**Data classification:** Synthetic laboratory data
