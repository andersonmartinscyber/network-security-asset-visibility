# Network Security & Asset Visibility

**Python-based Network Security Engineering | Asset Inventory | Security Configuration Assessment**

A Security Engineering portfolio project designed to demonstrate how structured network asset information can support infrastructure visibility, security configuration assessment, and risk-informed decision-making.

> **Project status:** Milestone 02 — Implementation and automated tests validated. Documentation and Git consolidation in progress.

## 1. Project Overview

Network infrastructure security depends on understanding which assets exist, their business criticality, and whether their management configurations follow appropriate security practices.

This project provides an extensible Python-based foundation for network asset inventory and rule-based security assessment.

The current implementation processes synthetic CSV datasets, validates asset information, evaluates declared security configurations, and generates structured findings.

**Key objectives:**

- Establish a consistent and validated network asset inventory.
- Identify potentially insecure network management configurations.
- Associate security findings with asset context and criticality.
- Support reproducible security assessments using automated tests.
- Prepare a foundation for security reporting, visualization, and authorized network discovery.

## 2. Current Features

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
- Structured findings containing asset ID, hostname, rule ID, severity, and asset criticality.

### Automated Validation

- 17 Python unit tests.
- Tests for invalid input and malformed CSV data.
- Tests for duplicate records.
- Tests for individual security assessment rules.
- Tests for secure configurations and unknown assets.

## 3. Architecture

The current processing workflow consists of four stages:

1. **Asset Inventory:** Load and validate the network asset dataset.
2. **Security Configuration:** Load and validate declared management settings.
3. **Assessment Engine:** Evaluate security rules and associate findings with known assets.
4. **Results:** Produce structured findings for analysis and future reporting.

The current implementation runs locally without a database, network scanner, or external service.

## 4. Project Structure

![Network Security and Asset Visibility — Project Structure](docs/images/project-structure.png)

*Project directory organization, including source modules, automated tests, documentation, and synthetic laboratory data.*

## 5. Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.14 | Core application development |
| Python Standard Library | CSV processing, IP validation, and data analysis |
| unittest | Automated testing |
| Git | Version control |
| PowerShell | Local development and test execution |

No third-party Python packages are required by the current implementation.

## 6. Getting Started

### Prerequisites

- Python 3.14 (validated development environment)
- Git
- PowerShell for the commands below

### Clone the Repository

After the GitHub repository has been published:

```powershell
git clone <REPOSITORY_URL>
cd network-security-asset-visibility
```

Alternatively, open an existing local project directory.

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
python -m unittest discover -s tests -v
```

**Latest validated execution:**

```text
Ran 17 tests

OK
```

All 17 tests passed in the latest local validation.

## 8. Running the Security Assessment

The project includes two synthetic datasets:

- `sample-data/assets.csv` — Network asset inventory.
- `sample-data/security_config.csv` — Declared security configurations.

Run the assessment using PowerShell:

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

The assessment evaluates the declared configurations and prints structured findings.

No live network connections are performed.

## 9. Security Assessment Rules

| Rule ID | Security Check | Severity |
|---|---|---|
| NET-001 | SNMPv1 or SNMPv2c configured | High |
| NET-002 | Telnet management enabled | High |
| NET-003 | SSH management disabled | Medium |
| NET-004 | High/critical asset without monitoring | High |

The rule severities are predefined and do not represent CVSS calculations.

SSH being disabled is treated as a configuration review indicator, not proof that a device lacks secure management access.

For rule descriptions, recommendations, and limitations, see [Security Assessment Documentation](docs/SECURITY_ASSESSMENT.md).

## 10. Laboratory Validation Results

The current synthetic laboratory dataset includes five network assets.

| Metric | Validated Result |
|---|---:|
| Total network assets | 5 |
| Assets with findings | 2 |
| Total security findings | 6 |
| High-severity findings | 5 |
| Medium-severity findings | 1 |
| Automated unit tests | 17 passed |

The findings demonstrate the behavior of the assessment engine using controlled laboratory inputs.

**These results are not evidence of vulnerabilities in a production network.**

## 11. Development Milestones

### Milestone 01 — Network Asset Inventory

**Completed**

- Initial project structure.
- CSV inventory ingestion.
- IPv4 and duplicate validation.
- Asset classification and inventory metrics.
- Five automated tests.
- Initial Git commit: `6f4a587`.

### Milestone 02 — Network Security Assessment

**Implementation and tests validated**

- Security configuration ingestion.
- Four rule-based security checks.
- Structured security findings.
- Expanded test suite: 17 passing tests.
- Technical documentation and Git consolidation in progress.

## 12. Roadmap

- [x] Network asset inventory engine
- [x] IPv4 and duplicate validation
- [x] Asset classification and inventory metrics
- [x] Rule-based security assessment engine
- [x] Automated unit tests for implemented functionality
- [ ] Security metrics and JSON reporting
- [ ] Asset configuration coverage analysis
- [ ] Contextual risk prioritization
- [ ] Security dashboard and visualization
- [ ] Authorized SNMPv3 laboratory integration
- [ ] Optional LibreNMS integration
- [ ] GitHub Actions continuous integration

## 13. Known Limitations

- No live network discovery or scanning.
- No direct SNMP collection.
- Configuration data is supplied through CSV files.
- Configuration accuracy is not independently verified against network devices.
- No firmware vulnerability assessment.
- No device-specific security baseline evaluation.
- No automatic verification that every inventory asset has a configuration record.
- No persistent findings database.
- No remediation tracking.
- No graphical dashboard in the current implementation.

## 14. Security and Ethical Considerations

This project is intended for educational use and authorized security engineering laboratories.

- All sample asset and configuration records are synthetic.
- Sample IPv4 addresses use documentation-reserved address space.
- No production credentials or sensitive infrastructure data are included.
- No network scanning or device configuration changes are performed.
- Assessment findings are based on declared data rather than independently verified device states.
- Future network discovery capabilities will be restricted to explicitly authorized environments.

## 15. Future Development

The project is intended to evolve into a broader network security visibility solution that integrates asset discovery, configuration assessment, contextual risk analysis, security metrics, and reporting.

The engineering objective is to demonstrate how network infrastructure information can support asset governance, security monitoring, and risk-informed decisions.