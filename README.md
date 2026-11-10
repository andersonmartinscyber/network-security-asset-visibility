# Network Security & Asset Visibility

A Python-based Security Engineering portfolio project focused on network asset inventory, visibility, and security assessment.

## Current Features

- CSV-based network asset inventory
- IPv4 address validation
- Duplicate asset detection
- Asset criticality classification
- Inventory metrics by vendor and device type
- Automated unit tests

## Technology Stack

- Python 3.14
- Python Standard Library
- unittest
- Git

## Project Status

Milestone 01 — Initial Asset Inventory Engine implemented and validated.

## Run Tests

From the project root, using PowerShell:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m unittest discover -s tests -v
```

## Sample Data

The repository uses synthetic network inventory data with documentation-only IP addresses.

No production network discovery or scanning is performed.

## Roadmap

- Asset Security Assessment Engine
- Security indicators and reporting
- SNMPv3 discovery in an authorized laboratory
- Optional LibreNMS integration