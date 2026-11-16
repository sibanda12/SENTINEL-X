
# 🛡️ SENTINEL-X
### Security Monitoring & Threat Detection System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Security](https://img.shields.io/badge/Domain-Blue%20Team-red)
![Status](https://img.shields.io/badge/Status-Development-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

SENTINEL-X is a Python-based security monitoring and
threat detection tool designed to analyse Linux SSH
authentication logs and identify suspicious login activity.

The project demonstrates practical Blue Team operations,
security event analysis, threat detection engineering,
and incident reporting.

## Key Features

- SSH authentication log analysis.
- Failed login attempt monitoring.
- Brute-force activity detection.
- Successful login after repeated failures detection.
- Source IP address identification.
- Configurable detection thresholds.
- Security alert generation.
- JSON incident reporting.
- Automated unit testing.

## Detection Capabilities

| Detection | Severity |
|---|---|
| Repeated failed logins | HIGH |
| Successful login after repeated failures | CRITICAL |
| Normal authentication activity | No alert |

## MITRE ATT&CK Mapping

SENTINEL-X maps repeated authentication failures
to the following MITRE ATT&CK technique:

- T1110 – Brute Force

Reference:
https://attack.mitre.org/techniques/T1110/

## Technology Stack

- Python 3
- Regular Expressions
- JSON
- Argparse
- Collections
- Unittest

## Repository Structure

SENTINEL-X/

├── sentinel.py
├── tests.py
├── sample_logs/
│   └── auth.log
├── README.md
├── LICENSE
└── SECURITY.md

## Installation

Clone the repository:

    git clone https://github.com/YOUR-USERNAME/SENTINEL-X.git

Navigate into the project:

    cd SENTINEL-X

## Usage

Analyse an authentication log:

    python sentinel.py sample_logs/auth.log

Set a custom failed-login threshold:

    python sentinel.py sample_logs/auth.log --threshold 3

Generate a JSON report:

    python sentinel.py sample_logs/auth.log --output report.json

## Running Tests

    python -m unittest -v tests.py

## Sample Detection Output

Example:

    SECURITY ALERT: POSSIBLE BRUTE FORCE ATTACK
    Severity: HIGH
    Source IP: 203.0.113.25
    Failed Attempts: 5
    MITRE ATT&CK: T1110

## Security Considerations

- Uses synthetic logs for demonstration.
- Does not execute attacks or access external systems.
- Does not block IP addresses.
- Detection results require analyst verification.
- This prototype is not a replacement for enterprise SIEM software.

## Future Development

- Time-window-based detection.
- Expanded authentication event detection.
- IP reputation enrichment.
- Interactive SOC dashboard.
- Sigma detection rule integration.
- Advanced incident reporting.
- Additional MITRE ATT&CK mappings.

## Author
Eng.M.Sibanda Cybersecurity specialist SOC practitioner 
Cybersecurity Research & Development

## License

MIT License.
See LICENSE for details.

