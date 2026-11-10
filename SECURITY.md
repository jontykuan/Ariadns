# Security Policy

## Supported Versions

| Version | Supported          |
| :---    | :---               |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a potential security vulnerability within Ariadns, please do **NOT** open a public issue.

Instead, please send an encrypted or private vulnerability report to the repository maintainers:
- **Email**: `security@ariadns.local` (or reach out via GitHub Security Advisories)
- **Required Details**:
  - Description of the vulnerability and attack vector.
  - Proof of concept or reproduction steps.
  - Affected operating systems and network environments.

Maintainers will acknowledge receipt within 48 hours and work on a coordinated fix and CVE disclosure timeline.

## Operational Security (OPSEC) Advisory

Ariadns incorporates active probing safeguards (e.g. `trace` and `manual-oob`), which require explicit `--ack-risk` acknowledgement. Always ensure you possess explicit legal authorization from asset owners before initiating active network probing.
