# LPET — Linux Privilege Escalation Exposure Scanner

**Version 2.0.0 — professional-oriented, detection-only host security auditing toolkit**

LPET automates read-only enumeration of Linux privilege-boundary exposure. It is designed for
authorized security assessments, hardening reviews, vulnerability-management triage and SOC/engineering
workflows.

## What makes this version more professional?
- Stable finding IDs (`LPE-SUID-001`, `LPE-SYSTEMD-001`, etc.)
- Structured finding schema
- Confidence separate from severity
- Configurable scan roots
- Fast mode
- Timeouts and result caps
- JSON + professional HTML reporting
- CI-friendly exit code
- Modular checks
- Explicit security model
- Vendor-advisory validation language
- Unit/CLI tests
- Python packaging via `pyproject.toml`

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

No third-party runtime packages are required.

## Usage

```bash
lpet scan --fast
lpet scan
lpet scan --root /etc --root /opt
lpet scan --fast --json reports/server.json --html reports/server.html
```

Or without installation:

```bash
python3 -m lpet.cli scan --fast
```

## Exit status
`0` means no High/Critical findings. `2` means at least one High/Critical finding.

## Security boundary
LPET does not exploit findings, obtain root shells, modify the host, create persistence, or alter
cron/systemd configuration.

Use only on systems you own or are authorized to assess.

## Important interpretation
A finding is an exposure indicator, not proof of exploitability. Kernel/CVE applicability must be
validated against the exact distribution package build and official security advisory.
