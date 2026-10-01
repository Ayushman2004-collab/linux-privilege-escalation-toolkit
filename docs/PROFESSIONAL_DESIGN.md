# Professional LPET 2.0 Design

## Product positioning
LPET is a lightweight host-based Linux privilege-boundary exposure scanner intended for authorized
security assessments, hardening reviews, vulnerability-management workflows, and SOC/engineering
triage.

## Design principles
1. Detection only.
2. Least privilege.
3. Evidence first.
4. Deterministic identifiers.
5. Configurable scope.
6. Machine-readable output.
7. CI/SOC-friendly exit codes.
8. Human validation before remediation.

## Finding schema
Every finding includes:
- Finding ID
- Category
- Severity
- Confidence
- Score
- Summary
- Evidence
- Impact
- Remediation
- References
- Tags

## Severity is not exploitability
Severity describes potential security impact. Confidence describes how strongly the scanner's
evidence supports the finding. Exploitability requires contextual validation.

## Exit codes
- 0: no High/Critical findings
- 2: at least one High/Critical finding
- Other non-zero codes: operational/runtime errors may be added in future releases

## Roadmap
- Vendor advisory adapters
- SQLite scan history
- Baseline/diff mode
- SBOM/package inventory
- Signed report bundles
- Policy-as-code rules
- Centralized API/SIEM integration
- PDF report output
