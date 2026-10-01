# Linux Privilege Escalation Automation Toolkit — Project Report

## 1. Abstract
The Linux Privilege Escalation Automation Toolkit is a detection-only security auditing application
written in Python. It automates enumeration of common Linux privilege-boundary weaknesses such as
SUID/SGID files, unsafe permissions, sudo policy issues, cron configuration, systemd service
configuration, Linux file capabilities, and kernel-age indicators. The system aggregates evidence,
assigns a risk severity, and produces JSON and HTML reports.

## 2. Problem Statement
Manual privilege-escalation auditing requires many commands and careful interpretation. Missed
permissions, services, scheduled jobs, or capabilities can create unnecessary administrative risk.
The proposed toolkit standardizes read-only checks and presents findings in a consistent format.

## 3. Objectives
1. Automate Linux privilege-boundary enumeration.
2. Identify potentially unsafe permissions and privileged execution paths.
3. Correlate findings with simple local risk patterns.
4. Produce actionable mitigation guidance.
5. Keep the project detection-only.

## 4. Scope
### Included
- User, groups, UID, OS and kernel information
- SUID/SGID enumeration
- Sensitive-file permission checks
- World-writable regular-file discovery
- Sudo policy enumeration
- Cron enumeration
- Systemd unit inspection
- File capability enumeration
- Conservative kernel-age indicators
- Risk scoring and report generation

### Excluded
- Exploit execution
- Root-shell acquisition
- Persistence
- Credential theft
- Service/cron modification
- Destructive actions

## 5. System Architecture
```text
              +-----------------------+
              |      main.py / CLI    |
              +-----------+-----------+
                          |
             +------------v------------+
             | Enumeration Modules     |
             |-------------------------|
             | System | SUID | Perms   |
             | Sudo   | Cron | Systemd |
             | Caps   | Kernel          |
             +------------+------------+
                          |
                   +------v------+
                   | Risk Engine |
                   +------+------+
                          |
                +---------v----------+
                | Report Generator  |
                +----+----------+----+
                     |          |
                  JSON        HTML
```

## 6. Workflow
START → System Information → SUID/SGID → Permissions → Sudo → Cron →
Systemd → Capabilities → Kernel Indicators → Risk Analysis → Report → END

## 7. Module Details
### System Information
Collects UID, username, groups, hostname, OS release, architecture and kernel release.

### SUID/SGID
Walks the filesystem and identifies regular files with SUID/SGID permission bits.
Known high-interest executable names receive a higher review score. The toolkit does not execute them.

### Permissions
Checks sensitive files and optionally performs a broad world-writable scan. Results are capped to
avoid huge reports.

### Sudo
Uses `sudo -l` in read-only mode and flags broad or NOPASSWD rules for review.

### Cron
Inspects standard cron locations and the current user's crontab. Writable cron-related files are
highlighted.

### Systemd
Inspects service units, root-context execution, writable units, non-absolute ExecStart paths,
and references into user home directories.

### Capabilities
Uses `getcap` when available and reports file capabilities for review.

### Kernel
Records the kernel version and uses conservative offline age indicators. It does not assert
CVE exploitability. Administrators should validate against official vendor advisories.

## 8. Risk Model
| Score | Severity | Meaning |
|---:|---|---|
| 90–100 | Critical | Immediate privilege-boundary concern |
| 70–89 | High | Strong security concern requiring prompt review |
| 40–69 | Medium | Potential weakness requiring investigation |
| 10–39 | Low | Low-impact or contextual issue |
| 0–9 | Info | Inventory/contextual information |

Severity should always be validated manually. A finding is not proof that exploitation is possible.

## 9. Practical Testing Plan
Use an isolated virtual machine.

### Test 1 — System inventory
Run:
```bash
python3 main.py --fast
```
Expected: user, UID, kernel and OS information appear in the report.

### Test 2 — SUID discovery
Create or use an existing harmless lab binary with SUID only in an isolated VM. Do not use the
binary to obtain elevated access. Run the toolkit and confirm that the file is reported.

### Test 3 — World-writable file
Create a harmless world-writable text file inside the VM:
```bash
touch /tmp/privesc_lab.txt
chmod 666 /tmp/privesc_lab.txt
```
Run the scanner. It should report the file as world-writable. Remove it afterward:
```bash
rm -f /tmp/privesc_lab.txt
```

### Test 4 — Report generation
```bash
python3 main.py --fast \
  --json reports/output/test.json \
  --html reports/output/test.html
```

## 10. Sample Findings Table
| Finding | Severity | Evidence | Mitigation |
|---|---|---|---|
| SUID high-interest binary | High | Path + permission bits | Remove unnecessary SUID; verify vendor guidance |
| World-writable privileged resource | High | Path + mode | Restrict write permissions |
| NOPASSWD sudo rule | High | sudo policy line | Apply least privilege |
| Writable systemd unit | Critical | Unit path + mode | Root ownership, restrictive permissions |
| File capability | Medium | getcap output | Remove unnecessary capabilities |
| Old kernel branch | High/Low confidence | Kernel release | Patch using vendor advisory |

## 11. Limitations
- Version matching is not equivalent to CVE exploitability.
- Distribution backports can make a version appear old while security fixes are present.
- Some files/services may be inaccessible to an unprivileged scanner.
- Full filesystem scans can be slow.
- The tool is an auditing aid, not a replacement for professional configuration review.

## 12. Future Enhancements
- Vendor-specific advisory ingestion
- SQLite finding history
- PDF export
- Configurable scan roots
- Baseline/difference mode
- Centralized SOC reporting
- Unit-file dependency graph
- More precise privilege-boundary analysis

## 13. Conclusion
The toolkit demonstrates how security automation can turn repetitive Linux enumeration into a
repeatable audit workflow. Its detection-only design makes it suitable for an academic lab while
teaching both offensive-security enumeration concepts and defensive remediation.
