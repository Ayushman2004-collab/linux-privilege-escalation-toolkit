import os
import re

from .common import add_finding, run_cmd


def scan_sudo():
    findings = []
    out, err, rc = run_cmd(["sudo", "-l"], timeout=8)

    if rc != 0:
        evidence = err or "sudo -l unavailable or denied"
        add_finding(
            findings, "Sudo", "Unable to enumerate sudo policy",
            severity="INFO", confidence="HIGH", evidence=evidence,
            impact="Sudo policy could not be fully assessed.",
            mitigation="Run the toolkit under an authorized account with permission to inspect sudo policy.",
            score=0, tags=["sudo"]
        )
        return findings

    lines = out.splitlines()
    for line in lines:
        if "NOPASSWD:" in line:
            add_finding(
                findings, "Sudo", "NOPASSWD sudo rule detected",
                severity="HIGH", confidence="HIGH", evidence=line.strip(),
                impact="Passwordless sudo access can significantly increase the impact of a misconfigured command.",
                mitigation="Review the command allowlist, remove unnecessary NOPASSWD rules, and restrict commands to the minimum required.",
                score=85, tags=["sudo", "nopasswd"]
            )
        elif re.search(r"\(ALL(?::ALL)?\)\s+ALL", line):
            add_finding(
                findings, "Sudo", "Broad sudo rule detected",
                severity="HIGH", confidence="HIGH", evidence=line.strip(),
                impact="Broad sudo rights can permit administrative actions beyond the user's intended role.",
                mitigation="Replace broad rules with narrowly scoped commands and use least privilege.",
                score=90, tags=["sudo", "broad-rule"]
            )
    return findings
