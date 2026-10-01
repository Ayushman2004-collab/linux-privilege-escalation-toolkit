import re
from ..core.models import Finding
from .common import run_cmd


def run(ctx, inventory):
    findings = []
    out, err, rc = run_cmd(["sudo", "-l"], ctx.command_timeout)
    if rc != 0:
        return [Finding(
            id="LPE-SUDO-001", title="Sudo policy could not be enumerated",
            category="Sudo", severity="INFO", confidence="HIGH", score=0,
            summary="Read-only sudo policy enumeration was unavailable.",
            evidence=[err or "sudo -l returned a non-zero status."],
            impact="Sudo configuration could not be fully assessed.",
            remediation="Run an authorized scan where sudo policy inspection is permitted.",
            tags=["sudo"]
        )]

    for line in out.splitlines():
        if "NOPASSWD:" in line:
            findings.append(Finding(
                id="LPE-SUDO-002", title="NOPASSWD sudo rule detected",
                category="Sudo", severity="HIGH", confidence="HIGH", score=85,
                summary="A command is permitted through sudo without password authentication.",
                evidence=[line.strip()],
                impact="A mis-scoped passwordless command can materially increase privilege-boundary risk.",
                remediation="Restrict the command list to least privilege and remove unnecessary NOPASSWD rules.",
                tags=["sudo", "nopasswd"]
            ))
        elif re.search(r"\(ALL(?::ALL)?\)\s+ALL", line):
            findings.append(Finding(
                id="LPE-SUDO-003", title="Broad sudo rule detected",
                category="Sudo", severity="HIGH", confidence="HIGH", score=90,
                summary="The current user appears to have broad sudo authorization.",
                evidence=[line.strip()],
                impact="Broad administrative rights increase the impact of account compromise.",
                remediation="Replace broad authorization with narrowly scoped commands and roles.",
                tags=["sudo", "least-privilege"]
            ))
    return findings
