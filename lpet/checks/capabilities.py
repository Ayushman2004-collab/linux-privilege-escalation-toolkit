import subprocess
from ..core.models import Finding
from .common import has_command


def run(ctx, inventory):
    if not has_command("getcap"):
        return [Finding(
            id="LPE-CAP-001", title="getcap utility unavailable",
            category="Capabilities", severity="INFO", confidence="HIGH", score=0,
            summary="File capability enumeration was skipped.",
            evidence=["getcap was not found on PATH."],
            impact="Capability coverage is incomplete.",
            remediation="Install the package providing getcap if capability auditing is required.",
            tags=["capabilities"]
        )]

    try:
        p = subprocess.run(["getcap", "-r", "/"], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=max(ctx.command_timeout, 20), check=False)
    except subprocess.TimeoutExpired:
        return [Finding(
            id="LPE-CAP-002", title="Capability scan timed out",
            category="Capabilities", severity="INFO", confidence="HIGH", score=0,
            summary="Recursive capability enumeration exceeded its time limit.",
            evidence=["getcap -r / timed out."],
            impact="Capability findings may be incomplete.",
            remediation="Run a focused scan against relevant paths.",
            tags=["capabilities"]
        )]

    findings = []
    for i, line in enumerate(p.stdout.splitlines(), 1):
        if line.strip():
            findings.append(Finding(
                id=f"LPE-CAP-{i:03d}", title="File capability detected",
                category="Capabilities", severity="MEDIUM", confidence="MEDIUM", score=50,
                summary="A file has one or more Linux capabilities.",
                evidence=[line.strip()],
                impact="Capabilities can grant privileged operations without UID 0 and should be justified.",
                remediation="Remove unnecessary file capabilities and apply least privilege.",
                tags=["capabilities"]
            ))
    return findings
