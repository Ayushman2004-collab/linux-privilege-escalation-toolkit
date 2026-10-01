import os
import shutil
import subprocess

from .common import add_finding


def scan_capabilities():
    findings = []
    if not shutil.which("getcap"):
        add_finding(
            findings, "Capabilities", "getcap utility not available",
            severity="INFO", confidence="HIGH",
            evidence="The getcap executable was not found.",
            impact="File capability enumeration was skipped.",
            mitigation="Install the distribution package providing getcap if capability auditing is required.",
            score=0, tags=["capabilities"]
        )
        return findings

    try:
        p = subprocess.run(
            ["getcap", "-r", "/"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False
        )
    except subprocess.TimeoutExpired:
        add_finding(
            findings, "Capabilities", "Capability scan timed out",
            severity="INFO", confidence="HIGH",
            evidence="getcap -r / exceeded the timeout.",
            impact="Capability enumeration may be incomplete.",
            mitigation="Run a focused scan against relevant filesystem paths.",
            score=0, tags=["capabilities"]
        )
        return findings

    for line in p.stdout.splitlines():
        if not line.strip():
            continue
        add_finding(
            findings, "Capabilities", "File capability detected",
            severity="MEDIUM", confidence="MEDIUM",
            evidence=line.strip(),
            impact="Linux capabilities can grant privileged operations without full root UID; each capability should have a documented need.",
            mitigation="Remove unnecessary file capabilities and apply least privilege.",
            score=50, tags=["capabilities"]
        )
    return findings
