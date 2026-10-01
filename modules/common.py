import os
import shutil
import subprocess


def run_cmd(cmd, timeout=8):
    """Read-only command helper. Returns stdout, stderr, returncode."""
    try:
        p = subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False
        )
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError) as exc:
        return "", str(exc), 1


def which(name):
    return shutil.which(name)


def add_finding(findings, category, title, severity="INFO", confidence="MEDIUM",
                evidence="", impact="", mitigation="", score=0, tags=None):
    findings.append({
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "impact": impact,
        "mitigation": mitigation,
        "score": score,
        "tags": tags or [],
    })


def mode_string(path):
    try:
        return oct(os.stat(path).st_mode & 0o7777)
    except OSError:
        return "unavailable"
