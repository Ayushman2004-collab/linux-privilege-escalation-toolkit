import glob
import os
import re

from .common import add_finding, run_cmd


def _unit_files():
    paths = []
    for pattern in [
        "/etc/systemd/system/*.service",
        "/usr/lib/systemd/system/*.service",
        "/lib/systemd/system/*.service",
        "/run/systemd/system/*.service",
    ]:
        paths.extend(glob.glob(pattern))
    return sorted(set(paths))


def scan_services():
    findings = []
    for path in _unit_files():
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue

        exec_lines = []
        user_root = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("ExecStart=") or stripped.startswith("ExecStartPre=") or stripped.startswith("ExecStartPost="):
                exec_lines.append(stripped)
            if stripped.lower() == "user=root":
                user_root = True

        # If User= is absent, system services normally run as root unless another manager policy applies.
        root_context = user_root or not re.search(r"(?im)^User=", text)

        if not root_context:
            continue

        try:
            st = os.stat(path)
            writable = bool(st.st_mode & 0o002)
        except OSError:
            writable = False

        if writable:
            add_finding(
                findings, "Systemd",
                "Root-context service unit is writable by others",
                severity="CRITICAL", confidence="HIGH",
                evidence=f"unit={path}; mode={oct(st.st_mode & 0o7777)}",
                impact="Unauthorized edits to a privileged service definition can change what executes with elevated privileges.",
                mitigation="Make the unit root-owned and not writable by unprivileged users; reload systemd only after authorized changes.",
                score=98, tags=["systemd", "writable-unit"]
            )

        for line in exec_lines:
            command = line.split("=", 1)[1].strip()
            if not command.startswith("/"):
                add_finding(
                    findings, "Systemd",
                    "Service ExecStart does not use an absolute executable path",
                    severity="MEDIUM", confidence="MEDIUM",
                    evidence=f"unit={path}; {line}",
                    impact="Command resolution can depend on environment/search-path behavior and deserves review in privileged services.",
                    mitigation="Use trusted absolute executable paths and explicitly define a safe environment.",
                    score=45, tags=["systemd", "path"]
                )

            # Identify obvious user-home references for manual review.
            if "/home/" in command or "$HOME" in command:
                add_finding(
                    findings, "Systemd",
                    "Privileged service references a user-controlled home path",
                    severity="HIGH", confidence="MEDIUM",
                    evidence=f"unit={path}; {line}",
                    impact="A privileged service consuming user-controlled files can create a privilege boundary violation.",
                    mitigation="Move privileged resources to root-owned locations and enforce restrictive ownership/permissions.",
                    score=75, tags=["systemd", "user-controlled-path"]
                )

    # Optional active-state context, read-only.
    out, err, rc = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"], timeout=10)
    if rc == 0 and out:
        add_finding(
            findings, "Systemd", "Running systemd services enumerated",
            severity="INFO", confidence="HIGH",
            evidence=out[:6000],
            impact="Service inventory supports manual review of privileged workloads.",
            mitigation="Review privileged services for least privilege, trusted executable paths, and secure file ownership.",
            score=5, tags=["systemd", "inventory"]
        )
    return findings
