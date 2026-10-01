import glob
import os
import re
from ..core.models import Finding
from .common import run_cmd


def run(ctx, inventory):
    findings = []
    paths = set()
    for pattern in ("/etc/systemd/system/*.service", "/usr/lib/systemd/system/*.service",
                    "/lib/systemd/system/*.service", "/run/systemd/system/*.service"):
        paths.update(glob.glob(pattern))

    n = 1
    for path in sorted(paths):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
            st = os.stat(path)
        except OSError:
            continue

        root_context = bool(re.search(r"(?im)^User=root\s*$", text)) or not re.search(r"(?im)^User=", text)
        if not root_context:
            continue

        if st.st_mode & 0o002:
            findings.append(Finding(
                id=f"LPE-SYSTEMD-{n:03d}", title="Root-context service unit is writable by others",
                category="Systemd", severity="CRITICAL", confidence="HIGH", score=98,
                summary="A privileged service definition is writable by an unprivileged principal.",
                evidence=[f"unit={path}", f"mode={oct(st.st_mode & 0o7777)}"],
                impact="Unauthorized service-definition changes can alter privileged execution.",
                remediation="Ensure the unit is root-owned and not writable by unprivileged users.",
                tags=["systemd", "writable-unit"]
            ))
            n += 1

        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("ExecStart="):
                continue
            cmd = s.split("=", 1)[1].strip()
            if cmd and not cmd.startswith("/"):
                findings.append(Finding(
                    id=f"LPE-SYSTEMD-{n:03d}", title="Service ExecStart does not begin with an absolute path",
                    category="Systemd", severity="MEDIUM", confidence="MEDIUM", score=45,
                    summary="Privileged command resolution deserves review.",
                    evidence=[f"unit={path}", s],
                    impact="Unexpected path/environment behavior can weaken a privilege boundary.",
                    remediation="Use trusted absolute executable paths and an explicitly controlled environment.",
                    tags=["systemd", "path"]
                ))
                n += 1
            if "/home/" in cmd or "$HOME" in cmd:
                findings.append(Finding(
                    id=f"LPE-SYSTEMD-{n:03d}", title="Privileged service references a user-controlled home path",
                    category="Systemd", severity="HIGH", confidence="MEDIUM", score=75,
                    summary="A root-context service references a path commonly controlled by a non-root user.",
                    evidence=[f"unit={path}", s],
                    impact="A privileged service consuming user-controlled resources can cross a trust boundary.",
                    remediation="Move privileged resources to root-owned locations with restrictive permissions.",
                    tags=["systemd", "user-controlled-path"]
                ))
                n += 1

    out, err, rc = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"], ctx.command_timeout)
    if rc == 0 and out:
        findings.append(Finding(
            id="LPE-SYSTEMD-099", title="Running service inventory collected",
            category="Systemd", severity="INFO", confidence="HIGH", score=5,
            summary="Running services were enumerated for contextual review.",
            evidence=out[:6000].splitlines(),
            impact="Service inventory supports further least-privilege review.",
            remediation="Review privileged services for trusted paths, ownership, and least privilege.",
            tags=["systemd", "inventory"]
        ))
    return findings
