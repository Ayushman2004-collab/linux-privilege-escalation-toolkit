from datetime import datetime, timezone
import platform
import os
import pwd
import grp
import uuid

from .models import ScanContext, Finding
from ..checks.suid import run as suid
from ..checks.permissions import run as permissions
from ..checks.sudo import run as sudo
from ..checks.cron import run as cron
from ..checks.systemd import run as systemd
from ..checks.capabilities import run as capabilities
from ..checks.kernel import run as kernel


CHECKS = [
    ("SUID/SGID", suid),
    ("Permissions", permissions),
    ("Sudo", sudo),
    ("Cron", cron),
    ("Systemd", systemd),
    ("Capabilities", capabilities),
    ("Kernel", kernel),
]


def system_inventory():
    uid = os.getuid()
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = os.environ.get("USER", "unknown")

    groups = []
    for gid in os.getgroups():
        try:
            groups.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            groups.append(str(gid))

    release = {}
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    release[k] = v.strip('"')
    except OSError:
        pass

    u = platform.uname()
    return {
        "hostname": platform.node(),
        "user": user,
        "uid": uid,
        "is_root": uid == 0,
        "groups": groups,
        "kernel": u.release,
        "architecture": u.machine,
        "os": release,
        "python": platform.python_version(),
    }


def scan(ctx: ScanContext):
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6].upper()
    started = datetime.now(timezone.utc).isoformat()

    inventory = system_inventory()
    findings = []
    errors = []

    for name, check in CHECKS:
        try:
            result = check(ctx, inventory)
            findings.extend(result)
        except Exception as exc:
            errors.append({"module": name, "error": str(exc)})

    # Normalize and cap.
    findings.sort(key=lambda x: (-x.score, x.id))
    findings = findings[:ctx.max_findings]

    summary = {s.lower(): sum(f.severity == s for f in findings)
               for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    return {
        "schema_version": "2.0",
        "tool": "LPET",
        "version": "2.0.0",
        "scan_id": scan_id,
        "started_utc": started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "detection-only",
        "context": {
            "fast": ctx.fast,
            "roots": ctx.roots,
            "max_findings": ctx.max_findings,
            "command_timeout": ctx.command_timeout,
        },
        "system": inventory,
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
    }
