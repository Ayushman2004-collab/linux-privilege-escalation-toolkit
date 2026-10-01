import os
import stat
from ..core.models import Finding

SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]


def run(ctx, inventory):
    findings = []
    n = 0

    for path in SENSITIVE:
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = st.st_mode & 0o7777
        unsafe = bool(mode & stat.S_IWOTH) or (
            path in ("/etc/shadow", "/etc/sudoers") and bool(mode & stat.S_IWGRP)
        )
        if unsafe:
            findings.append(Finding(
                id=f"LPE-PERM-{n+1:03d}",
                title=f"Unsafe permissions on {path}",
                category="Permissions",
                severity="CRITICAL" if path in ("/etc/shadow", "/etc/sudoers") else "HIGH",
                confidence="HIGH",
                score=95 if path in ("/etc/shadow", "/etc/sudoers") else 75,
                summary="Security-sensitive file is writable beyond its intended trust boundary.",
                evidence=[f"path={path}", f"mode={oct(mode)}", f"uid={st.st_uid}", f"gid={st.st_gid}"],
                impact="Unauthorized changes may alter authentication or privilege policy.",
                remediation="Restore vendor-recommended ownership and restrictive permissions; investigate the source of the change.",
                tags=["sensitive-file", "permissions"]
            ))
            n += 1

    if ctx.fast:
        return findings

    count = 0
    for base in ctx.roots:
        for dp, dns, fns in os.walk(base, topdown=True, followlinks=False):
            dns[:] = [d for d in dns if not os.path.join(dp, d).startswith(("/proc","/sys","/dev","/run"))]
            for fn in fns:
                path = os.path.join(dp, fn)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
                    findings.append(Finding(
                        id=f"LPE-PERM-{n+1:03d}",
                        title="World-writable regular file",
                        category="Permissions",
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        score=40,
                        summary="Any local user may be able to modify this regular file.",
                        evidence=[f"path={path}", f"mode={oct(st.st_mode & 0o7777)}"],
                        impact="Risk depends on whether a privileged process consumes the file.",
                        remediation="Restrict write access and verify privileged consumers.",
                        tags=["world-writable"]
                    ))
                    n += 1
                    count += 1
                    if count >= 200 or n >= ctx.max_findings:
                        return findings
    return findings
