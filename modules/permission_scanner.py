import os
import stat

from .common import add_finding

SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]


def scan_permissions(fast=False):
    findings = []

    # Sensitive file checks
    for path in SENSITIVE:
        try:
            st = os.stat(path)
        except OSError:
            continue

        mode = st.st_mode & 0o7777
        world_write = bool(mode & stat.S_IWOTH)
        group_write = bool(mode & stat.S_IWGRP)

        if world_write or (path in {"/etc/shadow", "/etc/sudoers"} and group_write):
            add_finding(
                findings, "Permissions",
                f"Unsafe permissions on {path}",
                severity="CRITICAL" if path in {"/etc/shadow", "/etc/sudoers"} else "HIGH",
                confidence="HIGH",
                evidence=f"{path} mode={oct(mode)}",
                impact="Unauthorized modification of a security-sensitive file may alter authentication or privilege policy.",
                mitigation=f"Restore vendor-recommended ownership and restrictive permissions on {path}; investigate how the permissions changed.",
                score=95 if path in {"/etc/shadow", "/etc/sudoers"} else 75,
                tags=["sensitive-file", "write-permission"],
            )

    if fast:
        return findings

    # Broad scan for world-writable regular files outside pseudo filesystems.
    excluded = ("/proc", "/sys", "/dev", "/run")
    count = 0
    for dirpath, dirnames, filenames in os.walk("/"):
        if dirpath.startswith(excluded):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not os.path.join(dirpath, d).startswith(excluded)]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & stat.S_IWOTH:
                add_finding(
                    findings, "Permissions",
                    "World-writable regular file",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    evidence=f"path={path}; mode={oct(st.st_mode & 0o7777)}; uid={st.st_uid}; gid={st.st_gid}",
                    impact="A privileged process using a world-writable file could be exposed to unauthorized modification.",
                    mitigation="Restrict write permissions and verify that privileged processes do not consume user-controlled content.",
                    score=40,
                    tags=["world-writable"],
                )
                count += 1
                if count >= 200:
                    add_finding(
                        findings, "Permissions", "World-writable file results capped at 200",
                        severity="INFO", confidence="HIGH",
                        evidence="Result cap prevents excessively large reports.",
                        mitigation="Review the first results and run a focused audit for specific directories.",
                        score=0, tags=["limit"],
                    )
                    return findings
    return findings
