import os
import stat

from .common import add_finding

SKIP = {"/proc", "/sys", "/dev", "/run", "/snap"}


def scan_suid_sgid():
    findings = []
    roots = ["/"]
    interesting = {
        "find", "awk", "nawk", "mawk", "perl", "python", "python3", "ruby",
        "vim", "vi", "nmap", "bash", "sh", "env", "cp", "mv", "tar", "zip",
        "rsync", "less", "more", "man", "tcpdump", "openssl"
    }

    for base in roots:
        for dirpath, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if os.path.join(dirpath, d) not in SKIP
                and not os.path.join(dirpath, d).startswith(tuple(SKIP))
            ]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue

                bits = st.st_mode & (stat.S_ISUID | stat.S_ISGID)
                if not bits:
                    continue

                suid = bool(bits & stat.S_ISUID)
                sgid = bool(bits & stat.S_ISGID)
                label = "SUID" if suid else "SGID"
                if suid and sgid:
                    label = "SUID+SGID"

                basename = os.path.basename(path)
                known = basename in interesting
                severity = "HIGH" if known else "MEDIUM"
                score = 80 if known else 45

                add_finding(
                    findings,
                    "SUID/SGID",
                    f"{label} binary discovered: {basename}",
                    severity=severity,
                    confidence="MEDIUM",
                    evidence=f"path={path}; mode={oct(st.st_mode & 0o7777)}",
                    impact=("A privileged SUID/SGID executable can increase attack surface. "
                            "Review whether the binary is required and whether its behavior "
                            "is appropriate for privileged execution."),
                    mitigation=("Remove unnecessary SUID/SGID bits, replace unsafe privileged "
                                "utilities, and restrict ownership/permissions. Validate "
                                "against trusted vendor guidance."),
                    score=score,
                    tags=["permissions", label.lower(), "review-with-gtfobins"],
                )
    return findings
