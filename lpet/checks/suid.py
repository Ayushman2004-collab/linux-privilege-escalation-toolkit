import os
import stat
from ..core.models import Finding

INTERESTING = {"find", "awk", "perl", "python", "python3", "ruby", "vim", "nmap",
               "bash", "env", "cp", "tar", "rsync", "less", "tcpdump", "openssl"}


def run(ctx, inventory):
    findings = []
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
                if not stat.S_ISREG(st.st_mode):
                    continue
                bits = st.st_mode & (stat.S_ISUID | stat.S_ISGID)
                if not bits:
                    continue
                label = "SUID+SGID" if bits == (stat.S_ISUID|stat.S_ISGID) else ("SUID" if bits & stat.S_ISUID else "SGID")
                known = fn in INTERESTING
                findings.append(Finding(
                    id=f"LPE-SUID-{count+1:03d}",
                    title=f"{label} executable discovered: {fn}",
                    category="SUID/SGID",
                    severity="HIGH" if known else "MEDIUM",
                    confidence="MEDIUM",
                    score=80 if known else 45,
                    summary="Privileged permission bits increase the security impact of the executable.",
                    evidence=[f"path={path}", f"mode={oct(st.st_mode & 0o7777)}", f"uid={st.st_uid}", f"gid={st.st_gid}"],
                    impact="A privileged executable can expand the attack surface if its behavior or configuration is unsafe.",
                    remediation="Remove unnecessary SUID/SGID bits and verify ownership and vendor guidance. Manually validate whether the binary is actually exploitable.",
                    references=["https://gtfobins.github.io/"],
                    tags=["privileged-executable", "manual-validation"]
                ))
                count += 1
                if count >= ctx.max_findings:
                    return findings
    return findings
