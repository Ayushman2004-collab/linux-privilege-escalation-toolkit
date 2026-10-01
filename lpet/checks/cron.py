import glob
import os
import stat
from ..core.models import Finding
from .common import run_cmd


def run(ctx, inventory):
    findings = []
    paths = ["/etc/crontab", "/etc/anacrontab", "/etc/cron.d",
             "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    n = 1
    for p in paths:
        targets = [p] if os.path.isfile(p) else glob.glob(os.path.join(p, "*")) if os.path.isdir(p) else []
        for path in targets:
            try:
                st = os.stat(path)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
                findings.append(Finding(
                    id=f"LPE-CRON-{n:03d}", title="World-writable cron-related file",
                    category="Cron", severity="HIGH", confidence="HIGH", score=85,
                    summary="A cron-related file is writable by other users.",
                    evidence=[f"path={path}", f"mode={oct(st.st_mode & 0o7777)}"],
                    impact="If a privileged scheduled job consumes the file, unauthorized modification may cross a privilege boundary.",
                    remediation="Make cron files root-owned and non-writable by unprivileged users; review referenced scripts.",
                    tags=["cron", "scheduled-task"]
                ))
                n += 1

    out, err, rc = run_cmd(["crontab", "-l"], ctx.command_timeout)
    if rc == 0 and out:
        findings.append(Finding(
            id="LPE-CRON-099", title="Current-user scheduled jobs discovered",
            category="Cron", severity="INFO", confidence="HIGH", score=5,
            summary="The current user's crontab contains scheduled tasks.",
            evidence=out[:4000].splitlines(),
            impact="Scheduled jobs should be reviewed for unsafe paths and excessive privileges.",
            remediation="Use absolute trusted paths and protect referenced files from unprivileged modification.",
            tags=["cron", "inventory"]
        ))
    return findings
