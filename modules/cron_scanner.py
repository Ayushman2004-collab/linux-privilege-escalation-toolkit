import os
import glob
import stat

from .common import add_finding


def _inspect_file(path, findings):
    try:
        st = os.stat(path)
    except OSError:
        return
    mode = st.st_mode & 0o7777
    if stat.S_ISREG(st.st_mode) and (mode & stat.S_IWOTH):
        add_finding(
            findings, "Cron", "World-writable cron-related file",
            severity="HIGH", confidence="HIGH",
            evidence=f"path={path}; mode={oct(mode)}; uid={st.st_uid}",
            impact="A writable cron script/config used by a privileged job could allow unauthorized command changes.",
            mitigation="Make cron files root-owned and non-writable by unprivileged users; review every referenced script.",
            score=85, tags=["cron", "world-writable"]
        )


def scan_cron():
    findings = []
    paths = [
        "/etc/crontab",
        "/etc/anacrontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    for p in paths:
        if os.path.isfile(p):
            _inspect_file(p, findings)
        elif os.path.isdir(p):
            for f in glob.glob(os.path.join(p, "*")):
                _inspect_file(f, findings)

    try:
        user_cron = os.path.expanduser("~/.config/crontab")
        if os.path.exists(user_cron):
            _inspect_file(user_cron, findings)
    except Exception:
        pass

    # Read-only extraction of current user's crontab.
    import subprocess
    try:
        p = subprocess.run(["crontab", "-l"], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=5, check=False)
        if p.returncode == 0 and p.stdout.strip():
            add_finding(
                findings, "Cron", "Current user's crontab contains scheduled jobs",
                severity="INFO", confidence="HIGH",
                evidence=p.stdout[:4000],
                impact="Scheduled tasks should be reviewed for unsafe file paths and excessive privileges.",
                mitigation="Ensure scheduled commands use absolute paths and reference files not writable by unprivileged users.",
                score=10, tags=["cron", "review"]
            )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return findings
