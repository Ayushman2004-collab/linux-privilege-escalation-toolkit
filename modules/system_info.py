import os
import platform
import pwd
import grp

from .common import run_cmd


def collect_system_info():
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    uid = os.getuid()

    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = user

    groups = []
    try:
        gids = os.getgroups()
        for gid in gids:
            try:
                groups.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                groups.append(str(gid))
    except OSError:
        groups = []

    os_release = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    os_release[k] = v.strip('"')
    except OSError:
        pass

    uname = platform.uname()
    return {
        "username": username,
        "uid": uid,
        "is_root": uid == 0,
        "groups": groups,
        "hostname": platform.node(),
        "kernel": uname.release,
        "kernel_full": " ".join(uname),
        "architecture": platform.machine(),
        "os": os_release,
        "python": platform.python_version(),
    }
