import shutil
import subprocess


def run_cmd(cmd, timeout=10):
    try:
        p = subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False
        )
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired) as exc:
        return "", str(exc), 1


def has_command(name):
    return shutil.which(name) is not None
