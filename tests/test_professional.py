import json
import subprocess
import sys
from pathlib import Path

from lpet.core.models import ScanContext
from lpet.core.runner import system_inventory


def test_inventory_has_core_fields():
    data = system_inventory()
    assert "kernel" in data
    assert "uid" in data
    assert "hostname" in data


def test_cli_help():
    p = subprocess.run([sys.executable, "-m", "lpet.cli", "--help"],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert p.returncode == 0
    assert "detection-only" in p.stdout.lower()
