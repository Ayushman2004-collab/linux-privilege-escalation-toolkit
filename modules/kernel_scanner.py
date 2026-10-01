import re
import platform

from .common import add_finding

# Conservative offline indicators. This module intentionally does not exploit or claim
# that a CVE is definitely exploitable. Exact applicability must be verified against
# the distro advisory and installed package build.
PATTERNS = [
    # (regex for kernel release, advisory label, note)
    (r"^([0-4])\.", "Very old kernel branch", "Kernel branch is historically old; patch/upgrade review is recommended."),
    (r"^5\.[0-3]\.", "Older 5.x kernel branch", "Older kernel branch; verify vendor security updates and supported lifecycle."),
]


def scan_kernel(system_info):
    findings = []
    kernel = system_info.get("kernel", platform.release())
    matched = False

    for regex, label, note in PATTERNS:
        if re.search(regex, kernel):
            matched = True
            add_finding(
                findings, "Kernel",
                label,
                severity="HIGH",
                confidence="LOW",
                evidence=f"kernel={kernel}; offline pattern={regex}",
                impact=note + " A kernel version alone is not enough to establish exploitability.",
                mitigation="Check the Linux distribution's official security advisories and update to the latest supported kernel/package build.",
                score=70, tags=["kernel", "patching", "advisory-review"]
            )

    if not matched:
        add_finding(
            findings, "Kernel", "No offline kernel age pattern matched",
            severity="INFO", confidence="LOW",
            evidence=f"kernel={kernel}",
            impact="This toolkit does not claim the kernel is vulnerability-free.",
            mitigation="Continue patch-management and compare the installed package build with official vendor advisories.",
            score=0, tags=["kernel"]
        )
    return findings
