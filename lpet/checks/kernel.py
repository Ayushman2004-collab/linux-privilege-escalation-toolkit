import re
from ..core.models import Finding

# This is deliberately conservative. It is an age/branch indicator, not a CVE exploitability claim.
PATTERNS = [
    (r"^[0-4]\.", "Very old kernel branch"),
    (r"^5\.[0-3]\.", "Older 5.x kernel branch"),
]


def run(ctx, inventory):
    kernel = inventory["kernel"]
    for regex, label in PATTERNS:
        if re.search(regex, kernel):
            return [Finding(
                id="LPE-KERNEL-001", title=label,
                category="Kernel", severity="HIGH", confidence="LOW", score=70,
                summary="The kernel release appears old enough to justify vendor-advisory review.",
                evidence=[f"kernel={kernel}", f"offline-pattern={regex}"],
                impact="Kernel age can correlate with unpatched security issues, but version strings alone do not prove exploitability.",
                remediation="Compare the installed package build with official distribution security advisories and update to a supported kernel.",
                references=["https://nvd.nist.gov/"],
                tags=["kernel", "patching", "advisory-validation"]
            )]
    return [Finding(
        id="LPE-KERNEL-099", title="No conservative kernel-age pattern matched",
        category="Kernel", severity="INFO", confidence="LOW", score=0,
        summary="No local age indicator matched the kernel release.",
        evidence=[f"kernel={kernel}"],
        impact="This does not establish that the kernel is vulnerability-free.",
        remediation="Continue normal patch management and vendor advisory review.",
        references=["https://nvd.nist.gov/"],
        tags=["kernel"]
    )]
