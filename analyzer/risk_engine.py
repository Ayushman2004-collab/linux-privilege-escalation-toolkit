SEVERITY_BY_SCORE = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (10, "LOW"),
    (0, "INFO"),
]


def analyze_findings(findings):
    for f in findings:
        score = int(f.get("score", 0))
        detected = next((s for threshold, s in SEVERITY_BY_SCORE if score >= threshold), "INFO")

        # Do not silently downgrade explicitly critical/high findings.
        current = f.get("severity", "INFO")
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(detected, 0) > order.get(current, 0):
            f["severity"] = detected

    findings.sort(
        key=lambda x: (-x.get("score", 0), x.get("category", ""), x.get("title", ""))
    )
    return findings
