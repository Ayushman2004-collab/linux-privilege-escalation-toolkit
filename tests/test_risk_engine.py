import unittest
from analyzer.risk_engine import analyze_findings


class RiskEngineTests(unittest.TestCase):
    def test_score_upgrades_severity(self):
        findings = [{
            "severity": "INFO",
            "score": 95,
            "title": "test",
            "category": "test"
        }]
        result = analyze_findings(findings)
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_sorting(self):
        findings = [
            {"severity": "INFO", "score": 10, "title": "low", "category": "x"},
            {"severity": "INFO", "score": 80, "title": "high", "category": "x"},
        ]
        result = analyze_findings(findings)
        self.assertEqual(result[0]["title"], "high")


if __name__ == "__main__":
    unittest.main()
