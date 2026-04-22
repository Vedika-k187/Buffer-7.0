import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from analysis.entropy_detector import is_suspicious_entropy
from analysis.typosquatting_detector import check_typosquatting
from analysis.stego_detector import analyze_domain
from intelligence.threat_scorer import score_domain

class TestIntegration:

   def test_clean_domain_scores_low(self):
    result = score_domain("google.com")
    # google.com may get small ML anomaly score depending on training data
    # but should never be HIGH or CRITICAL
    assert result["final_score"] <= 25
    assert result["severity"] == "LOW"
    assert result["is_threat"] is False

    def test_typosquat_domain_detected_and_scored(self):
        typo = check_typosquatting("g00gle.com")
        score = score_domain("g00gle.com")
        assert typo["is_suspicious"] is True
        assert score["final_score"] >= 20

    def test_high_entropy_domain_scored(self):
        domain = "xk29dhs82kla9s2m.evil.com"
        entropy = is_suspicious_entropy(domain)
        score = score_domain(domain)
        assert entropy["is_suspicious"] is True
        assert score["final_score"] >= 25

    def test_score_result_has_all_fields(self):
        result = score_domain("test.com")
        required = [
            "domain", "final_score", "severity",
            "reasons", "is_threat",
            "entropy_contribution",
            "tunneling_contribution",
            "typo_contribution",
            "stego_contribution",
            "anomaly_contribution"
        ]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_score_never_exceeds_100(self):
        domains = [
            "xk29dhs82kla.evil.com",
            "g00gle.com",
            "google.com",
            "amazon.com"
        ]
        for d in domains:
            result = score_domain(d)
            assert result["final_score"] <= 100

    def test_severity_matches_score(self):
        result = score_domain("google.com")
        score = result["final_score"]
        severity = result["severity"]

        if score <= 25:
            assert severity == "LOW"
        elif score <= 50:
            assert severity == "MEDIUM"
        elif score <= 75:
            assert severity == "HIGH"
        else:
            assert severity == "CRITICAL"