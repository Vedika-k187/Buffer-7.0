import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from analysis.entropy_detector import calculate_entropy, is_suspicious_entropy

class TestEntropyCalculation:

    def test_known_low_entropy(self):
        score = calculate_entropy("google.com")
        assert score < 3.5, f"google.com should be low entropy, got {score}"

    def test_known_high_entropy(self):
        score = calculate_entropy("xk29dhs82kla9s.evil.com")
        assert score > 3.5, f"Random domain should be high entropy, got {score}"

    def test_empty_domain_does_not_crash(self):
        score = calculate_entropy("")
        assert score == 0.0

    def test_single_char_domain(self):
        score = calculate_entropy("a.com")
        assert score >= 0.0

    def test_entropy_returns_float(self):
        score = calculate_entropy("test.com")
        assert isinstance(score, float)

    def test_entropy_always_positive(self):
        domains = ["google.com", "abc.net", "x9k2.org"]
        for d in domains:
            assert calculate_entropy(d) >= 0

class TestSuspiciousEntropy:

    def test_clean_domain_not_flagged(self):
        result = is_suspicious_entropy("google.com")
        assert result["is_suspicious"] is False

    def test_random_domain_flagged(self):
        result = is_suspicious_entropy("xk29dhs82kla9s.evil.com")
        assert result["is_suspicious"] is True

    def test_result_has_required_keys(self):
        result = is_suspicious_entropy("test.com")
        assert "domain" in result
        assert "entropy_score" in result
        assert "is_suspicious" in result
        assert "reason" in result

    def test_result_domain_matches_input(self):
        result = is_suspicious_entropy("google.com")
        assert result["domain"] == "google.com"

    def test_flagged_domain_has_reason(self):
        result = is_suspicious_entropy("xk29dhs82kla9s.evil.com")
        assert len(result["reason"]) > 0