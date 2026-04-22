import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import base64
from analysis.stego_detector import (
    extract_subdomain,
    is_base64_encoded,
    decode_base64,
    analyze_domain
)

def make_encoded_domain(message, base="evil.com"):
    encoded = base64.b64encode(message.encode()).decode().rstrip("=")
    return f"{encoded}.{base}"

class TestSteganography:

    def test_extract_subdomain_found(self):
        result = extract_subdomain("sub.evil.com")
        assert result == "sub"

    def test_extract_subdomain_no_subdomain(self):
        result = extract_subdomain("evil.com")
        assert result is None

    def test_base64_pattern_detected(self):
        encoded = base64.b64encode(b"hello world test").decode()
        assert is_base64_encoded(encoded) is True

    def test_normal_text_not_base64(self):
        assert is_base64_encoded("mail") is False
        assert is_base64_encoded("google") is False

    def test_decode_base64_correct(self):
        encoded = base64.b64encode(b"secret").decode()
        result = decode_base64(encoded)
        assert result == "secret"

    def test_analyze_domain_clean(self):
        result = analyze_domain("mail.google.com")
        assert result["is_suspicious"] is False

    def test_analyze_domain_suspicious(self):
        domain = make_encoded_domain("exfiltrated_data")
        result = analyze_domain(domain)
        assert result["is_suspicious"] is True
    def test_decoded_message_correct(self):
        # Use longer message to ensure encoded length exceeds 16 char minimum
        domain = make_encoded_domain("hello_world_secret_data")
        result = analyze_domain(domain)
        assert result["decoded_message"] is not None
        assert "hello_world_secret_data" in result["decoded_message"]
    def test_result_has_required_keys(self):
        result = analyze_domain("test.evil.com")
        assert "domain" in result
        assert "decoded_message" in result
        assert "is_suspicious" in result
        assert "reason" in result