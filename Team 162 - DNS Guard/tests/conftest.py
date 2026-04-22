import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from config.database import get_connection

@pytest.fixture
def db_conn():
    conn = get_connection()
    yield conn
    conn.close()

@pytest.fixture
def sample_domains():
    return [
        "google.com",
        "mail.google.com",
        "g00gle.com",
        "xk29dhs82kla.evil.com",
        "a9x2kd83ls92.attacker.com"
    ]

@pytest.fixture
def clean_domains():
    return [
        "google.com",
        "facebook.com",
        "amazon.com",
        "github.com"
    ]

@pytest.fixture
def suspicious_domains():
    return [
        "xk29dhs82kla9s2m.evil.com",
        "a8b2c9d1e4f6g7h3.net",
        "g00gle.com",
        "amaz0n.com"
    ]