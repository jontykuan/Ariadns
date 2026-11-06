import time
import pytest
from ariadns.storage.db import DatabaseManager

def test_dns_cache_lifecycle(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)

    # Miss
    assert db.get_dns_cache("example.com", "A") is None

    # Hit
    payload = {"records": ["93.184.216.34"]}
    db.set_dns_cache("example.com", "A", payload, ttl_seconds=100)
    cached = db.get_dns_cache("example.com", "A")
    assert cached == payload

    # Expiry
    db.set_dns_cache("example.com", "AAAA", {"records": []}, ttl_seconds=-1)
    assert db.get_dns_cache("example.com", "AAAA") is None

def test_pivot_cache_lifecycle(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)

    assert db.get_pivot_cache("hackertarget", "reverse_ip", "1.2.3.4") is None

    payload = ["domain1.com", "domain2.com"]
    db.set_pivot_cache("hackertarget", "reverse_ip", "1.2.3.4", payload, ttl_seconds=500)
    cached = db.get_pivot_cache("hackertarget", "reverse_ip", "1.2.3.4")
    assert cached == payload

def test_readonly_sql_security(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    db.set_dns_cache("example.com", "A", {"ip": "1.1.1.1"}, ttl_seconds=100)

    # Valid select
    rows = db.execute_readonly_sql("SELECT domain, record_type FROM dns_cache")
    assert len(rows) == 1
    assert rows[0]["domain"] == "example.com"

    # Reject non-SELECT
    with pytest.raises(ValueError, match="Only SELECT or WITH queries"):
        db.execute_readonly_sql("DELETE FROM dns_cache")

    with pytest.raises(ValueError, match="Only SELECT or WITH queries"):
        db.execute_readonly_sql("DROP TABLE dns_cache")

    with pytest.raises(ValueError, match="Multiple SQL statements"):
        db.execute_readonly_sql("SELECT 1; DROP TABLE dns_cache")
