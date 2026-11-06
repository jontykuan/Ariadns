from unittest.mock import MagicMock
from ariadns.models.config import AppConfig
from ariadns.models.enums import ModuleStatus
from ariadns.modules.m4_pivoting import PivotingEngine
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_reverse_ip_cached(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    engine = PivotingEngine(db, client, cfg)

    db.set_pivot_cache("hackertarget", "reverse_ip", "1.2.3.4", ["test1.com", "test2.com"])
    domains = engine.reverse_ip("1.2.3.4")
    assert domains == ["test1.com", "test2.com"]

def test_reverse_mx_blacklisted(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    engine = PivotingEngine(db, client, cfg)

    # Blacklisted MX host
    domains = engine.reverse_mx("aspmx.l.google.com")
    assert domains == []

def test_reverse_token_missing_key(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    engine = PivotingEngine(db, client, cfg)

    domains, status = engine.reverse_token_or_email("google-site-verification=xyz")
    assert domains == []
    assert status == ModuleStatus.SKIPPED_NO_KEY.value
