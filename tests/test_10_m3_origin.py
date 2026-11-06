from unittest.mock import MagicMock
from ariadns.models.config import AppConfig
from ariadns.models.enums import OriginVerificationStatus
from ariadns.modules.m3_origin import OriginDetector
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_detect_origin_non_cdn(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    detector = OriginDetector(db, client, cfg)

    # 1.2.3.4 is non-CDN
    ip, status = detector.detect_origin("example.com", "1.2.3.4")
    assert ip == "1.2.3.4"
    assert status == OriginVerificationStatus.CONFIRMED.value

def test_detect_origin_cdn_with_history(tmp_path, monkeypatch):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    detector = OriginDetector(db, client, cfg)

    # Mock historical IP
    db.set_dns_cache("example.com", "PDNS_HISTORY", {"ips": ["198.51.100.24"]})

    # Mock verify_candidate_origin to return True
    monkeypatch.setattr(detector, "verify_candidate_origin", lambda d, ip, **kw: True)

    # Cloudflare IP
    ip, status = detector.detect_origin("example.com", "104.21.23.45", live_title="Example Domain")
    assert ip == "198.51.100.24"
    assert status == OriginVerificationStatus.CONFIRMED.value
