from unittest.mock import MagicMock
import httpx
from ariadns.models.config import AppConfig
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_rate_limiter_quota(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    cfg = AppConfig(virustotal_rpm=2, default_delay_seconds=0.01)
    limiter = RateLimiter(db, cfg)

    # Within quota
    assert limiter.check_and_increment_quota("virustotal") is True
    assert limiter.check_and_increment_quota("virustotal") is True

    # Exceeds quota (2 per minute)
    assert limiter.check_and_increment_quota("virustotal") is False

def test_http_client_backoff_exhaustion(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    cfg = AppConfig(default_delay_seconds=0.01)
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)

    # Mock time.sleep to run instantly
    monkeypatch.setattr("time.sleep", lambda s: None)

    # Mock call that always returns 429
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 429

    resp, status = client.fetch_with_backoff(
        "https://api.example.com",
        custom_caller=lambda: mock_resp
    )
    # When retries exhaust on 429, it returns the final response with OK status
    assert resp.status_code == 429

def test_http_client_quota_rejection(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    cfg = AppConfig(virustotal_rpm=1, default_delay_seconds=0.01)
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)

    resp1, status1 = client.fetch_with_backoff(
        "https://www.virustotal.com/api/v3",
        provider="virustotal",
        custom_caller=lambda: MagicMock(status_code=200)
    )
    assert status1 == ModuleStatus.OK.value

    # Second call in same minute rejected
    resp2, status2 = client.fetch_with_backoff(
        "https://www.virustotal.com/api/v3",
        provider="virustotal",
        custom_caller=lambda: MagicMock(status_code=200)
    )
    assert resp2 is None
    assert status2 == ModuleStatus.SKIPPED_QUOTA.value
