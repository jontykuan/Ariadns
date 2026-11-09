import time
import httpx
import pytest
from ariadns.models.config import AppConfig
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import RateLimiter, HttpClient
from ariadns.utils.warninglist_sync import WarninglistSynchronizer
from ariadns.modules.m4_pivoting import PivotingEngine

def test_warninglist_sync_cached_within_7_days(tmp_path, monkeypatch):
    db_file = tmp_path / "test_sync.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    rl = RateLimiter(db, cfg)
    http_client = HttpClient(rl, cfg)

    now = int(time.time())
    db.set_warninglist_metadata("last_synced_at", str(now - 3600))  # 1 hour ago

    external_calls = 0
    def mock_fetch(url, *args, **kwargs):
        nonlocal external_calls
        external_calls += 1
        return None, ModuleStatus.OK

    monkeypatch.setattr(http_client, "fetch_with_backoff", mock_fetch)

    syncer = WarninglistSynchronizer(db, http_client, cfg)
    status = syncer.ensure_warninglists_synced()

    assert status == ModuleStatus.CACHED
    assert external_calls == 0

def test_warninglist_sync_executes_and_filters_pivots(tmp_path, monkeypatch):
    db_file = tmp_path / "test_filter.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    rl = RateLimiter(db, cfg)
    http_client = HttpClient(rl, cfg)

    now = int(time.time())
    db.set_warninglist_metadata("last_synced_at", str(now - 700000))  # > 7 days

    def mock_fetch(url, *args, **kwargs):
        if "parking-domain-ns" in url:
            content = '{"name": "parking-domain-ns", "type": "substring", "list": ["parking.namecheap.com", "above.com"]}'
        elif "free-email-domains" in url:
            content = '["privateemail.com", "titan.email"]'
        elif "parking-domain" in url:
            content = '{"name": "parking-domain", "type": "cidr", "list": ["198.51.100.99"]}'
        elif "common-contact-emails" in url:
            content = '{"name": "common-contact-emails", "type": "regex", "list": ["abuse@.*"]}'
        else:
            content = '[]'

        resp = httpx.Response(200, text=content, request=httpx.Request("GET", url))
        return resp, ModuleStatus.OK

    monkeypatch.setattr(http_client, "fetch_with_backoff", mock_fetch)

    syncer = WarninglistSynchronizer(db, http_client, cfg)
    status = syncer.ensure_warninglists_synced()

    assert status == ModuleStatus.OK
    assert db.get_warninglist_last_synced() is not None

    # Test M4 pivoting filtration
    pivot_engine = PivotingEngine(db, http_client, cfg)

    external_pivot_calls = 0
    def mock_pivot_fetch(url, *args, **kwargs):
        nonlocal external_pivot_calls
        external_pivot_calls += 1
        return None, ModuleStatus.OK

    monkeypatch.setattr(http_client, "fetch_with_backoff", mock_pivot_fetch)

    # Reverse MX with blacklisted shared host
    res_mx = pivot_engine.reverse_mx("mx1.privateemail.com")
    assert res_mx == []
    assert external_pivot_calls == 0

    # Reverse NS with blacklisted parking NS
    res_ns = pivot_engine.reverse_ns("ns1.parking.namecheap.com")
    assert res_ns == []
    assert external_pivot_calls == 0

def test_warninglist_sync_fallback_on_network_failure(tmp_path, monkeypatch):
    db_file = tmp_path / "test_fallback.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    rl = RateLimiter(db, cfg)
    http_client = HttpClient(rl, cfg)

    def mock_fail(url, *args, **kwargs):
        return None, ModuleStatus.TIMEOUT_UNVERIFIED

    monkeypatch.setattr(http_client, "fetch_with_backoff", mock_fail)

    syncer = WarninglistSynchronizer(db, http_client, cfg)
    status = syncer.ensure_warninglists_synced()

    assert status == ModuleStatus.FALLBACK_NATIVE
