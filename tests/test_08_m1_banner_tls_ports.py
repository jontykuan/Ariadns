from unittest.mock import MagicMock
from ariadns.models.config import AppConfig
from ariadns.modules.m1_local_probe import (
    LocalDnsResolver,
    grab_http_banner,
    scan_ports,
)
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_grab_http_banner_timeout_resilience():
    # Attempt connecting to non-routable address to verify timeout resilience
    res = grab_http_banner("example.com", ip="192.0.2.1", timeout=0.1)
    assert res["status_code"] is None
    assert res["server"] is None

def test_probe_infrastructure_skips_cdn_ports(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    resolver = LocalDnsResolver(db, client, cfg)

    # Cloudflare IP
    infra = resolver.probe_infrastructure("example.com", ["104.21.23.45"], run_portscan=True)
    assert infra.is_cdn is True
    assert infra.cdn_provider == "Cloudflare"
    # Portscan must be skipped automatically for CDN
    assert infra.open_ports == []
