from unittest.mock import MagicMock
from ariadns.models.config import AppConfig
from ariadns.modules.m2_subdomain import SubdomainEnumerator
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_query_crt_sh_parsing(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    enumerator = SubdomainEnumerator(db, client, cfg)

    # Mock response from crt.sh
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"name_value": "*.api.example.com\nadmin.example.com"},
        {"name_value": "dev.example.com"},
        {"name_value": "otherdomain.com"},  # Not matching target
    ]
    client.fetch_with_backoff = MagicMock(return_value=(mock_resp, "OK"))

    subs = enumerator.query_crt_sh("example.com")
    assert "api.example.com" in subs
    assert "admin.example.com" in subs
    assert "dev.example.com" in subs
    assert "otherdomain.com" not in subs

def test_subdomain_cached_run(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    enumerator = SubdomainEnumerator(db, client, cfg)

    db.set_dns_cache("example.com", "SUBDOMAINS_PROBED", {
        "records": [
            {"subdomain": "api.example.com", "ip": "1.2.3.4", "status_code": 200, "title": "API", "server": "nginx"}
        ]
    })

    records = enumerator.run("example.com")
    assert len(records) == 1
    assert records[0].subdomain == "api.example.com"
    assert records[0].ip == "1.2.3.4"
