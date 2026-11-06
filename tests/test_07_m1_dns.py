from ariadns.models.config import AppConfig
from ariadns.modules.m1_local_probe import (
    LocalDnsResolver,
    extract_verification_tokens,
    parse_soa_rname,
)
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_parse_soa_rname():
    assert parse_soa_rname("admin.example.com.") == "admin@example.com"
    assert parse_soa_rname(r"hostmaster\.security.domain.com.") == "hostmaster.security@domain.com"
    assert parse_soa_rname("root.local") == "root@local"

def test_extract_verification_tokens():
    txts = [
        "v=spf1 include:_spf.google.com ~all",
        "google-site-verification=abc_123-XYZ",
        "facebook-domain-verification=fb998877",
        "some-random-text",
    ]
    tokens = extract_verification_tokens(txts)
    assert tokens["google"] == "google-site-verification=abc_123-XYZ"
    assert tokens["facebook"] == "facebook-domain-verification=fb998877"
    assert "ms" not in tokens

def test_dns_cache_hit_in_resolver(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    resolver = LocalDnsResolver(db, client, cfg)

    # Pre-populate cache
    db.set_dns_cache("testsite.local", "A", {"records": ["192.168.1.1"]})
    res = resolver.resolve_records("testsite.local")
    assert res["A"] == ["192.168.1.1"]
