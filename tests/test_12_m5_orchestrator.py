from unittest.mock import MagicMock
from ariadns.models.config import AppConfig
from ariadns.models.enums import ConfidenceLevel
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.storage.db import DatabaseManager

def test_orchestrator_pipeline_cached(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    cfg = AppConfig(db_path=str(db_file))
    orchestrator = Orchestrator(config=cfg, db=db)

    # Pre-populate cache for example.com
    db.set_dns_cache("example.com", "A", {"records": ["198.51.100.24"]})
    db.set_dns_cache("example.com", "MX", {"records": ["10 aspmx.l.google.com."]})
    db.set_dns_cache("example.com", "NS", {"records": ["ns1.cloudflare.com."]})
    db.set_dns_cache("example.com", "TXT", {"records": ["google-site-verification=tok123"]})
    db.set_dns_cache("example.com", "SOA", {"records": {"mname": "ns.example.com", "rname": "admin.example.com.", "serial": 1}})
    db.set_dns_cache("example.com", "SUBDOMAINS_PROBED", {"records": []})

    # Reverse IP pivot returns co-hosted domain
    db.set_pivot_cache("hackertarget", "reverse_ip", "198.51.100.24", ["portal.example.org"])

    res = orchestrator.run_investigation("example.com", depth=1)
    assert res.target_domain == "example.com"
    assert res.infrastructure.current_ip == "198.51.100.24"
    assert "portal.example.org" in res.pivots.same_origin_domains

    # Second run should work seamlessly from cache
    res2 = orchestrator.run_investigation("example.com", depth=1)
    assert res2.target_domain == "example.com"
    assert len(res2.pivots.same_origin_domains) == 1
