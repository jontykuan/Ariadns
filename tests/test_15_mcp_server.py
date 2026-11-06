from ariadns.interfaces.mcp_server import osint_inspect, osint_scan
from ariadns.storage.db import DatabaseManager

def test_mcp_osint_scan_compact_digest(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)

    # Pre-populate cache so scan runs locally with 0 external network calls
    db.set_dns_cache("target.local", "A", {"records": ["198.51.100.24"]})
    db.set_dns_cache("target.local", "MX", {"records": []})
    db.set_dns_cache("target.local", "NS", {"records": []})
    db.set_dns_cache("target.local", "TXT", {"records": ["google-site-verification=tok999"]})
    db.set_dns_cache("target.local", "SOA", {"records": {"mname": "ns.local", "rname": "sec.target.local.", "serial": 1}})
    db.set_dns_cache("target.local", "SUBDOMAINS_PROBED", {"records": []})

    # Mock DB path in load
    monkeypatch.setattr("ariadns.interfaces.mcp_server.AppConfig.load", lambda: MagicMock(
        db_path=str(db_file),
        cache_ttl_seconds=604800,
        default_delay_seconds=0.01,
        http_timeout_seconds=1.0,
        virustotal_rpm=4,
        virustotal_rpd=500,
        mx_blacklist=[],
        ns_blacklist=[],
        shared_ip_threshold=100,
        api_keys={}
    ))
    from unittest.mock import MagicMock

    digest = osint_scan("target.local", mode="full")
    assert digest["status"] == "COMPLETED"
    assert digest["target_domain"] == "target.local"
    assert digest["current_ip"] == "198.51.100.24"
    assert "google" in digest["verification_tokens"]

    # Test inspect read-only SQL
    sql_res = osint_inspect("target.local", query_type="sql", sql_query="SELECT domain, record_type FROM dns_cache")
    assert "rows" in sql_res
    assert len(sql_res["rows"]) >= 1
