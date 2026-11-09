from unittest.mock import MagicMock
from ariadns.interfaces.cli import build_parser, execute_manual_oob
from ariadns.interfaces.mcp_server import osint_inspect, osint_manual_oob, osint_scan
from ariadns.storage.db import DatabaseManager

def test_cli_manual_oob_arguments():
    parser = build_parser()
    args = parser.parse_args([
        "manual-oob",
        "-t", "https://example.com/preview",
        "-c", "https://canary.example.net/123",
        "--ack-risk"
    ])
    assert args.command == "manual-oob"
    assert args.target_url == "https://example.com/preview"
    assert args.callback_url == "https://canary.example.net/123"
    assert args.ack_risk is True

def test_cli_manual_oob_execution_aborted():
    code = execute_manual_oob(
        target_url="https://example.com/preview",
        callback_url="https://canary.example.net/123",
        param="url",
        method="GET",
        ack_risk=False
    )
    # Without ack_risk -> returns non-zero error code
    assert code == 1

def test_mcp_osint_inspect_evidence_and_custodians(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)

    # Pre-populate cache so scan runs locally with 0 external network calls
    db.set_dns_cache("target.local", "A", {"records": ["198.51.100.24"]})
    db.set_dns_cache("target.local", "MX", {"records": []})
    db.set_dns_cache("target.local", "NS", {"records": []})
    db.set_dns_cache("target.local", "TXT", {"records": ["google-site-verification=tok999"]})
    db.set_dns_cache("target.local", "SOA", {"records": {"mname": "ns.local", "rname": "sec.target.local.", "serial": 1}})
    db.set_dns_cache("target.local", "SUBDOMAINS_PROBED", {"records": []})

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

    # Test evidence_chain inspect
    ev_res = osint_inspect("target.local", query_type="evidence_chain")
    assert "evidence_chain" in ev_res
    assert len(ev_res["evidence_chain"]) >= 2

    # Test custodians inspect
    cust_res = osint_inspect("target.local", query_type="custodians")
    assert "custodians" in cust_res

    # Test manual OOB risk rejection in MCP
    oob_res = osint_manual_oob(
        target_endpoint_url="https://example.com/preview",
        callback_url="https://canary.example.net/123",
        acknowledge_opsec_risk=False
    )
    assert oob_res["callback_sent"] is False
    assert "OPSEC WARNING" in oob_res["warning"]
