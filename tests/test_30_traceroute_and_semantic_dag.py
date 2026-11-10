import json
import pytest
from pathlib import Path
from ariadns.models.config import AppConfig
from ariadns.models.entities import IdentityProfile, Infrastructure, PropositionNode
from ariadns.storage.db import DatabaseManager
from ariadns.modules.m5_orchestrator import Orchestrator

def test_ip_entity_differentiation_causal_linking_and_bilingual_m1_m4(tmp_path, monkeypatch):
    db_file = tmp_path / "test_32.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    orch = Orchestrator(config=cfg, db=db)

    def mock_resolve(target):
        if target == "ofa177.net":
            return {"A": ["182.173.0.181"], "NS": ["ns1.domaincontrol.com"], "MX": []}
        return {"A": [target], "NS": [], "MX": []}

    def mock_identity(target, records):
        if target == "ofa177.net":
            return IdentityProfile(registrar_name="GoDaddy.com, LLC")
        return IdentityProfile(registrar_name=None)

    def mock_infra(target, ips, run_portscan=False):
        return Infrastructure(
            current_ip="182.173.0.181",
            is_cdn=False,
            asn="AS3462",
            asn_org_name="Chunghwa Telecom Co., Ltd.",
            server_banner="nginx"
        )

    monkeypatch.setattr(orch.m1, "resolve_records", mock_resolve)
    monkeypatch.setattr(orch.m1, "get_identity_profile", mock_identity)
    monkeypatch.setattr(orch.m1, "probe_infrastructure", mock_infra)

    # 1. Run M1 on root domain "ofa177.net" in zh mode
    orch.run_step("ofa177.net", "m1", "ofa177.net", params={"lang": "zh"})

    # 2. Run M1 on secondary IP "182.173.0.181" in zh mode
    orch.run_step("ofa177.net", "m1", "182.173.0.181", params={"lang": "zh"})

    props = db.get_normalized_propositions("ofa177.net", rendered_only=False)
    prop_map = {p.prop_id: p for p in props}

    assert "182_173_0_181_C1" in prop_map
    ip_c1 = prop_map["182_173_0_181_C1"]
    # Must be classified as IP, not DOMAIN_L1/L2
    assert ip_c1.entity_type == "IP"
    assert len(ip_c1.custodians) > 0
    # Custodian must be Chunghwa Telecom / Hosting ISP, NOT Domain Registrar
    assert "Domain Registrar" not in ip_c1.custodians[0].custodian_name
    assert "Chunghwa Telecom" in ip_c1.custodians[0].custodian_name
    # Chinese role output check
    assert "主機" in ip_c1.custodians[0].custodian_role or "電信" in ip_c1.custodians[0].custodian_role or "網路" in ip_c1.custodians[0].custodian_role

    # Causal edge must link F1 (which resolved 182.173.0.181) to 182_173_0_181_C1
    edges = db.get_normalized_edges("ofa177.net")
    assert ("F1", "182_173_0_181_C1") in edges

    # 3. Test M4 auto-IP extraction when invoked on domain name "ofa177.net"
    called_ips = []
    def mock_reverse_ip(ip_val):
        called_ips.append(ip_val)
        return ["sibling-ofa177.net"]

    monkeypatch.setattr(orch.m4, "reverse_ip", mock_reverse_ip)
    orch.run_step("ofa177.net", "m4", "ofa177.net", params={"lang": "zh"})
    assert "182.173.0.181" in called_ips
    props_after_m4 = db.get_normalized_propositions("ofa177.net", rendered_only=False)
    assert any(p.target_entity == "sibling-ofa177.net" for p in props_after_m4)

def test_active_traceroute_module_cli_and_mcp(tmp_path, monkeypatch):
    import subprocess
    from ariadns.modules.m9_traceroute import build_tracert_command, parse_tracert_output, run_active_trace
    from ariadns.interfaces.cli import main as cli_main
    from ariadns.interfaces import mcp_server

    # 1. Verify command construction includes -d -h 20 -w 500
    cmd = build_tracert_command("182.173.0.181", no_rdns=True, max_hops=20, timeout_ms=500)
    assert "-d" in cmd or "-n" in cmd
    assert "20" in cmd
    assert "182.173.0.181" in cmd

    # 2. Verify OPSEC guard blocks execution when ack_opsec=False
    blocked = run_active_trace("182.173.0.181", ack_opsec=False)
    assert blocked["executed"] is False

    # 3. Mock 8-hop tracert output (including private hop 192.168.1.1 and 5 public hops)
    sample_output = """
Tracing route to 182.173.0.181 over a maximum of 20 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     5 ms     4 ms     5 ms  168.95.98.254
  3     8 ms     7 ms     8 ms  220.128.1.1
  4    12 ms    11 ms    12 ms  220.128.2.2
  5    15 ms    14 ms    15 ms  210.65.126.1
  6     *        *        *     Request timed out.
  7    18 ms    19 ms    18 ms  182.173.0.181
"""
    parsed_hops = parse_tracert_output(sample_output, "182.173.0.181")
    # Private IP 192.168.1.1 must be filtered out; 5 public responsive hops remain
    assert len(parsed_hops) == 5
    assert parsed_hops[-1]["ip"] == "182.173.0.181"

    class DummyCompletedProcess:
        def __init__(self, stdout):
            self.stdout = stdout
            self.returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: DummyCompletedProcess(sample_output))
    monkeypatch.setattr("ariadns.modules.m9_traceroute.resolve_ip_asn_details", lambda ip: {
        "asn": "AS3462",
        "asn_org_name": "Chunghwa Telecom Co., Ltd.",
        "country": "TW",
    })
    monkeypatch.setattr("ariadns.modules.m9_traceroute.resolve_ptr", lambda ip: f"r-{ip.replace('.', '-')}.hinet.net")

    db_file = tmp_path / "test_trace.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    orch = Orchestrator(config=cfg, db=db)

    # Seed F1
    db.save_normalized_evidence("ofa177.net", [
        PropositionNode(
            prop_id="F1",
            node_kind="FACT",
            rank=0,
            statement="Domain ofa177.net resolves to A:['182.173.0.181']",
            target_entity="ofa177.net",
            entity_type="DOMAIN_L1"
        )
    ], [])

    # Execute trace step retaining last 3 hops
    orch.run_step("ofa177.net", "trace", "182.173.0.181", params={
        "no_rdns": True,
        "max_hops": 20,
        "timeout_ms": 500,
        "tail_hops": 3,
        "ack_opsec": True,
        "lang": "zh",
    })

    props = db.get_normalized_propositions("ofa177.net", rendered_only=False)
    prop_map = {p.prop_id: p for p in props}
    assert "F_TRACE" in prop_map
    assert "C_TRACE" in prop_map
    # Only last 3 hops (220.128.2.2, 210.65.126.1, 182.173.0.181) should be in F_TRACE, NOT hop 2 (168.95.98.254)
    assert "168.95.98.254" not in prop_map["F_TRACE"].statement
    assert "210.65.126.1" in prop_map["F_TRACE"].statement
    assert "182.173.0.181" in prop_map["F_TRACE"].statement

    # Verify CLI trace without --ack-risk returns 1
    assert cli_main(["trace", "-d", "ofa177.net", "--target", "182.173.0.181"]) == 1

    # Verify MCP osint_trace without acknowledge_opsec_risk returns SKIPPED_OPSEC
    mcp_res_blocked = mcp_server.osint_trace(session_id="ofa177.net", target="182.173.0.181", acknowledge_opsec_risk=False)
    assert mcp_res_blocked["executed"] is False
