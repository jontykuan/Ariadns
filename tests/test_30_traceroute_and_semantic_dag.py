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

def test_semantic_svg_renderer_multiline_colors_and_legend_toggles(tmp_path):
    from ariadns.modules.m6_reporting import render_evidence_artifacts
    from ariadns.models.entities import DataCustodian

    db_file = tmp_path / "test_svg.db"
    db = DatabaseManager(str(db_file))

    nodes = [
        PropositionNode(
            prop_id="F1",
            node_kind="FACT",
            rank=0,
            statement="網域 ofa177.net 解析至 A:['182.173.0.181']，CDN:False (無)，Server:nginx",
            target_entity="ofa177.net",
            entity_type="DOMAIN_L1",
        ),
        PropositionNode(
            prop_id="F_ORIGIN",
            node_kind="FACT",
            rank=0,
            statement="被動 DNS 發現真實來源 IP 182.173.0.181",
            target_entity="182.173.0.181",
            entity_type="IP",
        ),
        PropositionNode(
            prop_id="F_PIVOT_1",
            node_kind="FACT",
            rank=1,
            statement="橫向轉向發現共構網域 sibling-ofa177.net",
            premises=["F1"],
            target_entity="sibling-ofa177.net",
            entity_type="DOMAIN_L2",
        ),
        PropositionNode(
            prop_id="F_TRACE",
            node_kind="FACT",
            rank=1,
            statement="路由躍遷追蹤至 182.173.0.181",
            premises=["F1"],
            rule_name="RULE_ACTIVE_TRACEROUTE",
            target_entity="182.173.0.181",
            entity_type="IP",
        ),
        PropositionNode(
            prop_id="C1",
            node_kind="CONCLUSION",
            rank=2,
            statement="已確認基礎建設與調閱機構 GoDaddy.com, LLC",
            premises=["F1", "F_ORIGIN"],
            target_entity="ofa177.net",
            entity_type="DOMAIN_L1",
            custodians=[DataCustodian("GoDaddy", "Registrar", "DOMAIN:ofa177.net", ["KYC"])],
        ),
    ]
    edges = [("F1", "F_PIVOT_1"), ("F1", "F_TRACE"), ("F1", "C1"), ("F_ORIGIN", "C1")]
    db.save_normalized_evidence("ofa177.net", nodes, edges)

    # 1. Render with color_coding=True and show_legend=True
    svg_path, _, _, _ = render_evidence_artifacts(
        "ofa177.net", db, tmp_path, color_coding=True, show_legend=True, lang="zh"
    )
    svg_content = svg_path.read_text(encoding="utf-8")
    # Must contain all 4 semantic box colors
    assert "#38bdf8" in svg_content  # Direct Fact
    assert "#f59e0b" in svg_content  # Origin / Trace
    assert "#818cf8" in svg_content  # Pivot L2
    assert "#10b981" in svg_content  # Custodian Conclusion
    # Must contain dashed and dotted edge styles
    assert 'stroke-dasharray="6,4"' in svg_content
    assert 'stroke-dasharray="2,4"' in svg_content
    # Must contain Legend
    assert "圖例說明" in svg_content
    # Full statement preserved across wrapped lines without truncating IP at 32 chars
    assert "182.173.0.181" in svg_content
    assert "GoDaddy.com, LLC" in svg_content

    # 2. Render with color_coding=False and show_legend=False
    svg_path2, _, _, _ = render_evidence_artifacts(
        "ofa177.net", db, tmp_path, color_coding=False, show_legend=False, lang="zh"
    )
    svg_content2 = svg_path2.read_text(encoding="utf-8")
    assert "#f59e0b" not in svg_content2
    assert "#10b981" not in svg_content2
    assert "stroke-dasharray" not in svg_content2
    assert "圖例說明" not in svg_content2


def test_ui_compact_cards_autorun_modals_and_render_checkboxes():
    tpl_path = Path(__file__).parent.parent / "src" / "ariadns" / "interfaces" / "templates" / "workbench.html"
    html = tpl_path.read_text(encoding="utf-8")

    # 1. Auto-run button next to module section title
    assert 'id="btnAutoRun"' in html
    assert "autoRunSteps()" in html

    # 2. Compact clickable button cards with hover tooltips
    assert 'id="cardBtnM1"' in html
    assert 'id="cardBtnM2"' in html
    assert 'id="cardBtnM3"' in html
    assert 'id="cardBtnM4"' in html
    assert 'id="cardBtnTrace"' in html
    assert 'id="cardBtnM7"' in html

    # 3. Trace & M7 Confirmation Modals with default parameters (-d, 20, 500, 3)
    assert 'id="traceModal"' in html
    assert 'id="traceNoRdns" checked' in html
    assert 'id="traceMaxHops"' in html and 'value="20"' in html
    assert 'id="traceTimeout"' in html and 'value="500"' in html
    assert 'id="traceTailHops"' in html and 'value="3"' in html
    assert 'id="m7Modal"' in html
    assert "確定執行？" in html

    # 4. Color coding and Show legend default-checked checkboxes next to render button
    assert 'id="chkColorCoding" checked' in html
    assert 'id="chkShowLegend" checked' in html
    assert "顏色提示" in html
    assert "圖例說明" in html
    assert "color_coding: colorCoding" in html
    assert "show_legend: showLegend" in html
