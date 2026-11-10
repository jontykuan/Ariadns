"""Test Suite for Ticket 36 & 37: Topological Causal Chains, Structured Statements and SVG Edge Method Pills."""

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from ariadns.models.config import AppConfig
from ariadns.models.entities import IdentityProfile, Infrastructure, PropositionNode, SubdomainRecord
from ariadns.models.enums import OriginVerificationStatus
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.storage.db import DatabaseManager

def test_ticket_36_causal_chain_linking_ranks_and_structured_statements(tmp_path, monkeypatch):
    db_file = tmp_path / "test_causal.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    orch = Orchestrator(config=cfg, db=db)

    # Mock M1 resolvers
    def mock_resolve(target):
        if target == "ofa177.net":
            return {"A": ["182.173.0.181"], "NS": ["ns1.domaincontrol.com"], "MX": ["mail.ofa177.net"]}
        return {"A": [target], "NS": [], "MX": []}

    def mock_identity(target, records):
        return IdentityProfile(registrar_name="GoDaddy.com, LLC", soa_admin_email="dns@ofa177.net")

    def mock_infra(target, ips, run_portscan=False):
        return Infrastructure(
            current_ip=ips[0] if ips else target,
            is_cdn=False,
            asn="AS3462",
            asn_org_name="Chunghwa Telecom Co., Ltd.",
            server_banner="nginx"
        )

    monkeypatch.setattr(orch.m1, "resolve_records", mock_resolve)
    monkeypatch.setattr(orch.m1, "get_identity_profile", mock_identity)
    monkeypatch.setattr(orch.m1, "probe_infrastructure", mock_infra)

    # 1. Step M1 on root domain ofa177.net
    orch.run_step("ofa177.net", "m1", "ofa177.net", params={"lang": "zh"})
    props = {p.prop_id: p for p in db.get_normalized_propositions("ofa177.net", rendered_only=False)}

    assert "F1" in props and "F2" in props and "C1" in props
    assert props["F1"].rank == 0
    assert props["F2"].rank == 0
    assert props["C1"].rank == 1
    assert "【依據】" in props["F1"].statement and "【方法】" in props["F1"].statement and "【結果】" in props["F1"].statement
    assert "【依據】" in props["F2"].statement and "【方法】" in props["F2"].statement and "【結果】" in props["F2"].statement
    assert "【依據】" in props["C1"].statement and "【方法】" in props["C1"].statement and "【結果】" in props["C1"].statement

    # 2. Step M1 on secondary target IP 182.173.0.181
    orch.run_step("ofa177.net", "m1", "182.173.0.181", params={"lang": "zh"})
    props = {p.prop_id: p for p in db.get_normalized_propositions("ofa177.net", rendered_only=False)}
    edges = set(db.get_normalized_edges("ofa177.net"))

    assert "182_173_0_181_F1" in props
    ip_f1 = props["182_173_0_181_F1"]
    assert ip_f1.premises == ["F1"]
    assert ip_f1.rank == 1
    assert ("F1", "182_173_0_181_F1") in edges
    assert "【依據】" in ip_f1.statement and "【方法】" in ip_f1.statement and "【結果】" in ip_f1.statement

    assert "182_173_0_181_C1" in props
    ip_c1 = props["182_173_0_181_C1"]
    assert ip_c1.rank == 2
    assert ("182_173_0_181_F1", "182_173_0_181_C1") in edges

    # 3. Step M2 on root domain
    monkeypatch.setattr(orch.m2, "run", lambda tgt: [
        SubdomainRecord(subdomain="api.ofa177.net", ip="182.173.0.182", server="nginx")
    ])
    orch.run_step("ofa177.net", "m2", "ofa177.net", params={"lang": "zh"})
    props = {p.prop_id: p for p in db.get_normalized_propositions("ofa177.net", rendered_only=False)}
    edges = set(db.get_normalized_edges("ofa177.net"))

    assert "F_SUB_1" in props
    f_sub = props["F_SUB_1"]
    assert f_sub.premises == ["F1"]
    assert f_sub.rank == 1
    assert ("F1", "F_SUB_1") in edges
    assert "【依據】" in f_sub.statement and "【方法】" in f_sub.statement and "【結果】" in f_sub.statement

    # 4. Step M3 on root domain
    monkeypatch.setattr(orch.m3, "detect_origin", lambda tgt, ip: ("182.173.0.181", OriginVerificationStatus.CONFIRMED))
    orch.run_step("ofa177.net", "m3", "ofa177.net", params={"lang": "zh"})
    props = {p.prop_id: p for p in db.get_normalized_propositions("ofa177.net", rendered_only=False)}
    edges = set(db.get_normalized_edges("ofa177.net"))

    assert "F_ORIGIN" in props
    f_orig = props["F_ORIGIN"]
    assert f_orig.premises == ["F1"]
    assert f_orig.rank == 1
    assert ("F1", "F_ORIGIN") in edges
    assert "【依據】" in f_orig.statement and "【方法】" in f_orig.statement and "【結果】" in f_orig.statement

    # 5. Step M4 on root domain
    monkeypatch.setattr(orch.m4, "reverse_ip", lambda ip: ["sibling-ofa177.net"])
    orch.run_step("ofa177.net", "m4", "ofa177.net", params={"lang": "zh"})
    props = {p.prop_id: p for p in db.get_normalized_propositions("ofa177.net", rendered_only=False)}
    edges = set(db.get_normalized_edges("ofa177.net"))

    assert "F_PIVOT_1" in props
    f_piv = props["F_PIVOT_1"]
    assert len(f_piv.premises) > 0
    assert f_piv.rank >= 1
    assert (f_piv.premises[0], "F_PIVOT_1") in edges
    assert "【依據】" in f_piv.statement and "【方法】" in f_piv.statement and "【結果】" in f_piv.statement

    # 6. Step trace
    monkeypatch.setattr("ariadns.modules.m5_orchestrator.run_active_trace", lambda **kw: {
        "status": "OK",
        "tail_hops": [
            {"hop": 5, "ip": "210.65.126.1", "asn": "AS3462", "asn_org_name": "Chunghwa Telecom", "ptr": ""},
            {"hop": 6, "ip": "182.173.0.181", "asn": "AS3462", "asn_org_name": "Chunghwa Telecom", "ptr": ""},
        ]
    })
    orch.run_step("ofa177.net", "trace", "182.173.0.181", params={"ack_opsec": True, "lang": "zh"})
    props = {p.prop_id: p for p in db.get_normalized_propositions("ofa177.net", rendered_only=False)}
    edges = set(db.get_normalized_edges("ofa177.net"))

    assert "F_TRACE" in props
    f_tr = props["F_TRACE"]
    assert len(f_tr.premises) > 0
    assert f_tr.rank >= 1
    assert (f_tr.premises[0], "F_TRACE") in edges
    assert "【依據】" in f_tr.statement and "【方法】" in f_tr.statement and "【結果】" in f_tr.statement


def test_ticket_37_svg_edge_method_pills_and_node_badges(tmp_path):
    from ariadns.modules.m6_reporting import render_evidence_artifacts
    from ariadns.models.entities import DataCustodian

    db_file = tmp_path / "test_svg_pills.db"
    db = DatabaseManager(str(db_file))

    nodes = [
        PropositionNode(
            prop_id="F1",
            node_kind="FACT",
            rank=0,
            statement="【依據】調查目標網域 ofa177.net 【方法】本地 DNS 解析與 HTTP 標頭探測 【結果】解析至 A:['182.173.0.181']，CDN:False (無)，Server:nginx",
            target_entity="ofa177.net",
            entity_type="DOMAIN_L1",
        ),
        PropositionNode(
            prop_id="182_173_0_181_F1",
            node_kind="FACT",
            rank=1,
            premises=["F1"],
            statement="【依據】F1（解析紀錄包含 182.173.0.181） 【方法】Team Cymru BGP/ASN 與 HTTP 標頭探測 【結果】主機 IP 182.173.0.181 歸屬於 AS3462 (Chunghwa Telecom)，Server 標頭: nginx，CDN 代理: False",
            target_entity="182.173.0.181",
            entity_type="IP",
        ),
        PropositionNode(
            prop_id="F_SUB_1",
            node_kind="FACT",
            rank=1,
            premises=["F1"],
            statement="【依據】F1（根網域 ofa177.net） 【方法】被動憑證透明度 (CT) 與 DNS 字典枚舉 【結果】子網域 api.ofa177.net 解析至 182.173.0.182（伺服器: nginx）",
            target_entity="api.ofa177.net",
            entity_type="SUBDOMAIN",
        ),
        PropositionNode(
            prop_id="F_ORIGIN",
            node_kind="FACT",
            rank=1,
            premises=["F1"],
            statement="【依據】F1（受保護網域 ofa177.net） 【方法】被動 DNS 歷史紀錄回溯與 HTTP Host / Favicon 碰撞探測 【結果】發現候選真實來源主機 IP 182.173.0.181（狀態: CONFIRMED）",
            target_entity="182.173.0.181",
            entity_type="IP",
        ),
        PropositionNode(
            prop_id="F_PIVOT_1",
            node_kind="FACT",
            rank=2,
            premises=["182_173_0_181_F1"],
            statement="【依據】182_173_0_181_F1（182.173.0.181） 【方法】reverse_ip 關聯反查與 7 天誤報過濾 【結果】橫向轉向發現共構關聯網域 sibling-ofa177.net",
            target_entity="sibling-ofa177.net",
            entity_type="DOMAIN_L2",
        ),
        PropositionNode(
            prop_id="F_TRACE",
            node_kind="FACT",
            rank=2,
            premises=["182_173_0_181_F1"],
            statement="【依據】182_173_0_181_F1（目標 IP 182.173.0.181） 【方法】tracert 路由躍遷追蹤與 Team Cymru 骨幹 ASN 查詢 【結果】路由躍遷追蹤至 182.173.0.181",
            target_entity="182.173.0.181",
            entity_type="IP",
            rule_name="RULE_ACTIVE_TRACEROUTE"
        ),
        PropositionNode(
            prop_id="182_173_0_181_C1",
            node_kind="CONCLUSION",
            rank=2,
            premises=["182_173_0_181_F1"],
            statement="【依據】182_173_0_181_F1 【方法】因果歸納與資料保管單位映射 【結果】已確認主機 IP 182.173.0.181 之網路電信商與機房歸屬（Chunghwa Telecom）",
            target_entity="182.173.0.181",
            entity_type="IP",
            custodians=[DataCustodian("Chunghwa Telecom", "ISP", "IP:182.173.0.181", ["NetFlow", "KYC"])],
        ),
    ]

    edges = [
        ("F1", "182_173_0_181_F1"),
        ("F1", "F_SUB_1"),
        ("F1", "F_ORIGIN"),
        ("182_173_0_181_F1", "F_PIVOT_1"),
        ("182_173_0_181_F1", "F_TRACE"),
        ("182_173_0_181_F1", "182_173_0_181_C1"),
    ]
    db.save_normalized_evidence("ofa177.net", nodes, edges)

    svg_path, png_path, _, _ = render_evidence_artifacts(
        "ofa177.net", db, tmp_path, color_coding=True, show_legend=True, lang="zh"
    )
    svg_content = svg_path.read_text(encoding="utf-8")

    # 1. Edge midpoint pills present
    assert "A紀錄 ➔ ASN歸屬探測" in svg_content
    assert "子網域枚舉" in svg_content
    assert "來源碰撞探測" in svg_content
    assert "橫向共構轉向" in svg_content
    assert "路由躍遷追蹤" in svg_content
    assert "事實推導 ➔ 調閱結論" in svg_content

    # 2. Node method badges present in headers
    assert "M1:DNS探測" in svg_content
    assert "M1:ASN/BGP" in svg_content
    assert "M2:子網域" in svg_content
    assert "M3:來源探測" in svg_content
    assert "M4:關聯轉向" in svg_content
    assert "M9:路由追蹤" in svg_content
    assert "鑑識調閱" in svg_content


def test_ui_v102_prop_rec_swap_and_batch_execution():
    tpl_path = Path(__file__).parent.parent / "src" / "ariadns" / "interfaces" / "templates" / "workbench.html"
    html = tpl_path.read_text(encoding="utf-8")

    # 1. Proposition section ("證據節點") appears BEFORE Recommendation section ("建議下一步") in DOM
    prop_idx = html.index('id="txtPropTitle"')
    rec_idx = html.index('id="txtRecTitle"')
    assert prop_idx < rec_idx, "證據節點 must appear above 建議下一步 in left sidebar"

    # 2. Recommendation header has (n/MAX)項建議 format and 批次執行 button
    assert 'id="btnBatchRunRecs"' in html
    assert "batchRunRecommendations()" in html
    assert "(0/0)項建議" in html
    assert "批次執行" in html

    # 3. Each recommendation option renders a checkbox after REC_* badge
    assert 'class="rec-check"' in html
    assert "updateRecSelectionCount()" in html


def test_v103_aspect_ratio_and_viewport_zoom(tmp_path):
    import re
    from ariadns.modules.m6_reporting import render_evidence_artifacts

    db_file = tmp_path / "test_v103.db"
    db = DatabaseManager(str(db_file))

    # Case 1: Wide single-rank fan-out (1 root + 6 rank-1 nodes + 1 rank-2 conclusion)
    nodes = [
        PropositionNode(
            prop_id="F1",
            node_kind="FACT",
            rank=0,
            statement="【依據】調查目標 example.com 【方法】DNS探測 【結果】解析至 1.2.3.4",
            target_entity="example.com",
            entity_type="DOMAIN_L1",
        )
    ]
    edges = []
    for i in range(1, 7):
        pid = f"F_SUB_{i}"
        nodes.append(
            PropositionNode(
                prop_id=pid,
                node_kind="FACT",
                rank=1,
                premises=["F1"],
                statement=f"【依據】F1 【方法】子網域枚舉 【結果】sub{i}.example.com",
                target_entity=f"sub{i}.example.com",
                entity_type="SUBDOMAIN",
            )
        )
        edges.append(("F1", pid))

    nodes.append(
        PropositionNode(
            prop_id="C1",
            node_kind="CONCLUSION",
            rank=2,
            premises=["F_SUB_1"],
            statement="【依據】F_SUB_1 【方法】鑑識調閱 【結果】已確認保管單位",
            target_entity="example.com",
            entity_type="DOMAIN_L1",
        )
    )
    edges.append(("F_SUB_1", "C1"))
    db.save_normalized_evidence("example.com", nodes, edges)

    svg_path, _, _, _ = render_evidence_artifacts("example.com", db, tmp_path, lang="zh")
    svg_text = svg_path.read_text(encoding="utf-8")

    m = re.search(r'<svg[^>]+width="(\d+)"\s+height="(\d+)"', svg_text)
    assert m is not None
    w, h = int(m.group(1)), int(m.group(2))
    aspect_ratio = w / h
    # Must fall within human-comfortable 4:3 (~1.33) to 16:9 (~1.78) band
    assert 1.30 <= aspect_ratio <= 1.80, f"Expected aspect ratio in [1.30, 1.80], got {aspect_ratio:.2f} ({w}x{h})"

    # Verify interactive zoom & pan support in workbench.html
    tpl_path = Path(__file__).parent.parent / "src" / "ariadns" / "interfaces" / "templates" / "workbench.html"
    html = tpl_path.read_text(encoding="utf-8")
    assert 'id="btnResetZoom"' in html
    assert "resetGraphZoom()" in html
    assert "applyGraphTransform()" in html



