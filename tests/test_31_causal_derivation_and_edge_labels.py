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
