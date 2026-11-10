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
