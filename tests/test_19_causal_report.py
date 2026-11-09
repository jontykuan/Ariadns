import json
from ariadns.models.config import AppConfig
from ariadns.models.entities import (
    DataCustodian,
    IdentityProfile,
    Infrastructure,
    InvestigationResult,
    PropositionNode,
)
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.modules.m6_reporting import ReportingEngine
from ariadns.storage.db import DatabaseManager

def test_causal_report_generation(tmp_path):
    output_dir = tmp_path / "reports"
    reporting = ReportingEngine(output_dir=output_dir)

    custodian = DataCustodian(
        custodian_name="Cloudflare, Inc.",
        custodian_role="CDN / Reverse Proxy",
        queryable_node="IP:104.21.23.45",
        queryable_records=["Origin IP", "Billing Account"]
    )
    fact = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain points to 104.21.23.45",
        target_entity="104.21.23.45",
        entity_type="IP"
    )
    conclusion = PropositionNode(
        prop_id="C1",
        node_kind="CONCLUSION",
        rank=1,
        statement="Domain active on Cloudflare CDN",
        premises=["F1"],
        rule_name="RULE_DIRECT_OBSERVATION",
        target_entity="104.21.23.45",
        entity_type="IP",
        custodians=[custodian]
    )

    inv = InvestigationResult(
        target_domain="target.local",
        investigation_timestamp="2026-11-09T08:00:00Z",
        identity_profile=IdentityProfile(registrar_name="Namecheap"),
        infrastructure=Infrastructure(current_ip="104.21.23.45", is_cdn=True, cdn_provider="Cloudflare"),
        evidence_chain=[fact, conclusion]
    )

    paths = reporting.export_all(inv)
    assert paths["evidence_chain_json"].exists()
    assert paths["report_md"].exists()

    md_text = paths["report_md"].read_text(encoding="utf-8")
    assert "Causal Evidence Chain (因果證據鏈有向無環圖)" in md_text
    assert "結論節點對應資料管理源清單" in md_text
    assert "Cloudflare, Inc." in md_text
    assert "flowchart TD" in md_text
