import json
import pytest
from pathlib import Path
from ariadns.models.config import AppConfig
from ariadns.models.entities import PropositionNode, DataCustodian, SessionAuditEntry
from ariadns.storage.db import DatabaseManager
from ariadns.interfaces import mcp_server
from ariadns.interfaces.cli import main as cli_main

def test_mcp_inspect_normalized_zero_recompute(tmp_path, monkeypatch):
    db_file = tmp_path / "test_mcp_parity.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))

    # Pre-populate normalized propositions
    f1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain parity.local resolves to 1.1.1.1",
        target_entity="parity.local",
        entity_type="DOMAIN_L1",
        is_rendered=True,
    )
    f_hidden = PropositionNode(
        prop_id="F_HIDDEN",
        node_kind="FACT",
        rank=0,
        statement="Hidden fact",
        target_entity="parity.local",
        entity_type="SUBDOMAIN",
        is_rendered=False,
    )
    c1 = PropositionNode(
        prop_id="C1",
        node_kind="CONCLUSION",
        rank=1,
        statement="Infrastructure confirmed",
        premises=["F1"],
        target_entity="parity.local",
        entity_type="DOMAIN_L1",
        custodians=[
            DataCustodian(
                custodian_name="Test Custodian",
                custodian_role="Registrar",
                queryable_node="parity.local",
                queryable_records=["KYC"]
            )
        ],
        is_rendered=True,
    )

    db.save_normalized_evidence("parity.local", [f1, f_hidden, c1], [("F1", "C1")])
    db.append_audit_log(SessionAuditEntry(
        session_id="parity.local",
        step_seq=1,
        timestamp="2026-11-09T10:00:00Z",
        module_name="m1",
        target="parity.local",
        params_json="{}",
        added_fact_ids=["F1"],
        artifact_sha256="hash_parity"
    ))

    # Monkeypatch get_orchestrator
    class MockOrchestrator:
        def __init__(self):
            self.db = db
            self.config = cfg

        def run_investigation(self, *args, **kwargs):
            raise RuntimeError("run_investigation should NEVER be called on inspection!")

    monkeypatch.setattr(mcp_server, "get_orchestrator", lambda: MockOrchestrator())

    # 1. Inspect evidence_chain (rendered only)
    res_ec = mcp_server.osint_inspect(domain="parity.local", query_type="evidence_chain")
    chain = res_ec.get("evidence_chain", [])
    assert len(chain) == 2
    assert [p["prop_id"] for p in chain] == ["F1", "C1"]
    assert "F_HIDDEN" not in [p["prop_id"] for p in chain]

    # 2. Inspect custodians
    res_cust = mcp_server.osint_inspect(domain="parity.local", query_type="custodians")
    custs = res_cust.get("custodians", [])
    assert len(custs) == 1
    assert custs[0]["custodian_name"] == "Test Custodian"

    # 3. Read evidence graph tool
    graph_res = mcp_server.osint_read_evidence_graph("parity.local")
    assert graph_res["session_id"] == "parity.local"
    assert len(graph_res["propositions"]) == 2
    assert graph_res["edges"] == [["F1", "C1"]]
    assert len(graph_res["audit_logs"]) == 1

def test_mcp_and_cli_workflow(tmp_path, monkeypatch, capsys):
    db_file = tmp_path / "test_cli_parity.db"
    case_dir = tmp_path / "case_reports"
    case_dir.mkdir()

    # Pre-populate session
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    f1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain cli.test resolves to 104.21.91.151, CDN:True (Cloudflare)",
        target_entity="cli.test",
        entity_type="DOMAIN_L1",
        is_rendered=True
    )
    db.save_normalized_evidence("cli.test", [f1], [])
    db.append_audit_log(SessionAuditEntry(
        session_id="cli.test",
        step_seq=1,
        timestamp="2026-11-09T10:00:00Z",
        module_name="m1",
        target="cli.test",
        params_json="{}",
        added_fact_ids=["F1"],
        artifact_sha256="hash_cli"
    ))

    # Test MCP recommend tool
    from ariadns.modules.m5_orchestrator import Orchestrator
    orch = Orchestrator(config=cfg, db=db)
    monkeypatch.setattr(mcp_server, "get_orchestrator", lambda: orch)

    rec_res = mcp_server.osint_recommend_next("cli.test")
    assert len(rec_res.get("recommendations", [])) >= 1

    # Test MCP render graph tool
    render_res = mcp_server.osint_render_graph("cli.test", output_dir=str(case_dir))
    assert render_res["status"] == "OK"
    assert len(render_res["payload_sha256"]) == 64

    # Test MCP verify tool
    ver_res = mcp_server.osint_verify_case(str(case_dir))
    assert ver_res["verified"] is True

    # Test CLI verify command
    cli_exit = cli_main(["verify", "--case-dir", str(case_dir), "--db-path", str(db_file)])
    assert cli_exit == 0
    captured = capsys.readouterr()
    assert "VERIFIED: TRUE" in captured.out
