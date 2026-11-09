import pytest
from ariadns.models.entities import (
    PropositionNode,
    DataCustodian,
    SessionAuditEntry,
    NextStepRecommendation,
    ArtifactManifest,
    WarninglistIndicator,
)
from ariadns.storage.db import DatabaseManager

def test_normalized_evidence_storage_and_filter(tmp_path):
    db_file = tmp_path / "test_evidence.db"
    db = DatabaseManager(str(db_file))

    p1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain resolves to 1.1.1.1",
        premises=[],
        is_rendered=True,
    )
    p_noise = PropositionNode(
        prop_id="F_noise",
        node_kind="FACT",
        rank=0,
        statement="Noise subdomain resolves to 1.1.1.2",
        premises=[],
        is_rendered=False,
    )
    c1 = PropositionNode(
        prop_id="C1",
        node_kind="CONCLUSION",
        rank=1,
        statement="Infrastructure confirmed",
        premises=["F1"],
        is_rendered=True,
        custodians=[
            DataCustodian(
                custodian_name="Cloudflare",
                custodian_role="CDN",
                queryable_node="1.1.1.1",
                queryable_records=["Origin IP"],
            )
        ],
    )

    edges = [("F1", "C1")]
    db.save_normalized_evidence("test_session", [p1, p_noise, c1], edges)

    # All propositions
    all_props = db.get_normalized_propositions("test_session", rendered_only=False)
    assert len(all_props) == 3

    # Rendered only
    rendered = db.get_normalized_propositions("test_session", rendered_only=True)
    assert len(rendered) == 2
    rendered_ids = [p.prop_id for p in rendered]
    assert "F1" in rendered_ids
    assert "C1" in rendered_ids
    assert "F_noise" not in rendered_ids

    # Custodians
    custodians = db.get_normalized_custodians("test_session")
    assert len(custodians) == 1
    assert custodians[0]["custodian_name"] == "Cloudflare"

    # Edges
    retrieved_edges = db.get_normalized_edges("test_session")
    assert retrieved_edges == [("F1", "C1")]

    # Pure read-only SQL check on edges
    rows = db.execute_readonly_sql(
        "SELECT premise_id, conclusion_id FROM evidence_edges WHERE session_id = ?",
        ("test_session",)
    )
    assert rows == [{"premise_id": "F1", "conclusion_id": "C1"}]

def test_audit_log_append_and_retrieval(tmp_path):
    db_file = tmp_path / "test_audit.db"
    db = DatabaseManager(str(db_file))

    entry1 = SessionAuditEntry(
        session_id="case_1",
        step_seq=1,
        timestamp="2026-11-09T10:00:00Z",
        module_name="m1",
        target="example.com",
        params_json='{"depth": 1}',
        added_fact_ids=["F1", "F2"],
        artifact_sha256="abc123hash",
    )
    entry2 = SessionAuditEntry(
        session_id="case_1",
        step_seq=2,
        timestamp="2026-11-09T10:05:00Z",
        module_name="m2",
        target="example.com",
        params_json='{}',
        added_fact_ids=["F3"],
        artifact_sha256="def456hash",
    )

    db.append_audit_log(entry1)
    db.append_audit_log(entry2)

    logs = db.get_audit_logs("case_1")
    assert len(logs) == 2
    assert logs[0].step_seq == 1
    assert logs[0].added_fact_ids == ["F1", "F2"]
    assert logs[1].step_seq == 2
    assert logs[1].module_name == "m2"

def test_warninglist_schema_and_metadata(tmp_path):
    db_file = tmp_path / "test_warninglist.db"
    db = DatabaseManager(str(db_file))

    assert db.get_warninglist_last_synced() is None
    db.set_warninglist_metadata("last_synced_at", "1700000000")
    assert db.get_warninglist_last_synced() == 1700000000

    indicators = [
        WarninglistIndicator("parking-domain-ns", "substring", "above.com", 1700000000),
        WarninglistIndicator("freemail", "exact", "privateemail.com", 1700000000),
    ]
    db.save_warninglist_indicators(indicators)

    assert db.is_warninglist_match("ns1.above.com") is True
    assert db.is_warninglist_match("privateemail.com") is True
    assert db.is_warninglist_match("clean-domain.tw") is False
