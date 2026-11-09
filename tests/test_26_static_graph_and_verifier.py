import json
from pathlib import Path
import pytest
from ariadns.models.entities import PropositionNode, DataCustodian, SessionAuditEntry
from ariadns.storage.db import DatabaseManager
from ariadns.modules.m6_reporting import render_evidence_artifacts
from ariadns.storage.forensic_verifier import verify_case_artifacts

def test_static_graph_rendering_and_verification(tmp_path):
    db_file = tmp_path / "test_render.db"
    db = DatabaseManager(str(db_file))
    case_dir = tmp_path / "case_artifacts"
    case_dir.mkdir()

    # Pre-populate propositions
    f1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain example.com resolves to 104.21.91.151 (Cloudflare)",
        target_entity="example.com",
        entity_type="DOMAIN_L1",
        is_rendered=True,
    )
    f_excluded = PropositionNode(
        prop_id="F_EXCLUDED",
        node_kind="FACT",
        rank=0,
        statement="Low confidence noise item",
        target_entity="example.com",
        entity_type="SUBDOMAIN",
        is_rendered=False,
    )
    c1 = PropositionNode(
        prop_id="C1",
        node_kind="CONCLUSION",
        rank=1,
        statement="Active infrastructure identified",
        premises=["F1"],
        target_entity="example.com",
        entity_type="DOMAIN_L1",
        custodians=[
            DataCustodian(
                custodian_name="Cloudflare",
                custodian_role="CDN",
                queryable_node="104.21.91.151",
                queryable_records=["Origin IP"],
            )
        ],
        is_rendered=True,
    )

    db.save_normalized_evidence("case_verify", [f1, f_excluded, c1], [("F1", "C1")])
    db.append_audit_log(SessionAuditEntry(
        session_id="case_verify",
        step_seq=1,
        timestamp="2026-11-09T10:00:00Z",
        module_name="m1",
        target="example.com",
        params_json="{}",
        added_fact_ids=["F1"],
        artifact_sha256="hash1"
    ))

    # Render artifacts selecting only F1 and C1
    svg_path, png_path, md_path, manifest = render_evidence_artifacts(
        session_id="case_verify",
        db=db,
        output_dir=case_dir,
        selected_prop_ids=["F1", "C1"]
    )

    assert svg_path.exists()
    assert png_path.exists()
    assert md_path.exists()
    assert manifest.session_id == "case_verify"
    assert len(manifest.payload_sha256) == 64
    assert "F1" in manifest.rendered_prop_ids
    assert "F_EXCLUDED" in manifest.excluded_prop_ids

    # SVG content check
    svg_text = svg_path.read_text(encoding="utf-8")
    assert "F1" in svg_text
    assert "C1" in svg_text
    assert "F_EXCLUDED" not in svg_text
    assert manifest.payload_sha256 in svg_text  # Embedded watermark

    # Report content check
    md_text = md_path.read_text(encoding="utf-8")
    assert "Session Audit Log" in md_text
    assert "Forensic Manifest" in md_text or "Artifact Hashes" in md_text
    assert manifest.payload_sha256 in md_text

    # Verification: Unmodified -> Verified
    ver_result = verify_case_artifacts(case_dir, db=db)
    assert ver_result["verified"] is True
    assert ver_result["mismatches"] == []

    # Verification: Tampered SVG -> Unverified
    svg_path.write_text(svg_text + "<!-- tamper -->", encoding="utf-8")
    tampered_result = verify_case_artifacts(case_dir, db=db)
    assert tampered_result["verified"] is False
    assert len(tampered_result["mismatches"]) > 0
