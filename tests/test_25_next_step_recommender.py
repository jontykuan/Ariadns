import pytest
from ariadns.models.config import AppConfig
from ariadns.models.entities import PropositionNode, SessionAuditEntry
from ariadns.storage.db import DatabaseManager
from ariadns.modules.m8_recommender import NextStepRecommender

def test_recommender_suggests_subdomains_and_origin_for_cdn_target(tmp_path):
    db_file = tmp_path / "test_rec.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))

    # Pre-populate session with M1 facts showing CDN
    p1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain example.com resolves to A:['104.21.91.151'], CDN:True (Cloudflare), Server:cloudflare",
        target_entity="example.com",
        entity_type="DOMAIN_L1"
    )
    p2 = PropositionNode(
        prop_id="F2",
        node_kind="FACT",
        rank=0,
        statement="Domain example.com registered via 'NameCheap, Inc.', SOA Admin 'admin@example.com', Tokens: []",
        target_entity="example.com",
        entity_type="DOMAIN_L1"
    )
    c1 = PropositionNode(
        prop_id="C1",
        node_kind="CONCLUSION",
        rank=1,
        statement="Active infrastructure identified for example.com",
        premises=["F1", "F2"],
        target_entity="example.com",
        entity_type="DOMAIN_L1"
    )
    db.save_normalized_evidence("case_cdn", [p1, p2, c1], [("F1", "C1"), ("F2", "C1")])

    # Record M1 in audit log
    db.append_audit_log(SessionAuditEntry(
        session_id="case_cdn",
        step_seq=1,
        timestamp="2026-11-09T10:00:00Z",
        module_name="m1",
        target="example.com",
        params_json="{}",
        added_fact_ids=["F1", "F2"],
        artifact_sha256="hash1"
    ))

    recommender = NextStepRecommender(db, cfg)
    recs = recommender.recommend("case_cdn")

    rec_modules = [r.recommended_module for r in recs]
    assert "m2" in rec_modules  # REC_ENUM_SUBDOMAINS
    assert "m3" in rec_modules  # REC_ORIGIN_COLLISION

    # Check recommendation details
    m2_rec = next(r for r in recs if r.recommended_module == "m2")
    assert m2_rec.recommended_target == "example.com"
    assert "F1" in m2_rec.trigger_fact_ids
    assert "subdomain" in m2_rec.rationale.lower()

def test_recommender_suggests_unproxied_ip_probe(tmp_path):
    db_file = tmp_path / "test_rec_ip.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))

    # Pre-populate session with M1 and M2 facts exposing unproxied IP
    f_sub = PropositionNode(
        prop_id="F_SUB_1",
        node_kind="FACT",
        rank=0,
        statement="Subdomain app.example.com resolves to 47.129.246.64 (Server: nginx)",
        target_entity="app.example.com",
        entity_type="SUBDOMAIN"
    )
    c_leak = PropositionNode(
        prop_id="C_UNPROXIED_1",
        node_kind="CONCLUSION",
        rank=2,
        statement="Unproxied backend origin host detected at 47.129.246.64 via app.example.com",
        premises=["F_SUB_1"],
        target_entity="47.129.246.64",
        entity_type="IP"
    )
    db.save_normalized_evidence("case_leak", [f_sub, c_leak], [("F_SUB_1", "C_UNPROXIED_1")])

    db.append_audit_log(SessionAuditEntry(
        session_id="case_leak",
        step_seq=1,
        timestamp="2026-11-09T10:00:00Z",
        module_name="m2",
        target="example.com",
        params_json="{}",
        added_fact_ids=["F_SUB_1"],
        artifact_sha256="hash2"
    ))

    recommender = NextStepRecommender(db, cfg)
    recs = recommender.recommend("case_leak")

    # Should recommend M1 port/banner probe on 47.129.246.64
    ip_rec = next(r for r in recs if r.recommended_target == "47.129.246.64")
    assert ip_rec.recommended_module == "m1"
    assert "F_SUB_1" in ip_rec.trigger_fact_ids

    # If M1 has already run on 47.129.246.64, it must NOT be re-recommended
    db.append_audit_log(SessionAuditEntry(
        session_id="case_leak",
        step_seq=2,
        timestamp="2026-11-09T10:05:00Z",
        module_name="m1",
        target="47.129.246.64",
        params_json="{}",
        added_fact_ids=[],
        artifact_sha256="hash3"
    ))
    updated_recs = recommender.recommend("case_leak")
    assert not any(r.recommended_module == "m1" and r.recommended_target == "47.129.246.64" for r in updated_recs)
