import json
import time
import pytest
from pathlib import Path
from ariadns.models.config import AppConfig
from ariadns.models.entities import PropositionNode, SessionAuditEntry
from ariadns.storage.db import DatabaseManager

def test_db_list_sessions_returns_aggregated_targets_and_counts(tmp_path):
    db_file = tmp_path / "test_catalog.db"
    db = DatabaseManager(str(db_file))

    # Seed session alpha.com with 2 propositions on alpha.com and beta.com
    p1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain alpha.com resolves to 1.1.1.1",
        target_entity="alpha.com",
        entity_type="DOMAIN_L1"
    )
    p2 = PropositionNode(
        prop_id="F_PIVOT_1",
        node_kind="FACT",
        rank=0,
        statement="Pivoting discovered correlated domain beta.com",
        target_entity="beta.com",
        entity_type="DOMAIN_L2"
    )
    db.save_normalized_evidence("alpha.com", [p1, p2], [])

    # Seed audit log for alpha.com with target beta.com
    db.append_audit_log(SessionAuditEntry(
        session_id="alpha.com",
        step_seq=1,
        timestamp="2026-11-09T12:00:00Z",
        module_name="m1",
        target="alpha.com",
        params_json="{}",
        added_fact_ids=["F1"],
        artifact_sha256="hash1"
    ))
    db.append_audit_log(SessionAuditEntry(
        session_id="alpha.com",
        step_seq=2,
        timestamp="2026-11-09T12:05:00Z",
        module_name="m4",
        target="beta.com",
        params_json="{}",
        added_fact_ids=["F_PIVOT_1"],
        artifact_sha256="hash2"
    ))

    # Seed separate session gamma.com
    p3 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain gamma.com resolves to 2.2.2.2",
        target_entity="gamma.com",
        entity_type="DOMAIN_L1"
    )
    db.save_normalized_evidence("gamma.com", [p3], [])

    sessions = db.list_sessions()
    session_map = {s["session_id"]: s for s in sessions}

    assert "alpha.com" in session_map
    assert "gamma.com" in session_map

    alpha = session_map["alpha.com"]
    assert alpha["proposition_count"] == 2
    assert "alpha.com" in alpha["targets"]
    assert "beta.com" in alpha["targets"]

    gamma = session_map["gamma.com"]
    assert gamma["proposition_count"] == 1
    assert gamma["targets"] == ["gamma.com"]

def test_web_ui_sessions_and_status_targets(tmp_path, monkeypatch):
    import urllib.request
    from ariadns.interfaces.web_ui import WorkbenchRequestHandler, start_web_ui
    import threading
    import socket

    db_file = tmp_path / "web_catalog.db"
    db = DatabaseManager(str(db_file))
    p1 = PropositionNode(
        prop_id="F1",
        node_kind="FACT",
        rank=0,
        statement="Domain delta.com resolves to 3.3.3.3",
        target_entity="delta.com",
        entity_type="DOMAIN_L1"
    )
    p2 = PropositionNode(
        prop_id="F_PIVOT_1",
        node_kind="FACT",
        rank=0,
        statement="Domain epsilon.com correlated",
        target_entity="epsilon.com",
        entity_type="DOMAIN_L2"
    )
    db.save_normalized_evidence("delta.com", [p1, p2], [])

    # Find free port
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = start_web_ui(host="127.0.0.1", port=port, db_path=str(db_file), output_dir=str(tmp_path), open_browser=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Test GET /api/sessions
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/sessions") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "OK"
            s_map = {s["session_id"]: s for s in data["sessions"]}
            assert "delta.com" in s_map
            assert "epsilon.com" in s_map["delta.com"]["targets"]

        # Test GET /api/status?session_id=delta.com includes targets
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status?session_id=delta.com") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "targets" in data
            assert "delta.com" in data["targets"]
            assert "epsilon.com" in data["targets"]
    finally:
        server.shutdown()
        server.server_close()

def test_multi_target_dag_linking_and_recommender(tmp_path, monkeypatch):
    from ariadns.modules.m5_orchestrator import Orchestrator
    from ariadns.modules.m8_recommender import NextStepRecommender
    from ariadns.models.entities import Infrastructure, IdentityProfile

    db_file = tmp_path / "pivot_test.db"
    db = DatabaseManager(str(db_file))
    cfg = AppConfig(db_path=str(db_file))
    orch = Orchestrator(config=cfg, db=db)

    # Mock M1 probe
    def mock_resolve(target):
        return {"A": ["1.2.3.4"], "NS": ["ns1.host.com"], "MX": []}
    def mock_identity(target, records):
        return IdentityProfile(registrar_name="TargetRegistrar")
    def mock_infra(target, ips, run_portscan=False):
        return Infrastructure(current_ip="1.2.3.4", is_cdn=False)

    monkeypatch.setattr(orch.m1, "resolve_records", mock_resolve)
    monkeypatch.setattr(orch.m1, "get_identity_profile", mock_identity)
    monkeypatch.setattr(orch.m1, "probe_infrastructure", mock_infra)

    # 1. Run M1 on primary target "root.com"
    entry1 = orch.run_step("root.com", "m1", "root.com")
    root_props = db.get_normalized_propositions("root.com", rendered_only=False)
    root_prop_ids = {p.prop_id for p in root_props}
    assert "F1" in root_prop_ids
    assert "C1" in root_prop_ids

    # 2. Add pivot discovery fact F_PIVOT_1 pointing to "correlated.com"
    f_pivot = PropositionNode(
        prop_id="F_PIVOT_1",
        node_kind="FACT",
        rank=0,
        statement="Pivoting on 1.2.3.4 discovered correlated domain correlated.com",
        target_entity="correlated.com",
        entity_type="DOMAIN_L2"
    )
    db.save_normalized_evidence("root.com", [f_pivot], [])

    # Recommender should suggest M1 on correlated.com
    recommender = NextStepRecommender(db, cfg)
    recs = recommender.recommend("root.com")
    assert any(r.recommended_module == "m1" and r.recommended_target == "correlated.com" for r in recs)

    # 3. Run M1 on secondary target "correlated.com" under the SAME session "root.com"
    entry2 = orch.run_step("root.com", "m1", "correlated.com")

    # 4. Verify root propositions are NOT overwritten
    all_props = db.get_normalized_propositions("root.com", rendered_only=False)
    all_prop_ids = {p.prop_id for p in all_props}
    assert "F1" in all_prop_ids
    assert "C1" in all_prop_ids
    # Secondary propositions are namespaced
    assert "correlated_com_F1" in all_prop_ids
    assert "correlated_com_C1" in all_prop_ids

    # 5. Verify causal edge from F_PIVOT_1 to correlated_com_C1
    edges = db.get_normalized_edges("root.com")
    assert ("F_PIVOT_1", "correlated_com_C1") in edges
