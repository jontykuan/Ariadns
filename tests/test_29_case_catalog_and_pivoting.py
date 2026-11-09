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
