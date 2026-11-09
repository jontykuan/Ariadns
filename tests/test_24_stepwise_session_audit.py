import json
import time
import pytest
from pathlib import Path
from ariadns.models.config import AppConfig
from ariadns.models.entities import IdentityProfile, Infrastructure, SubdomainRecord
from ariadns.models.enums import PropositionKind
from ariadns.storage.db import DatabaseManager
from ariadns.modules.m5_orchestrator import Orchestrator

def test_stepwise_execution_and_incremental_facts(tmp_path, monkeypatch):
    db_file = tmp_path / "test_session.db"
    db = DatabaseManager(str(db_file))
    # Mark warninglists as fresh to avoid network calls
    db.set_warninglist_metadata("last_synced_at", str(int(time.time())))

    cfg = AppConfig(db_path=str(db_file))
    orchestrator = Orchestrator(config=cfg, db=db)

    # Mock M1 probe on target
    def mock_m1_resolve(domain):
        return {
            "A": ["104.21.91.151"],
            "NS": ["dakota.ns.cloudflare.com."],
            "MX": ["10 mx1.privateemail.com."],
            "TXT": [],
            "SOA": {"mname": "ns1.com", "rname": "admin.com.", "serial": 1},
        }

    def mock_m1_identity(domain, records):
        return IdentityProfile(
            registrar_name="NameCheap, Inc.",
            soa_admin_email="admin@example.com",
            verification_tokens={"google": "tok123"},
        )

    def mock_m1_infra(domain, ips, run_portscan=False):
        return Infrastructure(
            current_ip="104.21.91.151",
            is_cdn=True,
            cdn_provider="Cloudflare",
            server_banner="cloudflare",
        )

    monkeypatch.setattr(orchestrator.m1, "resolve_records", mock_m1_resolve)
    monkeypatch.setattr(orchestrator.m1, "get_identity_profile", mock_m1_identity)
    monkeypatch.setattr(orchestrator.m1, "probe_infrastructure", mock_m1_infra)

    # Step 1: Run M1 on example.com
    entry1 = orchestrator.run_step("case_test", "m1", "example.com")
    assert entry1.step_seq == 1
    assert entry1.module_name == "m1"
    assert "F1" in entry1.added_fact_ids or len(entry1.added_fact_ids) > 0
    assert len(entry1.artifact_sha256) == 64

    # Verify propositions saved
    props_after_step1 = db.get_normalized_propositions("case_test", rendered_only=False)
    assert len(props_after_step1) >= 2  # F1, F2 and/or C1

    # Mock M2 subdomain enumeration
    def mock_m2_run(domain):
        return [
            SubdomainRecord(subdomain=f"app.{domain}", ip="47.129.246.64", status_code=404, server="nginx")
        ]

    monkeypatch.setattr(orchestrator.m2, "run", mock_m2_run)

    # Step 2: Run M2 on example.com
    entry2 = orchestrator.run_step("case_test", "m2", "example.com")
    assert entry2.step_seq == 2
    assert entry2.module_name == "m2"
    assert len(entry2.added_fact_ids) > 0

    # Verify propositions were merged, NOT overwritten
    props_after_step2 = db.get_normalized_propositions("case_test", rendered_only=False)
    prop_ids = [p.prop_id for p in props_after_step2]
    # M1 propositions still present
    for p_id in entry1.added_fact_ids:
        assert p_id in prop_ids
    # M2 propositions newly added
    for p_id in entry2.added_fact_ids:
        assert p_id in prop_ids

    # Verify audit logs in DB
    logs = db.get_audit_logs("case_test")
    assert len(logs) == 2
    assert logs[0].step_seq == 1
    assert logs[1].step_seq == 2

    # Verify NO static image files created
    assert not list(tmp_path.glob("*.svg"))
    assert not list(tmp_path.glob("*.png"))
