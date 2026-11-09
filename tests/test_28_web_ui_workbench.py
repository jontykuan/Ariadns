"""Test Suite for Ticket 28: Local Web UI Forensic Workbench."""

import json
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest
from ariadns.interfaces.web_ui import WorkbenchRequestHandler, start_web_ui
from ariadns.models.config import AppConfig
from ariadns.models.entities import IdentityProfile, Infrastructure, InvestigationResult
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.storage.db import DatabaseManager

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

@pytest.fixture(scope="module")
def web_workbench():
    test_dir = Path("./tmp_test_web_ui")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    db_path = str(test_dir / "test_workbench.db")
    output_dir = str(test_dir / "reports")
    db = DatabaseManager(db_path)

    # Seed an initial session with M1
    cfg = AppConfig.load()
    cfg.db_path = db_path
    orch = Orchestrator(config=cfg, db=db)

    # Mock m1 query
    mock_infra = Infrastructure(current_ip="1.2.3.4", asn_org_name="TEST_ISP")
    mock_id = IdentityProfile(soa_admin_email="admin@target.com")
    with patch.object(orch.m1, "resolve_records", return_value={"A": ["1.2.3.4"]}):
        with patch.object(orch.m1, "get_identity_profile", return_value=mock_id):
            with patch.object(orch.m1, "probe_infrastructure", return_value=mock_infra):
                orch.run_step("webtest.com", "m1", "webtest.com")

    port = get_free_port()
    host = "127.0.0.1"

    # Start server in background thread
    server = start_web_ui(host=host, port=port, db_path=db_path, output_dir=output_dir, open_browser=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    time.sleep(0.3)  # Wait for socket listen
    base_url = f"http://{host}:{port}"

    yield {
        "base_url": base_url,
        "test_dir": test_dir,
        "output_dir": output_dir,
        "db": db,
        "orch": orch,
    }

    server.shutdown()
    server.server_close()
    if test_dir.exists():
        shutil.rmtree(test_dir, ignore_errors=True)

def test_web_ui_root_page(web_workbench):
    """GET / serves the single-page workbench with key UI sections."""
    base_url = web_workbench["base_url"]
    with httpx.Client(base_url=base_url) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["Content-Type"]
        content = resp.text
        assert "Ariadns Forensic Workbench" in content
        assert "Visual CLI Command Cards" in content
        assert "Next-Step Recommendations" in content
        assert "Proposition Filter" in content
        assert "Data Custodians Matrix" in content

def test_web_ui_status_endpoint(web_workbench):
    """GET /api/status returns execution status and recommendations without rendering graph."""
    base_url = web_workbench["base_url"]
    with httpx.Client(base_url=base_url) as client:
        resp = client.get("/api/status?session_id=webtest.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert data["session_id"] == "webtest.com"
        assert "propositions" in data
        assert len(data["propositions"]) > 0
        assert "audit_logs" in data
        assert len(data["audit_logs"]) >= 1
        assert "recommendations" in data
        assert data["warninglist_synced"] is True

def test_web_ui_step_no_autorender(web_workbench):
    """POST /api/step executes a module step without auto-rendering images."""
    base_url = web_workbench["base_url"]
    output_dir = Path(web_workbench["output_dir"])

    # Ensure no image files exist before step
    svg_file = output_dir / "webtest_com_evidence.svg"
    png_file = output_dir / "webtest_com_evidence.png"
    assert not svg_file.exists()
    assert not png_file.exists()

    with httpx.Client(base_url=base_url) as client:
        # Step M2
        with patch.object(WorkbenchRequestHandler.orchestrator.m2, "run", return_value=[]):
            resp = client.post("/api/step", json={
                "session_id": "webtest.com",
                "module": "m2",
                "target": "webtest.com",
                "params": {}
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "OK"
            assert data["step"]["module_name"] == "m2"
            assert len(data["audit_logs"]) >= 2

    # Deterministic Mutant Kill: Auto-rendering must NOT have happened!
    assert not svg_file.exists(), "Mutant detected: POST /api/step must not auto-render static graph!"
    assert not png_file.exists(), "Mutant detected: POST /api/step must not auto-render static graph!"

def test_web_ui_render_endpoint(web_workbench):
    """POST /api/render generates static artifacts and returns payload_sha256 and manifest."""
    base_url = web_workbench["base_url"]
    output_dir = Path(web_workbench["output_dir"])

    with httpx.Client(base_url=base_url) as client:
        resp = client.post("/api/render", json={
            "session_id": "webtest.com",
            "selected_prop_ids": ["F1", "C1"]
        })
        assert resp.status_code == 200
        data = resp.json()

        # Deterministic Mutant Kill: Omitting payload_sha256 or audit_logs must fail
        assert "payload_sha256" in data and len(data["payload_sha256"]) == 64
        assert "session_audit_logs" in data and len(data["session_audit_logs"]) >= 1
        assert data["verified"] is True
        assert "svg_url" in data
        assert "png_url" in data
        assert "manifest" in data

        # Check files on disk
        svg_file = output_dir / "webtest_com_evidence.svg"
        png_file = output_dir / "webtest_com_evidence.png"
        assert svg_file.exists()
        assert png_file.exists()

        # Check /api/image endpoint
        img_svg = client.get("/api/image?session_id=webtest.com&type=svg")
        assert img_svg.status_code == 200
        assert "image/svg+xml" in img_svg.headers["Content-Type"]

        img_png = client.get("/api/image?session_id=webtest.com&type=png")
        assert img_png.status_code == 200
        assert "image/png" in img_png.headers["Content-Type"]

        # Check /api/verify endpoint
        ver_resp = client.get(f"/api/verify?case_dir={output_dir}")
        assert ver_resp.status_code == 200
        ver_data = ver_resp.json()
        assert ver_data["verified"] is True
        assert ver_data["payload_sha256"] == data["payload_sha256"]

def test_impeccable_template_clean():
    """Verify that impeccabe detect reports 0 anti-patterns on workbench.html."""
    tpl_path = Path(__file__).parent.parent / "src" / "ariadns" / "interfaces" / "templates" / "workbench.html"
    assert tpl_path.exists()

    res = subprocess.run(
        ["npx", "impeccable", "detect", str(tpl_path)],
        capture_output=True,
        text=True,
        shell=True
    )
    # exit code 0 indicates 0 primary anti-patterns
    assert res.returncode == 0, f"impeccable detect failed: {res.stderr}\n{res.stdout}"
