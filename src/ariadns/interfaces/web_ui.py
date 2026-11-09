"""Ariadns Local Web UI Forensic Workbench Interface."""

import http.server
import json
import os
import urllib.parse
import webbrowser
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional
from ariadns.models.config import AppConfig
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.modules.m6_reporting import render_evidence_artifacts
from ariadns.modules.m8_recommender import NextStepRecommender
from ariadns.storage.db import DatabaseManager
from ariadns.storage.forensic_verifier import verify_case_artifacts
from ariadns.utils.warninglist_sync import WarninglistSynchronizer

def load_template_html() -> str:
    """Load workbench single page HTML template from disk or fallback."""
    tpl_path = Path(__file__).parent / "templates" / "workbench.html"
    if tpl_path.exists():
        return tpl_path.read_text(encoding="utf-8")
    return "<html><body><h3>ARIADNS 網域公開情資分析平台</h3></body></html>"

class WorkbenchRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler serving the Ariadns Forensic Workbench."""

    orchestrator: Optional[Orchestrator] = None
    output_dir: str = "./reports"

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr HTTP request logging for clean CLI output."""
        pass

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error(self, status_code: int, message: str) -> None:
        self._send_json(status_code, {"status": "ERROR", "error": message})

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("", "/"):
            html = load_template_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        if path == "/api/status":
            self._handle_get_status(query)
            return

        if path == "/api/image":
            self._handle_get_image(query)
            return

        if path == "/api/verify":
            self._handle_get_verify(query)
            return

        self._send_error(404, "Not Found")

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            self._send_error(400, "Invalid JSON payload")
            return

        if path == "/api/step":
            self._handle_post_step(body)
            return

        if path == "/api/render":
            self._handle_post_render(body)
            return

        if path == "/api/sync-lists":
            self._handle_post_sync_lists(body)
            return

        self._send_error(404, "Not Found")

    def _get_orchestrator(self) -> Orchestrator:
        if WorkbenchRequestHandler.orchestrator is None:
            WorkbenchRequestHandler.orchestrator = Orchestrator()
        return WorkbenchRequestHandler.orchestrator

    def _handle_get_status(self, query: dict[str, list[str]]) -> None:
        session_id = query.get("session_id", [""])[0].strip()
        if not session_id:
            self._send_error(400, "Missing session_id parameter")
            return

        orch = self._get_orchestrator()
        db = orch.db
        props = db.get_normalized_propositions(session_id, rendered_only=False)
        logs = db.get_audit_logs(session_id)
        recs = NextStepRecommender(db, orch.config).recommend(session_id)
        warninglist_synced = db.get_warninglist_last_synced() is not None

        resp_data = {
            "status": "OK",
            "session_id": session_id,
            "active_module": "IDLE",
            "target": session_id,
            "progress": "READY",
            "elapsed_seconds": 0.0,
            "warninglist_synced": warninglist_synced,
            "propositions": [asdict(p) for p in props],
            "audit_logs": [asdict(l) for l in logs],
            "recommendations": [asdict(r) for r in recs],
        }
        self._send_json(200, resp_data)

    def _handle_post_step(self, body: dict[str, Any]) -> None:
        session_id = body.get("session_id", "").strip()
        module_name = body.get("module", "").strip().lower()
        target = body.get("target", session_id).strip()
        params = body.get("params", {})

        if not session_id or not module_name:
            self._send_error(400, "Missing session_id or module")
            return

        orch = self._get_orchestrator()
        try:
            audit_entry = orch.run_step(
                session_id=session_id,
                module_name=module_name,
                target=target,
                params=params
            )
            db = orch.db
            props = db.get_normalized_propositions(session_id, rendered_only=False)
            logs = db.get_audit_logs(session_id)
            recs = NextStepRecommender(db, orch.config).recommend(session_id)

            resp_data = {
                "status": "OK",
                "session_id": session_id,
                "step": asdict(audit_entry),
                "audit_logs": [asdict(l) for l in logs],
                "propositions": [asdict(p) for p in props],
                "recommendations": [asdict(r) for r in recs],
            }
            self._send_json(200, resp_data)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._send_error(500, f"Step execution failed: {str(e)}")

    def _handle_post_render(self, body: dict[str, Any]) -> None:
        session_id = body.get("session_id", "").strip()
        selected_prop_ids = body.get("selected_prop_ids")
        output_dir = body.get("output_dir", WorkbenchRequestHandler.output_dir)

        if not session_id:
            self._send_error(400, "Missing session_id")
            return

        orch = self._get_orchestrator()
        try:
            svg, png, md, manifest = render_evidence_artifacts(
                session_id=session_id,
                db=orch.db,
                output_dir=output_dir,
                selected_prop_ids=selected_prop_ids
            )
            logs = orch.db.get_audit_logs(session_id)

            resp_data = {
                "status": "OK",
                "session_id": session_id,
                "svg_url": f"/api/image?session_id={session_id}&type=svg",
                "png_url": f"/api/image?session_id={session_id}&type=png",
                "payload_sha256": manifest.payload_sha256,
                "manifest": manifest.__dict__,
                "verified": manifest.verified,
                "rendered_prop_ids": manifest.rendered_prop_ids,
                "excluded_prop_ids": manifest.excluded_prop_ids,
                "session_audit_logs": [l.__dict__ for l in logs],
            }
            self._send_json(200, resp_data)
        except Exception as e:
            self._send_error(500, f"Render failed: {str(e)}")

    def _handle_post_sync_lists(self, body: dict[str, Any]) -> None:
        orch = self._get_orchestrator()
        try:
            syncer = WarninglistSynchronizer(orch.db, orch.http_client, orch.config)
            status = syncer.ensure_warninglists_synced(force=True)
            self._send_json(200, {"status": "OK", "result": status.value, "synced": True})
        except Exception as e:
            self._send_error(500, f"Warninglist sync failed: {str(e)}")

    def _handle_get_image(self, query: dict[str, list[str]]) -> None:
        session_id = query.get("session_id", [""])[0].strip()
        img_type = query.get("type", ["svg"])[0].strip().lower()
        clean = session_id.replace(":", "_").replace("/", "_").replace("\\", "_").replace(".", "_")

        base_dir = Path(WorkbenchRequestHandler.output_dir)
        candidates = [
            base_dir / f"{clean}_evidence.{img_type}",
            base_dir / session_id / f"{clean}_evidence.{img_type}",
            base_dir / clean / f"{clean}_evidence.{img_type}",
            base_dir / clean / f"{clean}_evidence_dag.{img_type}",
        ]
        file_path = next((p for p in candidates if p.exists()), None)

        if not file_path:
            self._send_error(404, f"Image not found for session {session_id}")
            return

        content_type = "image/svg+xml" if img_type == "svg" else "image/png"
        data = file_path.read_bytes()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_get_verify(self, query: dict[str, list[str]]) -> None:
        case_dir = query.get("case_dir", [""])[0].strip()
        if not case_dir:
            self._send_error(400, "Missing case_dir parameter")
            return

        orch = self._get_orchestrator()
        res = verify_case_artifacts(case_dir, db=orch.db)
        self._send_json(200, res)

def start_web_ui(
    host: str = "127.0.0.1",
    port: int = 8000,
    db_path: Optional[str] = None,
    output_dir: str = "./reports",
    open_browser: bool = False
) -> http.server.HTTPServer:
    """Start local Web UI server."""
    config = AppConfig.load()
    if db_path:
        config.db_path = db_path
    db = DatabaseManager(config.db_path)
    WorkbenchRequestHandler.orchestrator = Orchestrator(config=config, db=db)
    WorkbenchRequestHandler.output_dir = output_dir

    server = http.server.ThreadingHTTPServer((host, port), WorkbenchRequestHandler)
    print(f"[*] Ariadns Forensic Workbench running at http://{host}:{port}/")

    if open_browser:
        webbrowser.open(f"http://{host}:{port}/")

    return server
