"""Forensic Verification Utility for Case Artifacts and Evidence Manifests."""

import hashlib
import json
from pathlib import Path
from typing import Any, Optional
from ariadns.models.entities import ArtifactManifest
from ariadns.storage.db import DatabaseManager

def compute_file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def verify_case_artifacts(case_dir: str | Path, db: Optional[DatabaseManager] = None) -> dict[str, Any]:
    case_path = Path(case_dir)
    manifest_files = list(case_path.glob("*_manifest.json"))
    if not manifest_files:
        return {
            "session_id": "",
            "verified": False,
            "payload_sha256": "",
            "mismatches": ["No manifest file found in case directory."],
        }

    manifest_path = manifest_files[0]
    with open(manifest_path, "r", encoding="utf-8") as f:
        m_data = json.load(f)

    session_id = m_data.get("session_id", "")
    expected_payload_sha256 = m_data.get("payload_sha256", "")
    file_hashes: dict[str, str] = m_data.get("file_hashes", {})

    mismatches: list[str] = []

    # Verify physical file hashes
    for filename, expected_hash in file_hashes.items():
        file_path = case_path / filename
        if not file_path.exists():
            mismatches.append(f"Missing artifact file: {filename}")
            continue
        actual_hash = compute_file_sha256(file_path)
        if actual_hash != expected_hash:
            mismatches.append(f"Hash mismatch on {filename}: expected {expected_hash}, got {actual_hash}")

    # Recompute payload SHA-256 if DB or manifest data is available
    if db:
        rendered_props = db.get_normalized_propositions(session_id, rendered_only=True)
        rendered_edges = db.get_normalized_edges(session_id)
        rendered_ids = {p.prop_id for p in rendered_props}
        filtered_edges = [(u, v) for u, v in rendered_edges if u in rendered_ids and v in rendered_ids]
        logs = db.get_audit_logs(session_id)

        payload_obj = {
            "session_id": session_id,
            "rendered_propositions": [{"id": p.prop_id, "rank": p.rank, "statement": p.statement} for p in rendered_props],
            "edges": filtered_edges,
            "audit_logs": [{"step": l.step_seq, "module": l.module_name, "target": l.target, "time": l.timestamp} for l in logs]
        }
        recomputed_payload_hash = hashlib.sha256(json.dumps(payload_obj, sort_keys=True).encode("utf-8")).hexdigest()
        if recomputed_payload_hash != expected_payload_sha256:
            mismatches.append(f"Payload DAG hash mismatch: expected {expected_payload_sha256}, got {recomputed_payload_hash}")

    verified = len(mismatches) == 0
    return {
        "session_id": session_id,
        "verified": verified,
        "payload_sha256": expected_payload_sha256,
        "mismatches": mismatches,
    }
