# 26: Deterministic Static Evidence Graph Renderer (SVG/PNG) & Dual-Layer Forensic Verifier

**What to build:** Implement pure-Python deterministic hierarchical `.svg` and `.png` static evidence graph rendering in `m6_reporting.py` (supporting pre-render node selection `selected_prop_ids`, fixed non-draggable coordinates, embedded `payload_sha256` watermark stamp, and a full `SessionAuditEntry` + `ArtifactManifest` table in `report.md`), plus `verify_case_artifacts(case_dir)` in `src/ariadns/storage/forensic_verifier.py`.
**Blocked by:** `24-stepwise-session-audit`
**Target files:** `src/ariadns/modules/m6_reporting.py`, `src/ariadns/storage/forensic_verifier.py`, `tests/test_26_static_graph_and_verifier.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given session `"case_verify"` with propositions `F1`, `F_excluded`, `C1` where `selected_prop_ids=["F1", "C1"]`, When `render_evidence_artifacts(session_id="case_verify", output_dir=tmp_dir, selected_prop_ids=["F1", "C1"])` runs, Then it writes `<session>_evidence.svg`, `<session>_evidence.png`, `<session>_manifest.json`, and `<session>_report.md` containing the `payload_sha256` stamp and audit log table, and `F_excluded` is absent from the rendered SVG.
- [ ] Given unmodified artifacts in `tmp_dir`, When `verify_case_artifacts(tmp_dir)` runs, Then `verified` equals `True` and `mismatches` equals `[]`.
- [ ] Given a 1-byte modification to `<session>_evidence.svg` or tampering of a statement in `<session>_evidence_chain.json`, When `verify_case_artifacts(tmp_dir)` runs, Then `verified` equals `False` and `mismatches` lists the tampered file or payload hash mismatch.

## Deterministic Verification
- Unit test path: `tests/test_26_static_graph_and_verifier.py`
- Mutation target: `src/ariadns/modules/m6_reporting.py`, `src/ariadns/storage/forensic_verifier.py`
- Mutants to kill:
  - Returning `verified=True` when `payload_sha256` differs from recomputed canonical DAG + audit hash must turn tests red.
  - Rendering propositions with `is_rendered == False` into the SVG must turn tests red.
