# 22: Normalized 4-Table Evidence, Audit & Warninglist Models and SQLite Schema

**What to build:** Add `WarninglistIndicator`, `SessionAuditEntry`, `NextStepRecommendation`, `ArtifactManifest`, and `PropositionNode.is_rendered` to `entities.py`, and expand `db.py` with the 4 normalized evidence/audit tables (`evidence_propositions`, `evidence_edges`, `evidence_custodians`, `session_audit_logs`) plus `warninglist_indicators` and `warninglist_metadata`.
**Blocked by:** `21-mcp-cli-evidence-integration`
**Target files:** `src/ariadns/models/entities.py`, `src/ariadns/storage/db.py`, `tests/test_22_normalized_evidence_db.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given two `PropositionNode` items (`F1` with `is_rendered=True` and `F_noise` with `is_rendered=False`), one edge `("F1", "C1")`, one `DataCustodian` on `C1`, and one `SessionAuditEntry` saved via `db.save_normalized_evidence("example.com", ...)` and `db.append_audit_log(...)`, When `db.get_rendered_propositions("example.com")` is called, Then only nodes with `is_rendered == 1` are returned (`F_noise` is excluded) and `db.get_audit_logs("example.com")` returns step sequence `1`.
- [ ] Given `db.execute_readonly_sql("SELECT premise_id, conclusion_id FROM evidence_edges WHERE session_id = 'example.com'")`, When executed, Then it returns `[{"premise_id": "F1", "conclusion_id": "C1"}]` without parsing JSON arrays.

## Deterministic Verification
- Unit test path: `tests/test_22_normalized_evidence_db.py`
- Mutation target: `src/ariadns/storage/db.py`, `src/ariadns/models/entities.py`
- Mutants to kill:
  - Removing `WHERE is_rendered = 1` filter in `get_rendered_propositions` must turn tests red.
  - Omitting `evidence_edges` insertion during `save_normalized_evidence` must turn tests red.
