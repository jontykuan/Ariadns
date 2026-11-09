# 24: Case Session Stepwise Execution & Incremental Fact Merging

**What to build:** Add `run_step(session_id, module_name, target, params)` to `Orchestrator` (`m5_orchestrator.py`) so individual modules (`m1`, `m2`, `m3`, `m4`, `m7`) can be executed incrementally against a persistent case session, merging newly discovered facts into the normalized SQLite tables and appending an immutable `SessionAuditEntry` with step sequence, timestamp, added fact IDs, and state SHA-256 without automatically rendering the graph image.
**Blocked by:** `22-normalized-evidence-audit-db`, `23-lazy-warninglist-sync`
**Target files:** `src/ariadns/modules/m5_orchestrator.py`, `tests/test_24_stepwise_session_audit.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given a clean session `"case_example"`, When `orchestrator.run_step("case_example", "m1", "example.com")` followed by `orchestrator.run_step("case_example", "m2", "example.com")` are invoked, Then `session_audit_logs` contains exactly 2 ordered entries (`step_seq` 1 and 2) with non-empty `added_fact_ids` and `artifact_sha256`, and both M1 and M2 propositions coexist in `evidence_propositions`.
- [ ] Given `run_step` execution, When completed, Then no static `.svg` or `.png` file is generated until `render_graph` is explicitly called.

## Deterministic Verification
- Unit test path: `tests/test_24_stepwise_session_audit.py`
- Mutation target: `src/ariadns/modules/m5_orchestrator.py`
- Mutants to kill:
  - Overwriting existing session propositions instead of merging prior step facts must turn tests red.
  - Failing to increment `step_seq` in `session_audit_logs` must turn tests red.
