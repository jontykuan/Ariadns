# 13: Module 6 — Reporting Engine (`result.json`, `topology.json`, `report.md`)

**What to build:** Export SRS Section 5.2 compliant `result.json`, Cytoscape.js/D3.js `topology.json`, and human-readable Markdown assessment report (`report.md`) containing identity profile, origin inference, and confidence-ranked L2 domains.
**Blocked by:** `12-m5-orchestrator-l2`
**Target files:** `src/ariadns/modules/m6_reporting.py`, `tests/test_13_m6_reporting.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a completed `InvestigationResult` and session graph, When `export_all()` is called, Then `result.json`, `topology.json`, and `report.md` are written to `output_dir` with valid schema and confidence badges (`HIGH`/`MEDIUM`/`LOW`).

## Deterministic Verification
- Unit test path: `tests/test_13_m6_reporting.py`
- Mutation target: `src/ariadns/modules/m6_reporting.py`
