# 28: Local Web UI Forensic Workbench (Impeccable Design System & CLI Wrapper)

**What to build:** Establish `DESIGN.md` following `impeccable` forensic high-density design tokens (zero AI slop, utilitarian dark/light contrast, monospace evidence hashes) and implement `src/ariadns/interfaces/web_ui.py` (`ariadns ui`) serving the Local Web Workbench: (1) lightweight status bar (active module, target, stage progress, elapsed time, warninglist sync status), (2) visual CLI command cards with purpose & OPSEC descriptions, (3) Next-Step Investigation Recommendations panel, (4) node selection filter checkboxes (pre-selecting core nodes), and (5) on-demand static SVG/PNG evidence graph + structured Custodian & Session Audit Log tables with SHA-256 verification badge.
**Blocked by:** `27-cli-mcp-tri-parity`
**Target files:** `DESIGN.md`, `src/ariadns/interfaces/web_ui.py`, `src/ariadns/interfaces/cli.py`, `tests/test_28_web_ui_workbench.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given the Web UI WSGI/HTTP handler in `web_ui.py`, When `GET /api/status?session_id=example.com` and `POST /api/step` (`{"session_id": "example.com", "module": "m1", "target": "example.com"}`) are called, Then the response returns current execution status (active module, target, progress, elapsed seconds), updated audit log entries, and `NextStepRecommendation` items without auto-rendering the graph image.
- [ ] Given `POST /api/render` with `selected_prop_ids`, When called, Then it generates the static `.svg`/`.png` and returns the static image URL, `payload_sha256`, `ArtifactManifest`, and `verified: True` status; and running `impeccable detect` against the UI template reports `0` critical anti-pattern violations.

## Deterministic Verification
- Unit test path: `tests/test_28_web_ui_workbench.py`
- Mutation target: `src/ariadns/interfaces/web_ui.py`
- Mutants to kill:
  - Auto-rendering the static graph during `POST /api/step` must turn tests red.
  - Omitting `payload_sha256` or `session_audit_logs` from the UI render payload must turn tests red.
