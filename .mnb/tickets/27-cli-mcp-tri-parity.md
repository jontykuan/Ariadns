# 27: CLI & FastMCP Tri-Parity (Normalized Read, Stepwise, Recommend, Render & Verify)

**What to build:** Update `mcp_server.py` and `cli.py` so `osint_inspect` (`evidence_chain` / `custodians`) and new tool `osint_read_evidence_graph` query the normalized SQLite tables directly (`WHERE is_rendered = 1`, zero duplicate `run_investigation()` calls), and expose symmetric commands/tools: `step` / `osint_run_step`, `recommend` / `osint_recommend_next`, `render-graph` / `osint_render_graph`, `show-graph` / `osint_read_evidence_graph`, `verify` / `osint_verify_case`, and `sync-lists` / `osint_sync_lists`.
**Blocked by:** `25-next-step-recommender`, `26-static-graph-renderer-verifier`
**Target files:** `src/ariadns/interfaces/mcp_server.py`, `src/ariadns/interfaces/cli.py`, `tests/test_27_cli_mcp_parity.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given a populated session `"example.com"` in SQLite, When `osint_inspect(domain="example.com", query_type="evidence_chain")` or `osint_read_evidence_graph(session_id="example.com")` is invoked, Then it returns only rendered propositions (`is_rendered=1`), `payload_sha256`, and audit summary from SQLite with `0` invocations of `orchestrator.run_investigation`.
- [ ] Given CLI invocations `ariadns step -d example.com -m m1`, `ariadns recommend -d example.com`, `ariadns render-graph -d example.com --output-dir <dir>`, and `ariadns verify --case-dir <dir>`, When executed sequentially, Then all exit with code `0` and `verify` outputs `"VERIFIED: TRUE"`.

## Deterministic Verification
- Unit test path: `tests/test_27_cli_mcp_parity.py`
- Mutation target: `src/ariadns/interfaces/mcp_server.py`, `src/ariadns/interfaces/cli.py`
- Mutants to kill:
  - Calling `run_investigation()` inside `osint_inspect` when session rows exist in `evidence_propositions` must turn tests red.
  - Returning unrendered propositions (`is_rendered=0`) by default in `osint_read_evidence_graph` must turn tests red.
