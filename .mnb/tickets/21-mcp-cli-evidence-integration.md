# 21: CLI, REPL & FastMCP Integration for Evidence Chain & Manual OOB

**What to build:** Expose `evidence_chain` and `custodians` inspection in `osint_inspect`, `evidence_chain_json` path in `osint_report`, `osint_manual_oob` in `mcp_server.py`, and `manual-oob` / `evidence` commands in `cli.py` and `repl.py`.
**Blocked by:** `19-m5-m6-causal-evidence-report`, `20-m7-isolated-manual-oob`
**Target files:** `src/ariadns/interfaces/cli.py`, `src/ariadns/interfaces/repl.py`, `src/ariadns/interfaces/mcp_server.py`, `tests/test_21_interfaces_evidence.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given MCP call `osint_inspect(domain="example.com", query_type="evidence_chain")` or `query_type="custodians"`, When executed, Then it returns the ordered propositions (`FACT` -> `CONCLUSION`) and custodian mappings from the session.
- [ ] Given CLI invocation `ariadns manual-oob -d example.com --target-url https://example.com/webhook --callback-url https://canary.example.net/123` without `--ack-risk`, When executed, Then it prints the OPSEC warning and exits without sending requests.

## Deterministic Verification
- Unit test path: `tests/test_21_interfaces_evidence.py`
- Mutation target: `src/ariadns/interfaces/mcp_server.py`, `src/ariadns/interfaces/cli.py`
