# 15: FastMCP Server (`ariadns-mcp`) & Local Agent Registration

**What to build:** Implement MCP stdio server exposing 4 summary-first tools (`osint_scan`, `osint_inspect`, `osint_expand`, `osint_report`) and `ariadns://` graph resources, plus automatic local MCP registration (`ariadns register-mcp`).
**Blocked by:** `13-m6-reporting-engine`
**Target files:** `src/ariadns/interfaces/mcp_server.py`, `tests/test_15_mcp_server.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given MCP tool call `osint_scan(domain="example.com", mode="full")`, When executed, Then full raw data is stored in SQLite and a compact digest (`<= 600` tokens) is returned.
- [ ] Given MCP tool call `osint_inspect(domain="example.com", query_type="neighbors", target_node="IP:198.51.100.24")` or `query_type="sql"`, When executed, Then graph neighbors or read-only SQL rows are returned deterministically.

## Deterministic Verification
- Unit test path: `tests/test_15_mcp_server.py`
- Mutation target: `src/ariadns/interfaces/mcp_server.py`
