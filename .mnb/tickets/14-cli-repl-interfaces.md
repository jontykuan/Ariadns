# 14: Dual-Mode CLI, Interactive REPL, `recon.py` & Cross-Platform Installers

**What to build:** Implement `ariadns` CLI (`run`, `probe`, `subdomain`, `origin`, `pivot`, `expand`, `report`, `repl`, `doctor`, `init`, `register-mcp`), SRS-compatible `recon.py` entrypoint, interactive REPL console for selecting L2 nodes to expand, and tool installation scripts (`scripts/install_tools.sh`, `scripts/install_tools.ps1`).
**Blocked by:** `13-m6-reporting-engine`
**Target files:** `src/ariadns/interfaces/__init__.py`, `src/ariadns/interfaces/cli.py`, `src/ariadns/interfaces/repl.py`, `recon.py`, `scripts/install_tools.sh`, `scripts/install_tools.ps1`, `tests/test_14_cli_repl.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given CLI invocation `python recon.py -d example.com --depth 2 --output-dir ./reports/ --no-portscan`, When executed, Then it runs the full pipeline and writes reports to `./reports/`.
- [ ] Given interactive REPL commands to list L2 candidates and expand a selected L2 domain, When executed, Then the selected L2 domain undergoes deep probing and updates the session graph.

## Deterministic Verification
- Unit test path: `tests/test_14_cli_repl.py`
- Mutation target: `src/ariadns/interfaces/cli.py`, `src/ariadns/interfaces/repl.py`
