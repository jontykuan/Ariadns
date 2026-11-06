# 12: Module 5 — Noise Filter, Graph Orchestrator & L1->L2 Recursion Controller

**What to build:** Orchestrate M1..M4, block blacklisted MX/NS (`aspmx.l.google.com`, `cloudflare.com`) and Shared IPs (`> 100` domains), populate the SQLite/NetworkX property graph, run automatic lightweight L2 probes on `ConfidenceLevel.HIGH` domains (`--depth 2`), and support on-demand deep L2 expansion.
**Blocked by:** `04-property-graph-store`, `10-m3-origin-detection`, `11-m4-pivoting-engine`
**Target files:** `src/ariadns/modules/m5_orchestrator.py`, `tests/test_12_m5_orchestrator.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a domain using `"aspmx.l.google.com"`, When orchestrated, Then Reverse MX is blocked and logs `"觸發公共服務黑名單，跳過反查"` (`ModuleStatus.SKIPPED_BLACKLIST`).
- [ ] Given an IP returning 150 reverse domains, When evaluated by Module 5, Then the IP is marked `SHARED_HOSTING` and excluded from L2 recursion.
- [ ] Given two consecutive full runs on the same domain, When the second run completes, Then `external_api_calls` equals `0`.

## Deterministic Verification
- Unit test path: `tests/test_12_m5_orchestrator.py`
- Mutation target: `src/ariadns/modules/m5_orchestrator.py`
