# 19: Orchestrator & Reporting Engine — Causal Evidence DAG & Custodian Tables

**What to build:** Assemble the `EvidenceChainDAG` in `m5_orchestrator.py` across L1 observations, Origin confirmation, Pivot correlations, and L2 probes; export `<domain>_evidence_chain.json` and render the `ARCHITECTURE.md`-style Mermaid Evidence DAG (`因為 A 和 B 所以 C`) + `C 可查節點與對應資料管理源` section in `m6_reporting.py`.
**Blocked by:** `17-asn-org-registrar-custodian`, `18-evidence-dag-engine`
**Target files:** `src/ariadns/modules/m5_orchestrator.py`, `src/ariadns/modules/m6_reporting.py`, `tests/test_19_causal_report.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given an orchestrated investigation with L1 facts, confirmed origin IP, and correlated L2 domain, When `run_investigation()` and `export_all()` complete, Then `result.evidence_chain` is populated and `<domain>_evidence_chain.json` is written to disk.
- [ ] Given the generated `<domain>_report.md`, When inspected, Then it contains a layered `mermaid` `flowchart TD` diagram showing `Rank 0 Facts -> Rank 1..N Conclusions -> Data Custodians` and a structured table mapping each Conclusion $C$ to its queryable nodes and data custodians.

## Deterministic Verification
- Unit test path: `tests/test_19_causal_report.py`
- Mutation target: `src/ariadns/modules/m5_orchestrator.py`, `src/ariadns/modules/m6_reporting.py`
