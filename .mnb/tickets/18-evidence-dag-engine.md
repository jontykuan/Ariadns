# 18: Chained Propositional Evidence DAG & Data Custodian Mapper

**What to build:** Implement `EvidenceChainDAG` in `src/ariadns/storage/evidence_dag.py` supporting base Facts (`rank=0`), chained Conclusions (`rank = 1 + max(rank(premises))`), cycle rejection, Mermaid flowchart generation, and deterministic `DataCustodian` mapping for Domain, IP (CDN/Origin), Email/MX, and Token nodes.
**Blocked by:** `16-custodian-proposition-models`
**Target files:** `src/ariadns/storage/evidence_dag.py`, `tests/test_18_evidence_dag.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given Base Facts $F_1, F_2$ (`rank=0`), When Conclusion $C_1$ is derived from $[F_1, F_2]$ and Conclusion $C_2$ is derived from $[C_1, F_3]$, Then $\text{rank}(C_1) == 1$, $\text{rank}(C_2) == 2$, and `is_valid_dag()` returns `True`.
- [ ] Given a Conclusion node for a Domain, Origin IP, or Google Token, When `map_custodians_for_node()` runs, Then it attaches the corresponding `DataCustodian` (`Registrar`/`NS`, `ASN Org`, or `Google LLC`) and its queryable record types.

## Deterministic Verification
- Unit test path: `tests/test_18_evidence_dag.py`
- Mutation target: `src/ariadns/storage/evidence_dag.py`
