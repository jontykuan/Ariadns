# 04: Heterogeneous Property Graph Store (`SQLite` + `NetworkX`)

**What to build:** Persist `graph_nodes` and `graph_edges` in SQLite and synchronize with an in-memory `networkx` graph to compute node degree (`In-Degree > 100`), L2 confidence scores, shortest paths, and Cytoscape/D3 topology dicts.
**Blocked by:** `03-sqlite-cache-quota`
**Target files:** `src/ariadns/storage/graph_store.py`, `tests/test_04_graph_store.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a candidate `DomainL2` connected to `DomainL1` via `SAME_ORIGIN_IP` ($w=0.7$), When `score_l2_domain()` is evaluated, Then score is $0.7 \ge 0.6$ and `ConfidenceLevel.HIGH` is returned.
- [ ] Given an IP node with 101 connected domain edges, When `is_shared_hosting_ip()` is called, Then it returns `True` (degree $> 100$).
- [ ] Given a populated session graph, When `export_topology()` is called, Then it outputs valid `nodes` and `edges` arrays compatible with Cytoscape.js / D3.js.

## Deterministic Verification
- Unit test path: `tests/test_04_graph_store.py`
- Mutation target: `src/ariadns/storage/graph_store.py`
