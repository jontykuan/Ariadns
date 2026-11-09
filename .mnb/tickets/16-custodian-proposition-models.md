# 16: PropositionNode, DataCustodian & Enhanced Fingerprint Models

**What to build:** Add `PropositionKind`, `DataCustodian`, and `PropositionNode` models, and extend `IdentityProfile` (`registrar_name`, `html_tracking_tokens`), `Infrastructure` (`asn`, `asn_org_name`, `country`, `favicon_sha256`), `L2Result` (`registrar_name`, `asn_org_name`), and `InvestigationResult` (`evidence_chain`).
**Blocked by:** None (frontier)
**Target files:** `src/ariadns/models/enums.py`, `src/ariadns/models/entities.py`, `tests/test_16_evidence_models.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a `PropositionNode` with `DataCustodian` entries attached to `InvestigationResult`, When `.to_dict()` is called, Then `evidence_chain` serializes `prop_id`, `node_kind`, `rank`, `premises`, `rule_name`, `statement`, `target_entity`, and `custodians`.
- [ ] Given `IdentityProfile` and `Infrastructure`, When instantiated with `registrar_name`, `html_tracking_tokens`, `asn_org_name`, and `favicon_sha256`, Then backward compatibility with SRS 5.2 fields is preserved.

## Deterministic Verification
- Unit test path: `tests/test_16_evidence_models.py`
- Mutation target: `src/ariadns/models/entities.py`
