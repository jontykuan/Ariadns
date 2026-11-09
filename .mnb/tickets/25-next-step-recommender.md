# 25: Rule-Based Next-Step Investigation Recommender (M8)

**What to build:** Implement `NextStepRecommender` in `src/ariadns/modules/m8_recommender.py` that inspects the current session's normalized propositions (`evidence_propositions`) and executed steps (`session_audit_logs`) to output prioritized `NextStepRecommendation` records ("Because Fact A and B exist, run Step X on Target Y to obtain Evidence Z").
**Blocked by:** `24-stepwise-session-audit`
**Target files:** `src/ariadns/modules/m8_recommender.py`, `tests/test_25_next_step_recommender.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given session `"case_cdn"` where `F1` indicates `CDN:True` and `session_audit_logs` only has `m1`, When `recommender.recommend("case_cdn")` runs, Then it returns recommendations including `REC_ENUM_SUBDOMAINS` (`recommended_module="m2"`) and `REC_ORIGIN_COLLISION` (`recommended_module="m3"`).
- [ ] Given session `"case_leak"` where `M2` discovered unproxied subdomain IP `"47.129.246.64"` and no `m1` or `m4` step has targeted `"47.129.246.64"`, When `recommender.recommend("case_leak")` runs, Then it returns `REC_PROBE_UNPROXIED_IP` targeting `"47.129.246.64"` citing the triggering subdomain fact ID.

## Deterministic Verification
- Unit test path: `tests/test_25_next_step_recommender.py`
- Mutation target: `src/ariadns/modules/m8_recommender.py`
- Mutants to kill:
  - Recommending a module+target pair already present in `session_audit_logs` must turn tests red.
  - Omitting `trigger_fact_ids` in `NextStepRecommendation` must turn tests red.
