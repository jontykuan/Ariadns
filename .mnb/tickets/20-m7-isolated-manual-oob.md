# 20: Module 7 — Isolated Manual-Only OOB Callback Verifier

**What to build:** Implement `src/ariadns/modules/m7_manual_oob.py` providing human-invoked callback trigger verification (`trigger_manual_oob`), strictly isolated from automatic scans and gated by `acknowledge_opsec_risk: bool`.
**Blocked by:** `18-evidence-dag-engine`
**Target files:** `src/ariadns/modules/m7_manual_oob.py`, `tests/test_20_m7_manual_oob.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given `acknowledge_opsec_risk=False`, When `trigger_manual_oob()` is called, Then it refuses to send any network request and returns an explicit OPSEC risk warning.
- [ ] Given `acknowledge_opsec_risk=True` and a target endpoint + callback URL, When invoked manually, Then it sends the probe with `timeout=5.0s` and records the manual OOB observation in SQLite.

## Deterministic Verification
- Unit test path: `tests/test_20_m7_manual_oob.py`
- Mutation target: `src/ariadns/modules/m7_manual_oob.py`
