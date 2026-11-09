# 23: 7-Day Lazy Warninglist Synchronizer (MISP & Freemail False-Positive Filter)

**What to build:** Implement `WarninglistSynchronizer` in `src/ariadns/utils/warninglist_sync.py` that checks `warninglist_metadata.last_synced_at` on startup; if missing or older than `604800` seconds (7 days), fetches open-source MISP (`parking-domain-ns`, `parking-domain`, `common-contact-emails`) and `free-email-domains` feeds into `warninglist_indicators` (falling back gracefully to cached/static baseline on timeout), and integrates indicator lookup into `PivotingEngine`.
**Blocked by:** `22-normalized-evidence-audit-db`
**Target files:** `src/ariadns/utils/warninglist_sync.py`, `src/ariadns/modules/m4_pivoting.py`, `tests/test_23_lazy_warninglist_sync.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria (Deterministic Contracts)
- [ ] Given `warninglist_metadata` has `last_synced_at = current_epoch - 100` (< 7 days), When `ensure_warninglists_synced()` runs, Then return status equals `ModuleStatus.CACHED` and `external_api_calls` equals `0`.
- [ ] Given `warninglist_metadata` has `last_synced_at = current_epoch - 700000` (> 7 days) and mock feed returns `"parking.namecheap.com"` and `"privateemail.com"`, When `ensure_warninglists_synced()` runs and `pivoting.reverse_mx("mx1.privateemail.com")` is called, Then `reverse_mx` returns `[]` with zero external pivot API requests.
- [ ] Given network timeout during sync, When `ensure_warninglists_synced()` runs, Then it returns `ModuleStatus.FALLBACK_NATIVE` without raising an exception.

## Deterministic Verification
- Unit test path: `tests/test_23_lazy_warninglist_sync.py`
- Mutation target: `src/ariadns/utils/warninglist_sync.py`, `src/ariadns/modules/m4_pivoting.py`
- Mutants to kill:
  - Flipping `now - last_synced > 604800` to `<` must turn tests red.
  - Bypassing `is_indicator_blacklisted` check in `m4_pivoting.py` must turn tests red.
