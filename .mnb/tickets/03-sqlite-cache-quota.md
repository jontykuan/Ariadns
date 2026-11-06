# 03: SQLite 7-Day TTL Cache, Quota Tracker & Read-Only SQL

**What to build:** SQLite persistence (`ariadns_state.db`) for `dns_cache`, `ip_pivot_cache`, `api_quota_tracker`, `investigation_sessions`, and guarded read-only SQL execution (`mode=ro`).
**Blocked by:** `01-domain-models-enums`
**Target files:** `src/ariadns/storage/__init__.py`, `src/ariadns/storage/db.py`, `tests/test_03_sqlite_cache.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a cached DNS or Pivot record stored with `ttl_seconds=604800`, When queried within 7 days, Then `get_cache()` returns the payload with `ModuleStatus.CACHED` and `0` external calls.
- [ ] Given an expired cache entry (`expires_at < now`), When queried, Then `get_cache()` returns `None`.
- [ ] Given a destructive query `"DROP TABLE dns_cache"` or `"DELETE FROM dns_cache"` passed to `execute_readonly_sql()`, When executed, Then it raises a `ValueError`/`sqlite3.OperationalError` and leaves tables intact.

## Deterministic Verification
- Unit test path: `tests/test_03_sqlite_cache.py`
- Mutation target: `src/ariadns/storage/db.py`
