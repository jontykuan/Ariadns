# 05: Sliding-Window Rate Limiter & Exponential Backoff HTTP Client

**What to build:** Enforce `>= 1.5s` delay on keyless endpoints, `<= 4 req/min` (`15s` interval) & `<= 500/day` on VirusTotal, and `2s, 4s, 8s` exponential backoff on HTTP `429`/`504`.
**Blocked by:** `02-config-secret-masking`, `03-sqlite-cache-quota`
**Target files:** `src/ariadns/utils/__init__.py`, `src/ariadns/utils/rate_limiter.py`, `tests/test_05_rate_limiter.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given an upstream endpoint returning HTTP `429` or `504`, When `fetch_with_backoff()` is called, Then it retries up to 3 times with `2.0s`, `4.0s`, `8.0s` backoff intervals and returns `ModuleStatus.TIMEOUT_UNVERIFIED` on exhaustion without raising an unhandled exception.
- [ ] Given VirusTotal quota reaching 4 calls within 60 seconds or 500 calls in a day, When a 5th/501st call is requested, Then the rate limiter throttles or returns `ModuleStatus.SKIPPED_QUOTA`.

## Deterministic Verification
- Unit test path: `tests/test_05_rate_limiter.py`
- Mutation target: `src/ariadns/utils/rate_limiter.py`
