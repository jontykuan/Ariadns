# 11: Module 4 — Multi-Dimensional Pivoting Engine (Pluggable Providers)

**What to build:** Perform Reverse IP, Reverse MX/NS, and Reverse Whois/Token lookups via free providers (HackerTarget, ViewDNS, OTX) and optional key-configured providers, caching all results in `ip_pivot_cache`.
**Blocked by:** `05-rate-limiter-http-client`, `07-m1-local-dns-identity`
**Target files:** `src/ariadns/modules/m4_pivoting.py`, `tests/test_11_m4_pivoting.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a confirmed non-CDN origin IP `"198.51.100.24"`, When `pivot_reverse_ip()` runs, Then co-hosted domains are returned and stored in `ip_pivot_cache`.
- [ ] Given Reverse Whois or Token lookup when no paid provider API key is configured, When invoked, Then it gracefully returns `ModuleStatus.SKIPPED_NO_KEY` (or matches existing local SQLite graph tokens/emails) without failing.

## Deterministic Verification
- Unit test path: `tests/test_11_m4_pivoting.py`
- Mutation target: `src/ariadns/modules/m4_pivoting.py`
