# 09: Module 2 — Passive Subdomain Enumeration & Live HTTP Probing

**What to build:** Enumerate subdomains via `crt.sh` JSON API (cached + rate-limited) and `subfinder` CLI wrapper, then probe liveness/IP/title/server via `httpx` CLI or native Python fallback.
**Blocked by:** `05-rate-limiter-http-client`, `06-asn-cdn-tool-doctor`
**Target files:** `src/ariadns/modules/m2_subdomain.py`, `tests/test_09_m2_subdomain.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given `crt.sh` JSON output containing wildcard `"*.api.example.com"` and `"dev.example.com"`, When parsed and deduplicated, Then normalized hostnames `["api.example.com", "dev.example.com"]` are piped to the prober.
- [ ] Given live subdomain responses, When probed via `httpx` or native fallback, Then structured `SubdomainRecord(subdomain, ip, status_code, title, server)` objects are returned and cached in SQLite.

## Deterministic Verification
- Unit test path: `tests/test_09_m2_subdomain.py`
- Mutation target: `src/ariadns/modules/m2_subdomain.py`
