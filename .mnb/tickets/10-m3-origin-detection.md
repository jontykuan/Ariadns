# 10: Module 3 — Passive DNS History & Host Header Origin Collision

**What to build:** Query VirusTotal v3 `historical_dns` and AlienVault OTX for pre-CDN `CandidateOriginIP` records, and validate origin authenticity by comparing HTTP `Host: <domain>` responses (Title, Favicon hash, TLS CN/SAN) against live `DomainL1`.
**Blocked by:** `08-m1-banner-tls-portscan`, `09-m2-subdomain-enumerator`
**Target files:** `src/ariadns/modules/m3_origin.py`, `tests/test_10_m3_origin.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given a domain currently on Cloudflare (`104.21.23.45`) with historical pDNS IP `"198.51.100.24"`, When `"198.51.100.24"` responds to `Host: example.com` with matching Title or TLS SAN, Then `suspected_origin_ip` is set to `"198.51.100.24"` and `origin_verification_status` is `"CONFIRMED"`.
- [ ] Given a second run on the same domain within 7 days, When `detect_origin()` executes, Then VirusTotal/OTX results are served from SQLite cache with `0` external API calls.

## Deterministic Verification
- Unit test path: `tests/test_10_m3_origin.py`
- Mutation target: `src/ariadns/modules/m3_origin.py`
