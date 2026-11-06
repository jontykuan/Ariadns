# 07: Module 1A — Local DNS Deep Resolver, SOA Email & TXT Token Parser

**What to build:** Query A, AAAA, CNAME, MX, NS, TXT, SOA via `dnspython`, convert SOA `RNAME` (handling escaped `\.`) to standard email, extract verification tokens, and query RDAP/Whois identity.
**Blocked by:** `05-rate-limiter-http-client`, `06-asn-cdn-tool-doctor`
**Target files:** `src/ariadns/modules/__init__.py`, `src/ariadns/modules/m1_local_probe.py`, `tests/test_07_m1_dns.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given SOA RNAME `"admin.example.com."` and `"first\.last.example.com."`, When `parse_soa_rname()` is called, Then it returns `"admin@example.com"` and `"first.last@example.com"` respectively.
- [ ] Given TXT records containing `"v=spf1 ..."` and `"google-site-verification=abcdef123456"`, When `extract_verification_tokens()` is called, Then it returns `{"google": "google-site-verification=abcdef123456"}`.

## Deterministic Verification
- Unit test path: `tests/test_07_m1_dns.py`
- Mutation target: `src/ariadns/modules/m1_local_probe.py`
