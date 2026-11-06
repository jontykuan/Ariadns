# 08: Module 1B — HTTP Banner Grabber, TLS Cert CN/SAN & Optional Port Scanner

**What to build:** Send `HEAD / HTTP/1.1` with forced `Host: <target_domain>` (`timeout=5.0s`) to capture `Server`/`X-Powered-By`/`Set-Cookie`, extract TLS 443 CN & SANs, and optionally scan ports `[21, 22, 25, 80, 443, 3306, 8080, 8443]` on non-CDN IPs.
**Blocked by:** `07-m1-local-dns-identity`
**Target files:** `src/ariadns/modules/m1_local_probe.py`, `tests/test_08_m1_banner_tls_ports.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given an HTTP server responding with `Server: nginx/1.18.0`, When `grab_http_banner()` runs with `timeout=5.0s`, Then `server_banner` and headers are captured, and unresponsive hosts time out cleanly within `5.0s`.
- [ ] Given `is_cdn=True`, When port scanning is requested, Then port scanning is skipped automatically per SRS Module 1.3.

## Deterministic Verification
- Unit test path: `tests/test_08_m1_banner_tls_ports.py`
- Mutation target: `src/ariadns/modules/m1_local_probe.py`
