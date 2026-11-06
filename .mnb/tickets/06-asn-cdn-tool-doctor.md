# 06: Zero-Quota CDN ASN Detector & External Binary Runner (`doctor`)

**What to build:** Identify CDN IPs via local CIDR ranges and Team Cymru DNS (`origin.asn.cymru.com`), and detect/execute `subfinder`, `httpx`, `nmap` with `5.0s` timeout and native fallback reporting.
**Blocked by:** `01-domain-models-enums`, `03-sqlite-cache-quota`
**Target files:** `src/ariadns/utils/asn_cdn.py`, `src/ariadns/utils/tool_runner.py`, `tests/test_06_asn_and_tools.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given IP `"104.21.23.45"` (Cloudflare `AS13335`), When `detect_cdn(ip)` is called, Then it returns `(True, "Cloudflare", "AS13335")` with zero external HTTP API calls.
- [ ] Given an environment where `subfinder` or `httpx` is absent from `PATH`, When `check_environment()` or `run_external_tool()` is called, Then it reports `ModuleStatus.FALLBACK_NATIVE` instead of crashing.

## Deterministic Verification
- Unit test path: `tests/test_06_asn_and_tools.py`
- Mutation target: `src/ariadns/utils/asn_cdn.py`, `src/ariadns/utils/tool_runner.py`
