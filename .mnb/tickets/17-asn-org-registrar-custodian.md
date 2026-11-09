# 17: ASN Org Name, RDAP Registrar, Favicon SHA-256 & HTML Tracking Token Prober

**What to build:** Resolve ASN organization name and country via Team Cymru DNS (`AS<num>.asn.cymru.com`), extract `registrar` name from RDAP JSON, compute `/favicon.ico` SHA-256 hash, extract HTML tracking tokens (`ga_ua`, `ga4`, `gtm`, `fb_pixel`), and include `favicon_sha256` in Module 3 Host Header origin collision checks.
**Blocked by:** `16-custodian-proposition-models`
**Target files:** `src/ariadns/utils/asn_cdn.py`, `src/ariadns/modules/m1_local_probe.py`, `src/ariadns/modules/m3_origin.py`, `tests/test_17_custodian_and_fingerprints.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given HTML containing `"G-ABC1234567"`, `"GTM-XYZ987"`, and `"fbq('init', '1234567890123')"`, When `extract_html_tracking_tokens()` is called, Then all three tracking IDs are extracted deterministically.
- [ ] Given an RDAP response with a `registrar` role entity, When `get_identity_profile()` parses it, Then `identity.registrar_name` is populated with the registrar's `fn` value.
- [ ] Given a candidate origin IP returning an identical `favicon_sha256` as live `DomainL1` on `Host: <DomainL1>`, When `verify_candidate_origin()` runs, Then it returns `True`.

## Deterministic Verification
- Unit test path: `tests/test_17_custodian_and_fingerprints.py`
- Mutation target: `src/ariadns/modules/m1_local_probe.py`, `src/ariadns/utils/asn_cdn.py`
