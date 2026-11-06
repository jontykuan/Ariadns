# 02: Configuration Loader, Blacklists & Secret Masking

**What to build:** Load `config.yaml` (with fallback to defaults in `config.yaml.example`), enforce MX/NS blacklists, and mask API keys in logs/stdout.
**Blocked by:** `01-domain-models-enums`
**Target files:** `config.yaml.example`, `src/ariadns/models/config.py`, `tests/test_02_config.py`
**Size budget:** <= 20 LOC per unit

## Acceptance Criteria
- [ ] Given an API key `"abcdef123456"` in `AppConfig`, When `mask_secret()` or `redact_text()` is called on log output, Then it returns `"abc***"` and never leaks the raw key.
- [ ] Given MX host `"aspmx.l.google.com"` and NS host `"ns1.cloudflare.com"`, When checked against `AppConfig.is_mx_blacklisted()` and `is_ns_blacklisted()`, Then both return `True`.

## Deterministic Verification
- Unit test path: `tests/test_02_config.py`
- Mutation target: `src/ariadns/models/config.py`
