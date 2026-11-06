# Ariadns Engineering Standards (`.mnb/STANDARDS.md`)

## 1. Ubiquitous Language (統一領域詞彙)

All modules, database schemas, CLI arguments, and MCP tools must strictly use the following canonical identifiers. Synonyms are forbidden.

| Canonical Term | Type / Symbol | Definition |
| :--- | :--- | :--- |
| **DomainL1** | `target_domain: str` | Initial root domain under investigation (Depth 1). |
| **DomainL2** | `l2_domain: str` | Associated domain discovered via pivoting from `DomainL1` (Depth 2). |
| **SubdomainRecord** | `SubdomainRecord` | Structured record `{subdomain, ip, status_code, title, server, tech}` from passive enumeration + active probing. |
| **CandidateOriginIP** | `suspected_origin_ip: str` | Historical pre-CDN IPv4/IPv6 address or non-CDN subdomain IP candidate for origin verification. |
| **OriginVerificationStatus** | `OriginVerificationStatus` | Enum: `CONFIRMED` \| `SUSPECTED` \| `UNVERIFIED` \| `NOT_APPLICABLE`. |
| **ConfidenceLevel** | `ConfidenceLevel` | Enum: `HIGH` \| `MEDIUM` \| `LOW` \| `NOISE_FILTERED`. |
| **ModuleStatus** | `ModuleStatus` | Enum: `OK` \| `CACHED` \| `FALLBACK_NATIVE` \| `SKIPPED_BLACKLIST` \| `SKIPPED_QUOTA` \| `SKIPPED_NO_KEY` \| `TIMEOUT_UNVERIFIED`. |
| **GraphNode** | `GraphNode` | Heterogeneous property graph vertex with `node_type` in `{"DOMAIN_L1", "DOMAIN_L2", "SUBDOMAIN", "IP", "ASN", "MX", "NS", "EMAIL", "TOKEN", "CERT_SAN"}`. |
| **GraphEdge** | `GraphEdge` | Directed edge with `relation_type` in `{"RESOLVES_TO", "HISTORICAL_A", "USES_MX", "USES_NS", "HAS_SUBDOMAIN", "REGISTERED_BY", "HAS_TOKEN", "SAME_ORIGIN_IP", "SAME_MX", "SAME_NS", "SAME_TOKEN"}` and deterministic `weight: float`. |

---

## 2. Deterministic Calculation Formulas & Parsing Rules

### 2.1 SOA RNAME to Email Conversion
- Given an SOA `RNAME` string (after stripping trailing dot `.`):
  1. Replace escaped dots `\.` with a temporary sentinel before splitting.
  2. Split on the **first unescaped dot** into `(local_part, domain_part)`.
  3. Restore `\.` in `local_part` to literal `.` and join as `f"{local_part}@{domain_part}"`.
  - Example: `admin\.sec.example.com.` $\rightarrow$ `admin.sec@example.com`.

### 2.2 Verification Token Extraction Regex
- Extract from `TXT` records using deterministic regex patterns:
  - `google`: `r"google-site-verification=[A-Za-z0-9_-]+"`
  - `facebook`: `r"facebook-domain-verification=[A-Za-z0-9_-]+"`
  - `ms`: `r"MS=ms[0-9]+"`
  - `atlassian`: `r"atlassian-domain-verification=[A-Za-z0-9+/=_-]+"`

### 2.3 CDN Detection & IP-to-ASN Resolution
- Zero-quota local resolution order:
  1. **Local CIDR Table Match**: Check IP against built-in CIDR ranges of major CDNs.
  2. **Team Cymru DNS Lookup**: Query `<reversed-ip>.origin.asn.cymru.com` `TXT` via `dnspython` (zero external HTTP API quota).
- **Canonical CDN ASN Set**:
  - Cloudflare: `AS13335`, `AS209242`
  - Akamai: `AS16625`, `AS20940`, `AS32787`
  - Fastly: `AS54113`
  - Amazon CloudFront: `AS16509`, `AS14618`
  - Imperva / Incapsula: `AS19551`
  - Edgecast / Verizon: `AS15133`

### 2.4 Host Header Origin Collision Verification
- Probe `http://<CandidateOriginIP>/` and `https://<CandidateOriginIP>/` (with SNI = `DomainL1` and `verify=False` for cert extraction) carrying header `Host: <DomainL1>` and `timeout=5.0s`.
- Mark `OriginVerificationStatus.CONFIRMED` if and only if:
  1. `CandidateOriginIP` does not belong to the CDN ASN set, AND
  2. At least one deterministic fingerprint matches the live `DomainL1` response:
     - Exact TLS Certificate CN or SAN match for `DomainL1`, OR
     - Exact HTML `<title>` match (non-empty, non-generic error title), OR
     - Identical Favicon SHA-256 / MurmurHash3 digest.

### 2.5 Noise Filter & Circuit Breaker Thresholds (Module 5)
- **MX Blacklist** (case-insensitive substring/suffix match; blocks Reverse MX):
  `google.com`, `googlemail.com`, `outlook.com`, `protection.outlook.com`, `pphosted.com`, `mimecast.com`, `zoho.com`, `yahoodns.net`, `icloud.com`, `protonmail.ch`, `secureserver.net`.
- **NS Blacklist** (case-insensitive substring/suffix match; blocks Reverse NS):
  `cloudflare.com`, `domaincontrol.com`, `awsdns`, `googledomains.com`, `azure-dns`, `nsone.net`, `linode.com`, `digitalocean.com`, `registrar-servers.com`, `hichina.com`, `dnspod.net`.
- **Shared IP Circuit Breaker**:
  If Reverse IP returns `result_count > 100` (or `GraphNode` in-degree $> 100$), classify IP as `SHARED_HOSTING`, record `ModuleStatus.SKIPPED_BLACKLIST`, and block L2 expansion from that IP.

### 2.6 Graph Edge Weights & L2 Confidence Scoring
- Edge weight assignments between `DomainL1` and candidate `DomainL2`:
  - `SAME_TOKEN` (shared verification token): $w = 0.8$
  - `SAME_ORIGIN_IP` (confirmed/non-CDN IP with degree $\le 100$): $w = 0.7$
  - `REGISTERED_BY` (identical non-redacted Registrant/SOA Email): $w = 0.7$
  - `SAME_MX` (non-blacklisted custom MX host): $w = 0.6$
  - `SAME_NS` (non-blacklisted custom NS host): $w = 0.4$
- Aggregate confidence score for candidate `DomainL2` $d$:
  $$S(d) = \min\left(1.0, \sum_{e \in E(L1, d)} w(e)\right)$$
  - $S(d) \ge 0.60 \implies \text{ConfidenceLevel.HIGH}$ (Eligible for automatic L2 lightweight probe when `--depth 2`)
  - $0.40 \le S(d) < 0.60 \implies \text{ConfidenceLevel.MEDIUM}$
  - $S(d) < 0.40 \implies \text{ConfidenceLevel.LOW}$

---

## 3. System Invariants & Defensive Guardrails

1. **SQLite Cache TTL Invariant**:
   - Default TTL is `7 days` (`604800` seconds).
   - Before invoking any external endpoint (`crt.sh`, `VirusTotal`, `AlienVault OTX`, `HackerTarget`, `ViewDNS`, `RDAP`), the engine MUST check SQLite cache (`dns_cache`, `ip_pivot_cache`).
   - Within TTL, cached entries MUST be returned with `ModuleStatus.CACHED` and zero external HTTP requests (`external_api_calls == 0`).
2. **Rate Limiting & Quota Invariant**:
   - Keyless public endpoints (`crt.sh`, `HackerTarget`, `RDAP`): enforce minimum delay $\ge 1.5\text{s}$ between requests.
   - VirusTotal v3 Free API: enforce sliding window $\le 4\text{ requests} / 60\text{s}$ ($\ge 15.0\text{s}$ interval) and $\le 500\text{ requests} / \text{day}$ persisted in `api_quota_tracker`.
3. **Exponential Backoff & Soft Degradation Invariant**:
   - On HTTP `429` or `504` (or transient network timeout), pause and retry with delays `2s, 4s, 8s` (maximum 3 retries).
   - If retries exhaust or quota is exceeded, never crash the pipeline: record `ModuleStatus.TIMEOUT_UNVERIFIED` or `ModuleStatus.SKIPPED_QUOTA` and proceed with remaining modules.
4. **Hard Socket/HTTP Timeout Invariant**:
   - Every local probe (`socket`, `ssl`, `httpx`, subprocess CLI calls) MUST enforce `timeout=5.0s` per request (and bounded subprocess timeout) to prevent dropped packets from hanging execution.
5. **L2 Recursion Scope Invariant**:
   - Default automatic `--depth 2` recursion executes **only Module 1 lightweight local probe + RDAP/Cache lookup** on `ConfidenceLevel.HIGH` L2 domains to guarantee the `< 3 minutes` SLA.
   - Full deep probing (Module 2 subdomains, Module 3 pDNS, Module 4 pivoting) on a specific L2 domain is triggered explicitly via CLI (`ariadns expand -d <l2_domain>`), Interactive REPL, or MCP (`osint_expand`).
6. **Secret Masking Invariant**:
   - All terminal logs, progress output, exceptions, and MCP responses MUST mask API keys (`abc***`), storing raw keys exclusively in gitignored `config.yaml`.
7. **MCP Context & Read-Only SQL Invariant**:
   - MCP Server exposes exactly 4 tools (`osint_scan`, `osint_inspect`, `osint_expand`, `osint_report`) + read-only MCP resources.
   - `osint_scan` and `osint_expand` return compact summaries ($\le 600$ tokens), persisting full payloads in SQLite.
   - `osint_inspect` SQL mode MUST validate that the query starts with `SELECT` / `WITH` (no semicolons chaining mutations) AND open SQLite using URI `file:<path>?mode=ro`.
8. **Code Quality Invariant**:
   - Python 3.10+, PEP 8 compliant, full type hints on all function signatures, zero hardcoded user paths.
