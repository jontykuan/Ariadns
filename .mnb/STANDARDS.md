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
| **PropositionNode** | `PropositionNode` | Node in the Causal Evidence DAG (`node_kind` in `{"FACT", "CONCLUSION"}`) with `prop_id: str`, `rank: int`, `statement: str`, `premises: list[str]`, `rule_name: str`, `target_entity: str`, `entity_type: str`, and `custodians: list[DataCustodian]`. |
| **DataCustodian** | `DataCustodian` | Data management authority `{custodian_name, custodian_role, queryable_node, queryable_records}` mapped deterministically from a `PropositionNode`. |
| **EvidenceChainDAG** | `EvidenceChainDAG` | Strictly acyclic directed causal graph (`propositions`, `edges`) where every edge $(P \to C)$ satisfies $\text{rank}(P) < \text{rank}(C)$. |

---

## 2. Deterministic Calculation Formulas & Parsing Rules

### 2.1 SOA RNAME to Email Conversion
- Given an SOA `RNAME` string (after stripping trailing dot `.`):
  1. Replace escaped dots `\.` with a temporary sentinel before splitting.
  2. Split on the **first unescaped dot** into `(local_part, domain_part)`.
  3. Restore `\.` in `local_part` to literal `.` and join as `f"{local_part}@{domain_part}"`.
  - Example: `admin\.sec.example.com.` $\rightarrow$ `admin.sec@example.com`.

### 2.2 Verification & HTML Tracking Token Extraction Regex
- Extract from DNS `TXT` records:
  - `google`: `r"google-site-verification=[A-Za-z0-9_-]+"`
  - `facebook`: `r"facebook-domain-verification=[A-Za-z0-9_-]+"`
  - `ms`: `r"MS=ms[0-9]+"`
  - `atlassian`: `r"atlassian-domain-verification=[A-Za-z0-9+/=_-]+"`
- Extract from HTML response body (`extract_html_tracking_tokens`):
  - `ga_ua`: `r"\bUA-\d{4,10}-\d{1,4}\b"`
  - `ga4`: `r"\bG-[A-Z0-9]{8,12}\b"`
  - `gtm`: `r"\bGTM-[A-Z0-9]{5,10}\b"`
  - `fb_pixel`: `r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"`

### 2.3 CDN Detection & Zero-Quota IP/ASN Custodian Resolution
- Zero-quota local resolution order:
  1. **Local CIDR Table Match**: Check IP against built-in CIDR ranges of major CDNs.
  2. **Team Cymru DNS Origin & Peer Description Lookup**:
     - Query `<reversed-ip>.origin.asn.cymru.com` `TXT` $\rightarrow$ extract `(asn, bgp_prefix, country, rir)`.
     - Query `AS<number>.asn.cymru.com` `TXT` $\rightarrow$ extract `asn_org_name` (e.g., `"CLOUDFLARENET, US"`, `"DIGITALOCEAN-ASN, US"`, `"CHUNGHWA TELECOM CO., LTD., TW"`).
- **Canonical CDN ASN Set**:
  - Cloudflare: `AS13335`, `AS209242`
  - Akamai: `AS16625`, `AS20940`, `AS32787`
  - Fastly: `AS54113`
  - Amazon CloudFront: `AS16509`, `AS14618`
  - Imperva / Incapsula: `AS19551`
  - Edgecast / Verizon: `AS15133`

### 2.4 Host Header Origin Collision & Favicon Fingerprint Verification
- Probe `http://<CandidateOriginIP>/` and `https://<CandidateOriginIP>/` (with SNI = `DomainL1` and `verify=False` for cert extraction) carrying header `Host: <DomainL1>` and `timeout=5.0s`.
- Fetch `/favicon.ico` (with `Host: <DomainL1>`) and compute SHA-256 hex digest (`favicon_sha256`).
- **JARM Exclusion Rule**: JARM TLS stack hashes are excluded from correlation premises due to high false-positive rates across identical OS/Web server distributions.
- Mark `OriginVerificationStatus.CONFIRMED` if and only if:
  1. `CandidateOriginIP` does not belong to the CDN ASN set, AND
  2. At least one deterministic fingerprint matches the live `DomainL1` response:
     - Exact TLS Certificate CN or SAN match for `DomainL1`, OR
     - Exact HTML `<title>` match (non-empty, non-generic error title), OR
     - Identical `favicon_sha256` digest or shared HTML tracking token.

### 2.5 Noise Filter & Circuit Breaker Thresholds (Module 5)
- **MX Blacklist** (case-insensitive substring/suffix match; blocks Reverse MX):
  `google.com`, `googlemail.com`, `outlook.com`, `protection.outlook.com`, `pphosted.com`, `mimecast.com`, `zoho.com`, `yahoodns.net`, `icloud.com`, `protonmail.ch`, `secureserver.net`.
- **NS Blacklist** (case-insensitive substring/suffix match; blocks Reverse NS):
  `cloudflare.com`, `domaincontrol.com`, `awsdns`, `googledomains.com`, `azure-dns`, `nsone.net`, `linode.com`, `digitalocean.com`, `registrar-servers.com`, `hichina.com`, `dnspod.net`.
- **Shared IP Circuit Breaker**:
  If Reverse IP returns `result_count > 100` (or `GraphNode` in-degree $> 100$), classify IP as `SHARED_HOSTING`, record `ModuleStatus.SKIPPED_BLACKLIST`, and block L2 expansion from that IP.

### 2.6 Graph Edge Weights & L2 Confidence Scoring
- Edge weight assignments between `DomainL1` and candidate `DomainL2`:
  - `SAME_TOKEN` (shared verification or HTML tracking token): $w = 0.8$
  - `SAME_ORIGIN_IP` (confirmed/non-CDN IP with degree $\le 100$): $w = 0.7$
  - `REGISTERED_BY` (identical non-redacted Registrant/SOA Email): $w = 0.7$
  - `SAME_MX` (non-blacklisted custom MX host): $w = 0.6$
  - `SAME_NS` (non-blacklisted custom NS host): $w = 0.4$
- Aggregate confidence score for candidate `DomainL2` $d$:
  $$S(d) = \min\left(1.0, \sum_{e \in E(L1, d)} w(e)\right)$$
  - $S(d) \ge 0.60 \implies \text{ConfidenceLevel.HIGH}$ (Eligible for automatic L2 lightweight probe when `--depth 2`)
  - $0.40 \le S(d) < 0.60 \implies \text{ConfidenceLevel.MEDIUM}$
  - $S(d) < 0.40 \implies \text{ConfidenceLevel.LOW}$

### 2.7 Chained Propositional Evidence DAG & Data Custodian Mapping
- **Acyclicity & Rank Formula**:
  - Every `PropositionNode` $P$ has an integer epistemic rank:
    $$\text{rank}(P) = \begin{cases} 0 & \text{if } \text{premises}(P) = \emptyset \text{ (Base Fact)} \\ 1 + \max_{u \in \text{premises}(P)} \text{rank}(u) & \text{if } \text{premises}(P) \neq \emptyset \text{ (Derived Conclusion)} \end{cases}$$
  - Any Conclusion $C_k$ at $\text{rank} = r$ may serve as a premise for a subsequent Conclusion $C_{k+1}$ at $\text{rank} \ge r + 1$. Because edges strictly follow $\text{rank}(u) < \text{rank}(v)$, the Evidence Graph is mathematically guaranteed to be a **Directed Acyclic Graph (DAG)**.
- **Causal Derivation Rules ("因為 A 和 B 所以 C")**:
  1. `RULE_DIRECT_OBSERVATION` ($F_1 \implies C_1$): Direct DNS/RDAP/HTTP/TLS/Token observation on `DomainL1` establishes active infrastructure/identity component $C_1$.
  2. `RULE_ORIGIN_CONFIRMATION` ($F_{\text{pDNS/Subdomain/OOB}} \land F_{\text{Host/Title/TLS/Favicon Match}} \implies C_{\text{Origin}}$): Joint observation of candidate IP $X$ and matching host fingerprint establishes $C_{\text{Origin}}$ (`IP X is Confirmed Origin Server of DomainL1`).
  3. `RULE_PIVOT_CORRELATION` ($C_{\text{PivotKey}} \land F_{\text{ReverseLookup}} \implies C_{\text{L2}}$): Established L1 pivot key (Confirmed Origin IP, custom MX/NS, SOA/Registrant Email, or Verification/Tracking Token) combined with reverse lookup hit establishes $C_{\text{L2}}$ (`DomainL2 is correlated with DomainL1`).
  4. `RULE_L2_EXTENSION` ($C_{\text{L2}} \land F_{\text{L2\_Probe}} \implies C_{\text{L2\_Identity}}$): Correlated `DomainL2` combined with L2 DNS/RDAP/SOA facts establishes $C_{\text{L2\_Identity}}$ (`L2 infrastructure/identity node linked to investigation`).
- **Deterministic Custodian Mapping (`DataCustodian` per Conclusion $C$)**:
  - **Domain Node (`DOMAIN_L1`, `DOMAIN_L2`)** $\rightarrow$ Custodian: RDAP `registrar` entity name & `NS` operator $\rightarrow$ Queryable records: Registrant KYC, domain billing/payment logs, DNS modification access IPs.
  - **CDN IP Node (`IP` where `is_cdn=True`)** $\rightarrow$ Custodian: `cdn_provider` / `asn_org_name` $\rightarrow$ Queryable records: Backend origin forwarding IP, account registration email, payment method, account login IPs.
  - **Origin / Non-CDN IP Node (`IP` where `is_cdn=False`)** $\rightarrow$ Custodian: `asn_org_name` (`ASN`, `country`, `rir`) $\rightarrow$ Queryable records: Server/VPS subscriber identity (KYC), billing/payment logs, console/SSH access logs.
  - **Email / MX Node (`EMAIL`, `MX`)** $\rightarrow$ Custodian: Email domain operator / MX host ASN custodian $\rightarrow$ Queryable records: Account registration phone/recovery email, SMTP/Webmail login IP logs.
  - **Verification / Tracking Token Node (`TOKEN`)** $\rightarrow$ Custodian: Platform authority (`Google LLC` for `google`/`ga_ua`/`ga4`/`gtm`; `Meta Platforms, Inc.` for `facebook`/`fb_pixel`; `Microsoft Corp.` for `ms`; `Atlassian` for `atlassian`) $\rightarrow$ Queryable records: Account UID bound to token, recovery phone/email, access IP logs.

---

## 3. System Invariants & Defensive Guardrails

1. **SQLite Cache TTL Invariant**:
   - Default TTL is `7 days` (`604800` seconds). Within TTL, cached entries MUST be returned with `ModuleStatus.CACHED` and zero external HTTP requests (`external_api_calls == 0`).
2. **Rate Limiting & Quota Invariant**:
   - Keyless public endpoints (`crt.sh`, `HackerTarget`, `RDAP`): enforce minimum delay $\ge 1.5\text{s}$ between requests.
   - VirusTotal v3 Free API: enforce sliding window $\le 4\text{ requests} / 60\text{s}$ ($\ge 15.0\text{s}$ interval) and $\le 500\text{ requests} / \text{day}$ persisted in `api_quota_tracker`.
3. **Exponential Backoff & Soft Degradation Invariant**:
   - On HTTP `429` or `504` (or transient network timeout), pause and retry with delays `2s, 4s, 8s` (maximum 3 retries). Never crash the pipeline on exhaustion.
4. **Hard Socket/HTTP Timeout Invariant**:
   - Every local probe (`socket`, `ssl`, `httpx`, subprocess CLI calls) MUST enforce `timeout=5.0s` per request.
5. **L2 Recursion Scope Invariant**:
   - Default automatic `--depth 2` recursion executes **only Module 1 lightweight local probe + RDAP/Cache lookup** on `ConfidenceLevel.HIGH` L2 domains.
   - Full deep probing on a specific L2 domain is triggered explicitly via CLI (`ariadns expand -d <l2_domain>`), Interactive REPL, or MCP (`osint_expand`).
6. **Manual-Only OOB Callback Invariant**:
   - Active callback probing (`manual_oob`) MUST NEVER be executed during `ariadns run` or `osint_scan`. It may only run when explicitly invoked via `ariadns manual-oob` or MCP `osint_manual_oob(acknowledge_opsec_risk=True)` after surfacing OPSEC risk warnings (target server logs will record the callback destination).
7. **Secret Masking Invariant**:
   - All terminal logs, progress output, exceptions, and MCP responses MUST mask API keys (`abc***`), storing raw keys exclusively in gitignored `config.yaml`.
8. **MCP Context & Read-Only SQL Invariant**:
   - `osint_scan` and `osint_expand` return compact summaries ($\le 600$ tokens), persisting full payloads in SQLite.
   - `osint_inspect` SQL mode MUST validate that the query starts with `SELECT` / `WITH` and open SQLite using URI `file:<path>?mode=ro`.
9. **Code Quality Invariant**:
   - Python 3.10+, PEP 8 compliant, full type hints on all function signatures, zero hardcoded user paths.
