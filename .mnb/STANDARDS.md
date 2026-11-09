# Ariadns Engineering Standards (`.mnb/STANDARDS.md`)

## 1. Ubiquitous Language (統一領域詞彙)

All modules, database schemas, CLI arguments, MCP tools, and Web UI components must strictly use the following canonical identifiers. Synonyms are forbidden.

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
| **PropositionNode** | `PropositionNode` | Node in the Causal Evidence DAG (`node_kind` in `{"FACT", "CONCLUSION"}`) with `prop_id: str`, `rank: int`, `statement: str`, `premises: list[str]`, `rule_name: str`, `target_entity: str`, `entity_type: str`, `custodians: list[DataCustodian]`, and `is_rendered: bool`. |
| **DataCustodian** | `DataCustodian` | Data management authority `{custodian_name, custodian_role, queryable_node, queryable_records}` mapped deterministically from a `PropositionNode`. |
| **EvidenceChainDAG** | `EvidenceChainDAG` | Strictly acyclic directed causal graph (`propositions`, `edges`) where every edge $(P \to C)$ satisfies $\text{rank}(P) < \text{rank}(C)$. |
| **WarninglistIndicator** | `WarninglistIndicator` | Shared-infrastructure false-positive indicator `{list_name, indicator_type, indicator_value, synced_at}` synced lazily every 7 days. |
| **SessionAuditEntry** | `SessionAuditEntry` | Immutable stepwise execution log `{session_id, step_seq, timestamp, module_name, target, params_json, added_fact_ids, artifact_sha256}`. |
| **NextStepRecommendation** | `NextStepRecommendation` | Rule-derived investigative action `{rec_id, trigger_fact_ids, recommended_module, recommended_target, rationale, expected_evidence, cli_command}`. |
| **ArtifactManifest** | `ArtifactManifest` | Forensic verification manifest `{session_id, payload_sha256, rendered_prop_ids, excluded_prop_ids, file_hashes, verified}`. |

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
     - Query `AS<number>.asn.cymru.com` `TXT` $\rightarrow$ extract `asn_org_name` (e.g., `"CLOUDFLARENET, US"`, `"AMAZON-02, US"`, `"CHUNGHWA TELECOM CO., LTD., TW"`).
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

### 2.5 Noise Filter, Circuit Breakers & 7-Day Lazy Warninglist Sync
- **Static Baseline Blacklists** (case-insensitive substring/suffix match):
  - **MX Blacklist**: `google.com`, `googlemail.com`, `outlook.com`, `protection.outlook.com`, `pphosted.com`, `mimecast.com`, `zoho.com`, `yahoodns.net`, `icloud.com`, `protonmail.ch`, `secureserver.net`, `privateemail.com`, `titan.email`, `yandex.net`, `mailgun.org`, `sendgrid.net`.
  - **NS Blacklist**: `cloudflare.com`, `domaincontrol.com`, `awsdns`, `googledomains.com`, `azure-dns`, `nsone.net`, `linode.com`, `digitalocean.com`, `registrar-servers.com`, `hichina.com`, `dnspod.net`.
- **7-Day Lazy Warninglist Sync (`warninglist_sync.py`)**:
  - On engine initialization, query `warninglist_metadata` for `last_synced_at`.
  - If missing or `current_epoch - last_synced_at > 604800` (7 days), fetch open-source feeds (`MISP parking-domain-ns`, `MISP parking-domain`, `MISP common-contact-emails`, and `free-email-domains`) with `timeout=5.0s`, normalize indicators into `warninglist_indicators`, and update `last_synced_at`.
  - If offline or request times out, log `ModuleStatus.FALLBACK_NATIVE` and proceed immediately using existing SQLite + static baseline indicators without blocking execution.
- **Shared IP Circuit Breaker**:
  - If Reverse IP returns `result_count > 100` (or `GraphNode` in-degree $> 100$), classify IP as `SHARED_HOSTING`, record `ModuleStatus.SKIPPED_BLACKLIST`, and block L2 expansion from that IP.

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
  - Because edges strictly follow $\text{rank}(u) < \text{rank}(v)$, the Evidence Graph is mathematically guaranteed to be a **Directed Acyclic Graph (DAG)**.
- **Causal Derivation Rules ("因為 A 和 B 所以 C")**:
  1. `RULE_DIRECT_OBSERVATION` ($F_1 \implies C_1$): Direct DNS/RDAP/HTTP/TLS/Token observation on `DomainL1` establishes active infrastructure/identity component $C_1$.
  2. `RULE_ORIGIN_CONFIRMATION` ($F_{\text{pDNS/Subdomain/OOB}} \land F_{\text{Host/Title/TLS/Favicon Match}} \implies C_{\text{Origin}}$): Joint observation of candidate IP $X$ and matching host fingerprint establishes $C_{\text{Origin}}$ (`IP X is Confirmed Origin Server of DomainL1`).
  3. `RULE_PIVOT_CORRELATION` ($C_{\text{PivotKey}} \land F_{\text{ReverseLookup}} \implies C_{\text{L2}}$): Established L1 pivot key combined with reverse lookup hit establishes $C_{\text{L2}}$ (`DomainL2 is correlated with DomainL1`).
  4. `RULE_L2_EXTENSION` ($C_{\text{L2}} \land F_{\text{L2\_Probe}} \implies C_{\text{L2\_Identity}}$): Correlated `DomainL2` combined with L2 DNS/RDAP/SOA facts establishes $C_{\text{L2\_Identity}}$.
- **Deterministic Custodian Mapping (`DataCustodian` per Conclusion $C$)**:
  - **Domain Node (`DOMAIN_L1`, `DOMAIN_L2`)** $\rightarrow$ Custodian: RDAP `registrar` entity name & `NS` operator $\rightarrow$ Queryable records: Registrant KYC, domain billing/payment logs, DNS modification access IPs.
  - **CDN IP Node (`IP` where `is_cdn=True`)** $\rightarrow$ Custodian: `cdn_provider` / `asn_org_name` $\rightarrow$ Queryable records: Backend origin forwarding IP, account registration email, payment method, account login IPs.
  - **Origin / Non-CDN IP Node (`IP` where `is_cdn=False`)** $\rightarrow$ Custodian: `asn_org_name` (`ASN`, `country`, `rir`) $\rightarrow$ Queryable records: Server/VPS subscriber identity (KYC), billing/payment logs, console/SSH access logs.
  - **Email / MX Node (`EMAIL`, `MX`)** $\rightarrow$ Custodian: Email domain operator / MX host ASN custodian $\rightarrow$ Queryable records: Account registration phone/recovery email, SMTP/Webmail login IP logs.
  - **Verification / Tracking Token Node (`TOKEN`)** $\rightarrow$ Custodian: Platform authority (`Google LLC`, `Meta Platforms, Inc.`, `Microsoft Corp.`, `Atlassian`) $\rightarrow$ Queryable records: Account UID bound to token, recovery phone/email, access IP logs.

### 2.8 Normalized 4-Table Evidence Storage, Next-Step Recommender & Forensic Verification
- **Normalized SQLite Schema (`db.py`)**:
  1. `evidence_propositions`: `(session_id, prop_id, node_kind, rank, rule_name, target_entity, entity_type, statement, is_rendered)` — PK `(session_id, prop_id)`.
  2. `evidence_edges`: `(session_id, premise_id, conclusion_id)` — PK `(session_id, premise_id, conclusion_id)`.
  3. `evidence_custodians`: `(session_id, conclusion_id, custodian_name, custodian_role, queryable_node, queryable_records_json)`.
  4. `session_audit_logs`: `(session_id, step_seq, timestamp, module_name, target, params_json, added_fact_ids_json, artifact_sha256)` — PK `(session_id, step_seq)`.
- **Next-Step Recommendation Rules (`m8_recommender.py`)**:
  - Evaluates current session propositions (`FACT` / `CONCLUSION`) and already-executed `session_audit_logs` steps to emit prioritized `NextStepRecommendation` items:
    - `REC_ENUM_SUBDOMAINS`: When `F1` shows `is_cdn=True` and `M2` has not run $\implies$ recommend `M2` on `DomainL1` to uncover unproxied backend subdomains.
    - `REC_ORIGIN_COLLISION`: When `F1` shows `is_cdn=True` and `M3` has not run $\implies$ recommend `M3` passive DNS + Host collision on `DomainL1`.
    - `REC_PROBE_UNPROXIED_IP`: When `M2` or `M3` discovers a non-CDN IP $X$ not yet port-scanned or reverse-IP pivoted $\implies$ recommend `M1` port/banner probe and `M4` `reverse_ip` on $X$.
    - `REC_PIVOT_CUSTOM_INFRA`: When `M1` discovers non-blacklisted MX, NS, or Token not yet pivoted $\implies$ recommend `M4` pivot lookup on that indicator.
    - `REC_EXPAND_HIGH_L2`: When `M4` identifies a `ConfidenceLevel.HIGH` `DomainL2` not yet probed $\implies$ recommend `M1` lightweight identity probe on `DomainL2`.
- **Deferred Static Graph Rendering & Dual-Layer Forensic Hashing (`m6_reporting.py`, `forensic_verifier.py`)**:
  - Default node selection marks core propositions (`OriginVerificationStatus.CONFIRMED`, non-CDN subdomain IPs, `ConfidenceLevel.HIGH` L2 conclusions, and all `DataCustodian` nodes) as `is_rendered=1`, while low-confidence or unproxied noise defaults to `is_rendered=0` (overridable by user selection before render).
  - Pure-Python deterministic hierarchical SVG/PNG renderer computes fixed $(x, y)$ coordinates by `(rank, index)` and draws non-draggable boxes, directed edges, and a bottom forensic stamp containing `session_id`, UTC timestamp, and `payload_sha256` (SHA-256 of canonical JSON of rendered nodes + edges + `session_audit_logs`).
  - `ArtifactManifest` records standard `file_sha256` for each exported file (`.svg`, `.png`, `.md`, `.json`) alongside `payload_sha256`.
  - `verify_case_artifacts(case_dir)` recomputes both `file_sha256` of every artifact on disk and `payload_sha256` from the normalized DB / JSON audit trail, returning `verified=True` if and only if all hashes match bit-for-bit.

---

## 3. System Invariants & Defensive Guardrails

1. **SQLite Cache TTL & 7-Day Warninglist Invariant**:
   - Default cache and warninglist sync TTL is `7 days` (`604800` seconds). Within TTL, cached entries MUST be returned with `ModuleStatus.CACHED` and zero external HTTP requests (`external_api_calls == 0`).
2. **Rate Limiting & Quota Invariant**:
   - Keyless public endpoints (`crt.sh`, `HackerTarget`, `RDAP`): enforce minimum delay $\ge 1.5\text{s}$ between requests.
   - VirusTotal v3 Free API: enforce sliding window $\le 4\text{ requests} / 60\text{s}$ ($\ge 15.0\text{s}$ interval) and $\le 500\text{ requests} / \text{day}$ persisted in `api_quota_tracker`.
3. **Exponential Backoff & Soft Degradation Invariant**:
   - On HTTP `429` or `504` (or transient network timeout), pause and retry with delays `2s, 4s, 8s` (maximum 3 retries). Never crash the pipeline on exhaustion.
4. **Hard Socket/HTTP Timeout Invariant**:
   - Every local probe (`socket`, `ssl`, `httpx`, subprocess CLI calls) MUST enforce `timeout=5.0s` per request.
5. **L2 Recursion Scope Invariant**:
   - Default automatic `--depth 2` recursion executes **only Module 1 lightweight local probe + RDAP/Cache lookup** on `ConfidenceLevel.HIGH` L2 domains.
6. **Manual-Only OOB Callback Invariant**:
   - Active callback probing (`manual_oob`) MUST NEVER be executed during automatic runs. It may only run when explicitly invoked with OPSEC risk confirmation.
7. **Secret Masking Invariant**:
   - All terminal logs, progress output, exceptions, Web UI responses, and MCP responses MUST mask API keys (`abc***`), storing raw keys exclusively in gitignored `config.yaml`.
8. **MCP Context & Normalized Read-Only SQL Invariant**:
   - `osint_inspect` and `osint_read_evidence_graph` MUST query the 4 normalized SQLite tables (`evidence_propositions`, `evidence_edges`, `evidence_custodians`, `session_audit_logs`) directly with default filter `WHERE is_rendered = 1` and `LIMIT 20` ($\le 500$ tokens), NEVER re-running `run_investigation()` during inspection.
   - `osint_inspect` SQL mode MUST validate `SELECT` / `WITH` prefix and open SQLite using URI `file:<path>?mode=ro`.
9. **Tri-Interface Parity & Deferred Graph Rendering Invariant**:
   - All capabilities (7-day warninglist sync, stepwise module execution, next-step recommendations, node-filtered static graph rendering, evidence graph reading, and forensic hash verification) MUST be exposed symmetrically across CLI (`cli.py`), FastMCP (`mcp_server.py`), and Local Web UI (`web_ui.py`).
   - Static evidence graph rendering MUST NOT run on intermediate stepwise actions; it executes only at the conclusion of a full automatic run or upon explicit user/agent render command.
10. **Code Quality Invariant**:
    - Python 3.10+, PEP 8 compliant, full type hints on all function signatures, zero hardcoded user paths.
