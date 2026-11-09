# Ariadns System Architecture (`.mnb/ARCHITECTURE.md`)

## 1. High-Level Topology & Tri-Headed Architecture

```mermaid
flowchart TD
    subgraph Interfaces ["Layer 4: Presentation & Agent Interfaces (Tri-Parity)"]
        CLI["ariadns CLI (cli.py)\nrun / step / recommend / render-graph / show-graph / verify / sync-lists / manual-oob / ui"]
        WEB["Local Web UI Workbench (web_ui.py)\nVisual Command Cards, Progress Bar, Next-Step Panel, Node Filter, Static SVG/PNG & Forensic Tables"]
        MCP["MCP Server (mcp_server.py)\nosint_scan / run_step / recommend_next / render_graph / read_evidence_graph / verify_case / inspect"]
        REPL["Interactive Console (repl.py)\nNode Inspection & L2 Extension"]
    end

    subgraph Orchestration ["Layer 3: Application Orchestrator & Session Manager"]
        M5["M5: Filter, Stepwise Session & Orchestrator (m5_orchestrator.py)\nIncremental Fact Merge, Audit Logging, Evidence DAG Sync"]
    end

    subgraph Engines ["Layer 2: Domain Probing, Recommender, Static Renderer & Reporting Modules"]
        M1["M1: Local Active Prober (m1_local_probe.py)\nDNS/RDAP Registrar, Banner, TLS, Favicon, HTML Tokens, Ports"]
        M2["M2: Subdomain Enumerator (m2_subdomain.py)"]
        M3["M3: Passive OSINT & Origin (m3_origin.py)"]
        M4["M4: Pivoting Engine (m4_pivoting.py)"]
        M6["M6: Reporting & Deterministic Static Graph Renderer (m6_reporting.py)\nreport.md, SVG/PNG Static DAG with Payload Hash, Manifest"]
        M7["M7: Isolated Manual OOB Prober (m7_manual_oob.py)\nExplicit Human/Risk-Gated Callback Probe"]
        M8["M8: Next-Step Investigation Recommender (m8_recommender.py)\nRule-Based Fact -> Next Action Inference"]
    end

    subgraph Infra ["Layer 1: Normalized Storage, Forensic Verifier & Warninglist Sync"]
        DB["SQLite 4-Table Normalized Evidence & Cache Store (storage/db.py)\nevidence_propositions, evidence_edges, evidence_custodians, session_audit_logs"]
        DAG["Evidence DAG & Forensic Verifier\n(storage/evidence_dag.py, storage/forensic_verifier.py)"]
        SYNC["7-Day Lazy Warninglist Synchronizer (utils/warninglist_sync.py)\nMISP Parking/Mail Lists & Freemail Feeds"]
        NET["RateLimiter, Backoff HTTP, ASN Org Resolver, CLI Runner\n(utils/)"]
    end

    subgraph Models ["Layer 0: Core Domain Models"]
        MOD["Entities, Enums, PropositionNode, DataCustodian, SessionAuditEntry, NextStepRecommendation, ArtifactManifest, Config\n(models/)"]
    end

    CLI & WEB & MCP & REPL --> M5
    CLI & WEB & MCP --> M7 & M8 & DAG & SYNC & DB

    M5 --> M1 & M2 & M3 & M4 & M6 & M8
    M5 --> DB & DAG & SYNC
    M7 --> NET & DB & MOD
    M8 --> DB & MOD

    M1 & M2 & M3 & M4 --> NET & DB & SYNC & MOD
    M6 --> DB & DAG & MOD
    DAG & SYNC & NET & DB --> MOD
```

---

## 2. Causal Evidence Chain DAG & Normalized Forensic Pipeline

```mermaid
flowchart TD
    subgraph Stepwise ["Stepwise Execution & Audit Trail (session_audit_logs)"]
        S1["Step 1: M1 Local Probe (Logged + Facts Added)"]
        S2["Step 2: M8 Recommends M2/M3 -> User/Agent Executes Step 2"]
        S3["Step 3: User Selects/Filters Nodes (is_rendered=1/0) & Triggers Render"]
    end

    subgraph Rank0 ["Rank 0: Base Observed Facts (evidence_propositions: FACT)"]
        F1["[FACT F1] DNS/HTTP: L1 resolves to CDN IP"]
        F2["[FACT F2] Subdomain 'app' resolves to Unproxied IP_Origin"]
        F3["[FACT F3] Reverse IP / Pivot matches Domain_L2"]
    end

    subgraph Rank1 ["Rank 1..N: Derived Conclusions (evidence_propositions: CONCLUSION)"]
        C1["[CONCLUSION C1] Active L1 Infrastructure & Registrar Identified"]
        C2["[CONCLUSION C2] Unproxied Backend Origin Host Identified at IP_Origin"]
        C3["[CONCLUSION C3] Domain_L2 Co-Attributed via Shared Origin"]
    end

    subgraph Custodians ["Queryable Nodes & Data Custodians (evidence_custodians)"]
        DC1["Custodian: Registrar / CDN\nRecords: KYC, Payment, Forwarding Target"]
        DC2["Custodian: Origin ASN Cloud Provider\nRecords: EC2/VPS Lessee KYC, Billing, SSH/Console Logs"]
    end

    subgraph Verification ["Deterministic Static Graph & Dual-Layer Hash (forensic_verifier.py)"]
        SVG["Static Non-Draggable SVG/PNG\nEmbedded Watermark: Payload SHA-256 + Timestamp"]
        MAN["ArtifactManifest & Report Table\nFull Session Audit Log + File SHA-256 Hashes"]
    end

    S1 --> S2 --> S3
    F1 --> C1
    F2 & C1 --> C2
    F3 & C2 --> C3
    C1 -.-> DC1
    C2 -.-> DC2
    S3 --> SVG & MAN
```

---

## 3. Directory Structure & Target Seams

```text
d:\cykuan\geminiCLI\DNSA\
├── pyproject.toml                  # Package metadata (`ariadns`) & entrypoints: `ariadns`, `ariadns-mcp`
├── requirements.txt                # Pinned runtime & test dependencies
├── config.yaml.example             # Template configuration (API keys, blacklists, rate limits)
├── recon.py                        # Root CLI wrapper entrypoint (SRS 5.1 compatibility)
├── src/
│   └── ariadns/
│       ├── models/
│       │   ├── enums.py            # OriginVerificationStatus, ConfidenceLevel, ModuleStatus, NodeType, EdgeType
│       │   ├── entities.py         # IdentityProfile, Infrastructure, SubdomainRecord, DataCustodian, PropositionNode, SessionAuditEntry, NextStepRecommendation, ArtifactManifest, InvestigationResult
│       │   └── config.py           # AppConfig loader, baseline blacklists, secret masking helper
│       ├── utils/
│       │   ├── rate_limiter.py     # Sliding-window rate limiter & 2s/4s/8s exponential backoff HTTP client
│       │   ├── asn_cdn.py          # Built-in CDN CIDR/ASN matcher + Team Cymru DNS ASN & Org Name resolver
│       │   ├── tool_runner.py      # External binary detector & `ariadns doctor` checks
│       │   └── warninglist_sync.py # 7-day lazy startup sync of MISP & freemail false-positive lists into SQLite
│       ├── storage/
│       │   ├── db.py               # SQLite cache, 4 normalized evidence/audit tables, warninglist store, read-only SQL executor
│       │   ├── graph_store.py      # SQLite `graph_nodes` / `graph_edges` + `networkx` topology
│       │   ├── evidence_dag.py     # Chained Propositional Evidence DAG builder & Data Custodian mapper
│       │   └── forensic_verifier.py# Dual-layer SHA-256 verifier (File Hash + Canonical Payload/Audit Hash)
│       ├── modules/
│       │   ├── m1_local_probe.py   # DNS, RDAP, Banner, TLS CN/SAN, Favicon SHA-256, HTML Tracking Tokens, Port Scan
│       │   ├── m2_subdomain.py     # crt.sh + HackerTarget + subfinder -> httpx / native prober
│       │   ├── m3_origin.py        # CDN check, VT/OTX pDNS, Host header + Title/TLS/Favicon collision verification
│       │   ├── m4_pivoting.py      # Reverse IP, Reverse MX/NS, Reverse Token/Whois (consults warninglist_sync)
│       │   ├── m5_orchestrator.py  # Stepwise execution (`run_step`), audit trail append, normalized DB persistence
│       │   ├── m6_reporting.py     # Exports `report.md` (with Audit Log table), deterministic static `.svg`/`.png`, and `manifest.json`
│       │   ├── m7_manual_oob.py    # Isolated manual-only OOB callback verifier
│       │   └── m8_recommender.py   # Rule-based Next-Step Investigation Recommender from known session facts
│       └── interfaces/
│           ├── cli.py              # CLI (`run`, `step`, `recommend`, `render-graph`, `show-graph`, `verify`, `sync-lists`, `ui`, `manual-oob`, `repl`, `doctor`, `init`)
│           ├── repl.py             # Interactive terminal menu
│           ├── mcp_server.py       # FastMCP server (`osint_scan`, `osint_run_step`, `osint_recommend_next`, `osint_render_graph`, `osint_read_evidence_graph`, `osint_verify_case`, `osint_inspect`, `osint_expand`, `osint_report`, `osint_manual_oob`, `osint_sync_lists`)
│           └── web_ui.py           # Local Web UI server (`http://127.0.0.1:8765`) & Impeccable-compliant forensic workbench
└── tests/
    └── ...
```

---

## 4. Strict Import Directionality Rules (Forbidden Cycles)

1. **`ariadns.models`** (Layer 0): Imports Python standard library only.
2. **`ariadns.utils` & `ariadns.storage`** (Layer 1): Imports `ariadns.models` and third-party infra libraries (`dnspython`, `httpx`, `networkx`, `yaml`, `sqlite3`).
3. **`ariadns.modules.m1_*` .. `m4_*`, `m6_*`, `m7_*`, `m8_*`** (Layer 2): Imports `ariadns.models`, `ariadns.utils`, `ariadns.storage`. Never imports `m5_orchestrator` or `ariadns.interfaces`.
4. **`ariadns.modules.m5_orchestrator`** (Layer 3): Coordinates `m1`..`m4`, `m6`, `m8`, `storage`, `utils`, `models`. Never imports `m7_manual_oob` into automatic runs, and never imports `ariadns.interfaces`.
5. **`ariadns.interfaces.*` & `recon.py`** (Layer 4): Imports `ariadns.modules.*`, `ariadns.storage.*`, `ariadns.utils.*`, `ariadns.models.*`.
