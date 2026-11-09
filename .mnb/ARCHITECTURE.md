# Ariadns System Architecture (`.mnb/ARCHITECTURE.md`)

## 1. High-Level Topology & Dual-Headed Architecture

```mermaid
flowchart TD
    subgraph Interfaces ["Layer 4: Presentation & Agent Interfaces"]
        CLI["ariadns CLI (cli.py)\nrun / expand / report / manual-oob / doctor"]
        REPL["Interactive Console (repl.py)\nNode Inspection & L2 Extension"]
        MCP["MCP Server (mcp_server.py)\nosint_scan / inspect / expand / report / manual_oob"]
    end

    subgraph Orchestration ["Layer 3: Application Orchestrator"]
        M5["M5: Filter & Orchestrator (m5_orchestrator.py)\nBlacklists, Confidence Scoring, Evidence DAG Builder"]
    end

    subgraph Engines ["Layer 2: Domain Probing, Evidence & Reporting Modules"]
        M1["M1: Local Active Prober (m1_local_probe.py)\nDNS/RDAP Registrar, Banner, TLS, Favicon, HTML Tokens"]
        M2["M2: Subdomain Enumerator (m2_subdomain.py)"]
        M3["M3: Passive OSINT & Origin (m3_origin.py)"]
        M4["M4: Pivoting Engine (m4_pivoting.py)"]
        M6["M6: Reporting & Evidence Chain Engine (m6_reporting.py)\nresult.json, topology.json, evidence_chain.json, report.md"]
        M7["M7: Isolated Manual OOB Prober (m7_manual_oob.py)\nExplicit Human/Risk-Gated Callback Probe"]
    end

    subgraph Infra ["Layer 1: Storage, Graph & Utilities"]
        DB["SQLite + NetworkX Store\n(storage/db.py, storage/graph_store.py, storage/evidence_dag.py)"]
        NET["RateLimiter, Backoff HTTP, ASN Org Resolver, CLI Runner\n(utils/)"]
    end

    subgraph Models ["Layer 0: Core Domain Models"]
        MOD["Entities, Enums, PropositionNode, DataCustodian, Config\n(models/)"]
    end

    CLI --> M5
    CLI --> M7
    REPL --> M5
    MCP --> M5
    MCP --> M7
    CLI --> DB
    REPL --> DB
    MCP --> DB

    M5 --> M1 & M2 & M3 & M4 & M6
    M5 --> DB
    M7 --> NET & DB & MOD

    M1 & M2 & M3 & M4 --> NET & DB & MOD
    M6 --> DB & MOD
    NET & DB --> MOD
```

---

## 2. Causal Evidence Chain DAG Structure (Rendered in Reports)

```mermaid
flowchart TD
    subgraph Rank0 ["Rank 0: Base Observed Facts (觀測事實 A, B)"]
        F1["[FACT F1] DNS/HTTP: L1 現行解析 IP_CDN 且 Favicon/Title 特徵為 H1"]
        F2["[FACT F2] pDNS 歷史紀錄: L1 曾解析至非 CDN 之 IP_Origin"]
        F3["[FACT F3] Host Header 碰撞: IP_Origin 對 Host: L1 回傳相同特徵 H1"]
        F4["[FACT F4] Reverse IP 反查: IP_Origin 上同時綁定網域 Domain_L2"]
        F5["[FACT F5] L2 本地探測: Domain_L2 之 RDAP 註冊商為 R2、SOA 信箱為 E2"]
    end

    subgraph Rank1 ["Rank 1: First-Order Conclusions (因為 F1 + F2 + F3 所以 C1)"]
        C1["[CONCLUSION C1] IP_Origin 確認為 L1 之真實源站伺服器\n(Rule: RULE_ORIGIN_CONFIRMATION)"]
    end

    subgraph Rank2 ["Rank 2: Second-Order Conclusions (因為 C1 + F4 所以 C2)"]
        C2["[CONCLUSION C2] Domain_L2 與 L1 共用同一真實源站 IP_Origin\n(Rule: RULE_PIVOT_CORRELATION)"]
    end

    subgraph Rank3 ["Rank 3: Third-Order Conclusions (因為 C2 + F5 所以 C3)"]
        C3["[CONCLUSION C3] Domain_L2 之註冊紀錄 R2 與信箱 E2 為同源關聯節點\n(Rule: RULE_L2_EXTENSION)"]
    end

    subgraph Custodians ["Queryable Nodes & Data Custodians (C 對應可查節點與資料管理源)"]
        DC1["可查節點: IP_Origin\n資料管理源: ASN Org (ISP/Cloud)\n可查標的: 承租人 KYC、帳單金流、SSH/Console 登入 IP"]
        DC2["可查節點: Domain_L2\n資料管理源: Registrar R2 / NS 託管商\n可查標的: 網域申辦人資料、付款紀錄、DNS 後台登入 IP"]
        DC3["可查節點: Email E2\n資料管理源: 郵件服務商 / MX 主機商\n可查標的: 帳號註冊門號、備援信箱、SMTP 驗證紀錄"]
    end

    F1 & F2 & F3 --> C1
    C1 & F4 --> C2
    C2 & F5 --> C3

    C1 --> DC1
    C2 --> DC2
    C3 --> DC3
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
│       │   ├── enums.py            # OriginVerificationStatus, ConfidenceLevel, ModuleStatus, NodeType, EdgeType, PropositionKind
│       │   ├── entities.py         # IdentityProfile, Infrastructure, SubdomainRecord, PivotResult, L2Result, DataCustodian, PropositionNode, InvestigationResult
│       │   └── config.py           # AppConfig loader, blacklist defaults, secret masking helper
│       ├── utils/
│       │   ├── rate_limiter.py     # Sliding-window rate limiter & 2s/4s/8s exponential backoff HTTP client
│       │   ├── asn_cdn.py          # Built-in CDN CIDR/ASN matcher + Team Cymru DNS ASN & Org Name resolver
│       │   └── tool_runner.py      # External binary detector (`subfinder`, `httpx`, `nmap`) & `ariadns doctor` checks
│       ├── storage/
│       │   ├── db.py               # SQLite connection, 7-day TTL cache, quota tracker, read-only SQL executor
│       │   ├── graph_store.py      # SQLite `graph_nodes` / `graph_edges` + `networkx` topology
│       │   └── evidence_dag.py     # Chained Propositional Evidence DAG builder, acyclicity verifier & Data Custodian mapper
│       ├── modules/
│       │   ├── m1_local_probe.py   # DNS, RDAP (Registrant + Registrar), Banner, TLS CN/SAN, Favicon SHA-256, HTML Tracking Tokens, Port Scan
│       │   ├── m2_subdomain.py     # crt.sh + HackerTarget + subfinder -> httpx / native prober
│       │   ├── m3_origin.py        # CDN check, VT/OTX pDNS, Host header + Title/TLS/Favicon collision verification
│       │   ├── m4_pivoting.py      # Reverse IP, Reverse MX/NS, Reverse Token/Whois
│       │   ├── m5_orchestrator.py  # Noise filter, Graph weighting, L1->L2 pipeline, EvidenceChainDAG assembly
│       │   ├── m6_reporting.py     # Exports `result.json`, `topology.json`, `evidence_chain.json`, and `report.md` (with Mermaid Evidence DAG & Custodian tables)
│       │   └── m7_manual_oob.py    # Isolated manual-only OOB callback verifier (requires explicit OPSEC risk confirmation)
│       └── interfaces/
│           ├── cli.py              # CLI (`run`, `report`, `manual-oob`, `repl`, `doctor`, `init`)
│           ├── repl.py             # Interactive terminal menu
│           └── mcp_server.py       # FastMCP stdio server (`osint_scan`, `osint_inspect`, `osint_expand`, `osint_report`, `osint_manual_oob`)
└── tests/
    └── ...
```

---

## 4. Strict Import Directionality Rules (Forbidden Cycles)

1. **`ariadns.models`** (Layer 0): Imports Python standard library only.
2. **`ariadns.utils` & `ariadns.storage`** (Layer 1): Imports `ariadns.models` and third-party infra libraries (`dnspython`, `httpx`, `networkx`, `yaml`, `sqlite3`).
3. **`ariadns.modules.m1_*` .. `m4_*`, `m6_*`, `m7_*`** (Layer 2): Imports `ariadns.models`, `ariadns.utils`, `ariadns.storage`. Never imports `m5_orchestrator` or `ariadns.interfaces`.
4. **`ariadns.modules.m5_orchestrator`** (Layer 3): Coordinates `m1`..`m4`, `m6`, `storage`, `utils`, `models`. Never imports `m7_manual_oob` into automatic runs, and never imports `ariadns.interfaces`.
5. **`ariadns.interfaces.*` & `recon.py`** (Layer 4): Imports `ariadns.modules.*`, `ariadns.storage.*`, `ariadns.utils.*`, `ariadns.models.*`.
