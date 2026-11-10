# Ariadns: Automated Domain OSINT & Pivoting Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Release v1.0.4](https://img.shields.io/badge/release-v1.0.4-green.svg)](https://github.com/jontykuan/Ariadns/releases)
[![CI](https://github.com/jontykuan/Ariadns/actions/workflows/ci.yml/badge.svg)](https://github.com/jontykuan/Ariadns/actions)

**Ariadns** 是一套本地優先（Local-First）的網域開源情報（OSINT）探測、因果證據鏈推導與法規調閱機關對應工具。支援命令列（CLI）、互動式終端（REPL）、本機網頁操作介面（Web UI）以及 Model Context Protocol（FastMCP）伺服器。

---

## 【中文版使用手冊】

## 一、安裝與環境準備

### 1. 系統需求
- Python 3.10+
- 作業系統：Windows 10/11、Linux (Ubuntu/Debian/CentOS)、macOS、WSL2

### 2. 安裝步驟
```bash
git clone https://github.com/jontykuan/Ariadns.git
cd Ariadns

# 建立並啟動虛擬環境
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# 安裝套件
pip install -e .
```

### 3. 外部輔助工具檢查（選用）
Ariadns 內建純 Python 原生解析器。若系統安裝有 `subfinder`、`httpx` 或 `nmap`，將自動調用以提升掃描速度：
```bash
ariadns doctor
```
如需自動安裝外部工具，可執行：
- **Linux / macOS / WSL**: `bash scripts/install_tools.sh`
- **Windows (PowerShell)**: `.\scripts\install_tools.ps1`

### 4. 初始化設定檔與 API 金鑰說明 (Zero-Key 原生架構)
```bash
ariadns init
```
此指令會由 `config.yaml.example` 複製產生 `config.yaml`。

> **免金鑰架構（Zero-Key Native Architecture）**：  
> Ariadns **完全無需任何第三方 API Key 即可開箱即用**！內建原生整合：
> - **BGP / ASN 映射**：Team Cymru (whois/DNS 協定，免費無金鑰)
> - **子網域枚舉**：crt.sh 憑證透明度紀錄 (免費無金鑰)
> - **特徵與憑證探測**：原生 TLS/SSL 握手與 HTTP 伺服器指紋擷取

#### 選用第三方情資 API 金鑰清單
若需擴充長週期歷史 Passive DNS 解析、IP 歷史反查或 HTML 代碼 Token 關聯，可於 `config.yaml` 填入選用金鑰：

| 服務名稱 | 設定鍵名 (`config.yaml`) | 主要調查用途 | 免費額度與申請連結 |
| :--- | :--- | :--- | :--- |
| **VirusTotal** | `virustotal` | 歷史解析記錄、惡意樣本與網域標籤關聯 | 4 次/分，500 次/天 ([申請連結](https://www.virustotal.com/gui/join-us)) |
| **AlienVault OTX** | `alienvault_otx` | 威脅情資交換、被動 DNS 與關聯脈衝 (Pulses) | 免費社群版，無嚴格每分鐘限制 ([申請連結](https://otx.alienvault.com/)) |
| **SecurityTrails** | `securitytrails` | 權威歷史 DNS 與全量子網域歷程反查 | 免費 50 次月查詢 ([申請連結](https://securitytrails.com/)) |
| **WhoisXML API** | `whoisxml` | 歷史 WHOIS 資料比對與精確註冊人關聯 | 免費 500 次初始點數 ([申請連結](https://whoisxmlapi.com/)) |
| **ViewDNS.info** | `viewdns` | 反向 IP、反向 NS 與反向 MX 歷史交叉比對 | 免費 250 次查詢 ([申請連結](https://viewdns.info/)) |
| **HackerTarget** | `hackertarget` | 輕量外部反查與主機探測管道 | 免費 50 次/天 IP 反查 ([申請連結](https://hackertarget.com/)) |
| **PublicWWW** | `publicwww` | 網頁源碼特徵與 Snippet Token 追蹤 | 免費查詢與代碼比對 ([申請連結](https://publicwww.com/)) |

---

## 二、操作說明（CLI / Web UI / REPL）

### 0. 輔助說明指令
可隨時透過以下指令查看完整子指令說明與 API 設定提示：
```bash
ariadns help
ariadns /h
ariadns --help
```

### 1. 一鍵全流程掃描（CLI）

- **基礎掃描（單一主網域）**：
  ```bash
  ariadns run -d example.com --output-dir ./reports
  ```

- **二級關聯深度掃描（自動展開高信度關聯網域）**：
  ```bash
  ariadns run -d example.com --depth 2 --output-dir ./reports
  ```

- **跳過通訊埠掃描**：
  ```bash
  ariadns run -d example.com --no-portscan --output-dir ./reports
  ```

### 2. 分步調查與驗證指令（CLI）

- **單步執行指定探測模組**：
  每次執行單一模組並將發掘之事實與結論寫入本地案件資料庫：
  ```bash
  # M1: 基礎 DNS、BGP/ASN 歸屬、TLS 憑證與 HTTP 標頭探測
  ariadns step -d example.com -m m1

  # M2: 被動憑證透明度 (CT) 與子網域枚舉
  ariadns step -d example.com -m m2

  # M3: 歷史 DNS 回溯與 CDN 源站碰撞驗證
  ariadns step -d example.com -m m3

  # M4: 反向 IP / MX / NS / 頁面特徵共構關聯反查
  ariadns step -d example.com -m m4 --target 1.2.3.4
  ```

- **查詢下一步調查建議**：
  根據目前已收集的事實，列出建議執行的下一步模組與參數：
  ```bash
  ariadns recommend -d example.com
  ```

- **檢視案件命題與執行歷程**：
  ```bash
  ariadns show-graph -d example.com
  ```

- **生成靜態證據結構圖（SVG / PNG）**：
  可指定欲納入圖面的命題節點 ID（未指定則預設繪製核心節點），並支援開關顏色提示與圖例說明：
  ```bash
  ariadns render-graph -d example.com --select F1,C1,F_ORIGIN,C_ORIGIN
  ariadns render-graph -d example.com --no-color --no-legend
  ```

- **主動路由躍遷追蹤（需加上 `--ack-risk` 確認主動發包風險）**：
  對目標網域或 IP 執行路由追蹤（預設不解析主機名稱 `-d`、最大 20 跳 `-H 20`、逾時 500ms `-w 500`、擷取最末 3 跳 `--tail-hops 3`），自動查詢公網路由節點之 ASN 與 ISP 歸屬：
  ```bash
  ariadns trace -d example.com --target 182.173.0.181 -H 20 -w 500 --tail-hops 3 --ack-risk
  ```

- **手動 Out-of-Band 回連探測（需加上 `--ack-risk` 確認主動發包風險）**：
  ```bash
  ariadns manual-oob -t https://target.com/preview -c https://your-listener.com/callback --ack-risk
  ```

- **校驗案件產出物完整性（SHA-256）**：
  驗證報告目錄下所有檔案雜湊與資料庫狀態雜湊是否一致：
  ```bash
  ariadns verify --case-dir ./reports/example.com
  ```

- **手動更新 MISP 共享設施與停車網域排除清單**：
  ```bash
  ariadns sync-lists --force
  ```

### 3. 本地網頁操作介面（Web UI）

啟動本機網頁工作台：
```bash
ariadns ui --host 127.0.0.1 --port 8000 --open-browser
```

**介面操作方式**：
1. **案件與目標選擇**：
   - 於頂部「目標範圍」輸入欲調查的網域或 IP，或從「歷史案件」下拉選單載入既有案件。
   - 點擊「自動執行」將依序執行 M1 至 M4 探測並自動繪製證據結構圖。
2. **左側分步模組與主動探測**：
   - 點擊 `M1`、`M2`、`M3`、`M4` 卡片可單步執行對應探測模組。
   - 點擊「路由躍遷追蹤」或「手動回連探測」會彈出參數設定與風險確認視窗，勾選確認後即可執行。
3. **證據節點篩選與生成證據結構圖**：
   - 於左側「證據節點」清單勾選欲呈現在圖面上的事實（Fact）與結論（Conclusion）節點。
   - 下方可勾選或取消「顏色提示」（依節點與連線性質套用四色外框與三種線型）與「圖例說明」（於圖面右上角繪製圖例）。
   - 點擊「生成證據結構圖」即可在右側畫布產出靜態 SVG / PNG 證據圖譜（依 4:3 ~ 16:9 人類舒適比例自動排版折行，繪圖區支援滑鼠滾輪縮放、左鍵拖曳平移與雙擊/點擊按鈕重置視角）。
4. **建議下一步與批次執行**：
   - 系統依據當前進度列出建議步驟並顯示 `(n/MAX)項建議`，可勾選欲執行的建議項目後點擊「批次執行」，或點擊單一建議項目上的「套用並執行」。
5. **下方鑑識報表分頁**：
   - **資料保管者調閱矩陣**：列出各節點對應之註冊商、CDN、電信機房或雲端業者與可調閱之紀錄類型。
   - **調查步驟歷程**：顯示每一步執行的時間、模組、標的、新增命題數與狀態雜湊值。
   - **數位鑑識清單與雜湊驗證**：顯示產出檔案之 SHA-256 清單，點擊「執行完整性驗證」可立即檢驗檔案是否遭更動。

### 4. 互動式終端控制台（REPL）
```bash
ariadns repl
```
常用指令：
- `target <domain>`：設定目前調查目標網域。
- `scan [depth]`：執行掃描（`depth` 為 `1` 或 `2`）。
- `nodes`：列出目前已記錄的所有節點。
- `l2`：列出反查發現之關聯二級網域與信度評分。
- `expand <l2_domain>`：對指定關聯網域執行深度展開。
- `help` / `/h` / `?` / `exit`：顯示說明或離開。

### 5. 輸出檔案說明
案件輸出預設存放於 `./reports/<domain>/`（或 `./reports/`）：
- `<domain>_result.json`：完整探測結構化資料。
- `<domain>_topology.json`：節點與關聯拓撲資料（相容 Cytoscape.js / D3.js）。
- `<domain>_evidence.svg` / `<domain>_evidence.png`：靜態因果證據結構圖（含時間戳記與 `payload_sha256` 校驗碼）。
- `<domain>_manifest.json`：所有輸出檔案之 SHA-256 雜湊清單與狀態驗證碼。
- `<domain>_report.md`：Markdown 格式完整調查報告（含調閱單位對照表與步驟歷程）。

---

## 三、AI Agent 接入說明（FastMCP Server）

Ariadns 內建標準 stdio MCP 伺服器，可供支援 MCP 的 AI Agent 直接調用。

### 1. 設定方式
於 Agent 的 MCP 設定檔（例如 `claude_desktop_config.json` 或 `mcp_config.json`）加入：
```json
{
  "mcpServers": {
    "ariadns": {
      "command": "python",
      "args": ["-m", "ariadns.interfaces.mcp_server"],
      "cwd": "/path/to/Ariadns"
    }
  }
}
```

### 2. 可用 MCP 工具一覽

| 工具名稱 | 參數 | 用途說明 |
| :--- | :--- | :--- |
| **`osint_scan`** | `domain: str`<br>`depth: int = 1`<br>`portscan: bool = False`<br>`mode: str = "full"` | 執行全流程掃描並將結果存入 SQLite，回傳精簡摘要（CDN 狀態、疑似源站 IP、註冊商、前 10 個高信度關聯網域）。 |
| **`osint_inspect`** | `domain: str`<br>`query_type: str = "summary"`<br>`target_node: str = ""`<br>`sql_query: str = ""` | 直接查詢本地案件資料庫。`query_type` 支援 `"summary"`、`"neighbors"`、`"l2_candidates"`、`"evidence_chain"`、`"custodians"` 及唯讀 `"sql"`。 |
| **`osint_run_step`** | `session_id: str`<br>`module_name: str`<br>`target: str = ""`<br>`params: dict = None` | 單步執行指定探測模組（`m1`、`m2`、`m3`、`m4`、`trace`、`m7`），並將發現的事實增量寫入案件資料庫。 |
| **`osint_trace`** | `session_id: str`<br>`target: str = ""`<br>`max_hops: int = 20`<br>`timeout_ms: int = 500`<br>`tail_hops: int = 3`<br>`no_rdns: bool = True`<br>`acknowledge_risk: bool = False` | 執行主動路由躍遷追蹤（需將 `acknowledge_risk` 設為 `True`），解析最末跳機房 ASN 並寫入證據鏈。 |
| **`osint_recommend_next`** | `session_id: str` | 根據案件目前已收集的事實，回傳建議的下一步探測動作。 |
| **`osint_render_graph`** | `session_id: str`<br>`output_dir: str = "./reports"`<br>`selected_prop_ids: list[str] = None`<br>`color_coding: bool = True`<br>`show_legend: bool = True` | 將案件命題渲染為靜態 SVG 與 PNG 證據圖譜並產生 `_manifest.json`。 |
| **`osint_read_evidence_graph`** | `session_id: str`<br>`rendered_only: bool = True`<br>`limit: int = 20` | 讀取結構化命題節點、推導連線與資料保管者清單。 |
| **`osint_verify_case`** | `case_dir: str` | 驗證指定案件資料夾內所有檔案與資料庫狀態之 SHA-256 完整性。 |
| **`osint_sync_lists`** | `force: bool = False` | 同步 MISP 停車網域與共享基礎設施排除清單。 |
| **`osint_expand`** | `parent_domain: str`<br>`l2_domain: str` | 對指定的二級關聯網域進行深度展開並合併回主案件。 |
| **`osint_report`** | `domain: str`<br>`output_dir: str = "./reports"` | 匯出完整 JSON、SVG、PNG 與 Markdown 報告並回傳檔案路徑。 |

---

## 四、操作安全注意事項（OPSEC）

1. **API Key 自動遮罩**：所有終端輸出與日誌皆自動遮罩 API Key。
2. **本地快取機制**：相同查詢於 7 天內優先讀取本機 SQLite 快取，減少重複外部請求。
3. **共享基礎設施過濾**：自動排除 Google Workspace、Microsoft 365、Cloudflare 等大型共用郵件與名稱伺服器，避免無關網域誤關聯。
4. **唯讀 SQL 查詢保護**：透過 `osint_inspect` 執行自訂 SQL 時，強制以唯讀模式（`mode=ro`）連線。
5. **主動探測確認機制**：`trace`（路由追蹤）與 `manual-oob`（回連測試）預設不會在一般掃描中自動觸發，必須明確傳入 `--ack-risk`（或於 UI 勾選風險確認）才會發送探測封包。

---

## 【English User Manual】

## 1. Installation & Setup

### Prerequisites
- Python 3.10+
- OS: Windows 10/11, Linux, macOS, WSL2

### Install
```bash
git clone https://github.com/jontykuan/Ariadns.git
cd Ariadns

python -m venv .venv
# Windows PowerShell:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

pip install -e .
```

### Environment Check & API Configuration (Zero-Key Architecture)
```bash
# Check optional external binaries (subfinder, httpx, nmap)
ariadns doctor

# Create config.yaml from config.yaml.example
ariadns init

# Display help and subcommands
ariadns help
ariadns /h
```

> **Zero-Key Architecture**:  
> Ariadns works **100% out-of-the-box without any external API keys**. Native engines include:
> - **BGP / ASN Mapping**: Team Cymru (DNS/whois protocol, free, keyless)
> - **Subdomain Enumeration**: crt.sh Certificate Transparency logs (free, keyless)
> - **Probers**: Local DNS recursive resolution, TLS certificate inspection, and HTTP header fingerprinters.

#### Optional Third-Party Threat Intelligence Keys
For historical passive DNS, reverse IP pivot history, or HTML snippet tracking, configure optional keys in `config.yaml`:

| Service | Key in `config.yaml` | Investigation Role | Free Quota & Signup |
| :--- | :--- | :--- | :--- |
| **VirusTotal** | `virustotal` | Historical resolutions, malicious telemetry, and domain tags | 4 req/min, 500 req/day ([Sign up](https://www.virustotal.com/gui/join-us)) |
| **AlienVault OTX** | `alienvault_otx` | Threat intelligence community pulses and passive DNS | Free community tier ([Sign up](https://otx.alienvault.com/)) |
| **SecurityTrails** | `securitytrails` | Historical DNS records and comprehensive subdomain index | 50 queries/month ([Sign up](https://securitytrails.com/)) |
| **WhoisXML API** | `whoisxml` | Historical WHOIS records and registrant pivot tracking | 500 initial queries ([Sign up](https://whoisxmlapi.com/)) |
| **ViewDNS.info** | `viewdns` | Reverse IP, reverse NS, and reverse MX lookups | 250 queries ([Sign up](https://viewdns.info/)) |
| **HackerTarget** | `hackertarget` | Lightweight external reverse IP lookup | 50 lookups/day ([Sign up](https://hackertarget.com/)) |
| **PublicWWW** | `publicwww` | Source code and HTML token pivot discovery | Free tier search & code matching ([Sign up](https://publicwww.com/)) |

---

## 2. CLI Usage

### 2.1 One-Shot Investigation
```bash
# Standard scan (Root domain)
ariadns run -d example.com --output-dir ./reports

# Deep scan (Expands high-confidence correlated L2 domains)
ariadns run -d example.com --depth 2 --output-dir ./reports

# Skip port scanning on non-CDN IPs
ariadns run -d example.com --no-portscan --output-dir ./reports
```

### 2.2 Stepwise Investigation & Graph Rendering
```bash
# Stepwise module execution
ariadns step -d example.com -m m1
ariadns step -d example.com -m m2
ariadns step -d example.com -m m3
ariadns step -d example.com -m m4 --target 198.51.100.24

# Get recommended next steps based on current findings
ariadns recommend -d example.com

# View recorded propositions and audit trail
ariadns show-graph -d example.com

# Render static SVG/PNG evidence graph
ariadns render-graph -d example.com --select F1,C1,F_ORIGIN,C_ORIGIN
ariadns render-graph -d example.com --no-color --no-legend

# Active traceroute hop analysis (requires --ack-risk)
ariadns trace -d example.com --target 182.173.0.181 -H 20 -w 500 --tail-hops 3 --ack-risk

# Manual out-of-band callback probe (requires --ack-risk)
ariadns manual-oob -t https://target.com/preview -c https://your-listener.com/probe --ack-risk

# Verify cryptographic integrity of exported case files
ariadns verify --case-dir ./reports/example.com

# Update MISP false-positive warninglists
ariadns sync-lists --force
```

---

## 3. Local Web UI

Launch the local web interface:
```bash
ariadns ui --host 127.0.0.1 --port 8000 --open-browser
```

- **Target & Case Selection**: Enter a domain/IP in the target input or select a previous investigation from the history dropdown. Click **Auto Run** (`自動執行`) to run M1 through M4 sequentially and render the evidence diagram.
- **Stepwise & Active Modules**: Run `M1`, `M2`, `M3`, or `M4` individually, or click **Route Trace** (`路由躍遷追蹤`) / **Manual OOB** (`手動回連探測`) to configure parameters and acknowledge OPSEC risk in a modal dialog.
- **Evidence Graph Controls**: Filter proposition nodes in the left panel, toggle **Color Coding** (`顏色提示`) and **Show Legend** (`圖例說明`), and click **Generate Evidence Graph** (`生成證據結構圖`) to render static SVG/PNG diagrams (balanced to a 4:3 ~ 16:9 aspect ratio; viewport supports mouse wheel zoom, left-click pan, and double-click/button zoom reset).
- **Forensic Tables**: Review the **Data Custodians Matrix**, **Session Audit Trail**, and **Cryptographic Manifest** in the bottom tabs.

---

## 4. Interactive REPL Console
```bash
ariadns repl
```
Commands: `target <domain>`, `scan [depth]`, `nodes`, `l2`, `expand <domain>`, `help`, `/h`, `?`, `exit`.

---

## 5. Output Files
Generated in `./reports/<domain>/` (or `./reports/`):
- `<domain>_result.json`: Structured OSINT dataset.
- `<domain>_topology.json`: Cytoscape.js / D3.js compatible graph JSON.
- `<domain>_evidence.svg` & `<domain>_evidence.png`: Static evidence diagrams with `payload_sha256` watermark.
- `<domain>_manifest.json`: Dual-layer SHA-256 file and state manifest.
- `<domain>_report.md`: Human-readable Markdown report with custodian disclosure tables and audit history.

---

## 6. FastMCP Server Configuration

Add to your MCP client configuration:
```json
{
  "mcpServers": {
    "ariadns": {
      "command": "python",
      "args": ["-m", "ariadns.interfaces.mcp_server"],
      "cwd": "/path/to/Ariadns"
    }
  }
}
```

Available tools: `osint_scan`, `osint_inspect`, `osint_run_step`, `osint_trace`, `osint_recommend_next`, `osint_render_graph`, `osint_read_evidence_graph`, `osint_verify_case`, `osint_sync_lists`, `osint_expand`, `osint_report`.

---

## 7. License & Disclaimers

### License
Released under the [MIT License](LICENSE).

### AI-Assisted Development Notice & Disclaimer (AI 輔助生成與開發聲明)
This project was developed with the assistance of artificial intelligence systems (including Google Antigravity and autonomous agent orchestration pipelines). All architecture, business logic, and code slices undergo human verification and strict automated Test-Driven Development (TDD) gates.

**Legal & Operational Disclaimer**:
Ariadns is designed solely for legitimate domain intelligence, cybersecurity defense, digital forensics, and academic research. Users are strictly responsible for adhering to applicable local and international laws when conducting network scans. The authors and contributors assume no liability for misuse.
