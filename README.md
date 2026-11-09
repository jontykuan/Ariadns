# Ariadns: Automated Domain OSINT & Pivoting Engine

> **Ariadns** 是一套輕量、模組化且「本地優先（Local-First）」的網域開源情報（OSINT）探測與關聯分析系統。
> 支援「人類操作端口（CLI / 互動式 REPL）」與「AI Agent 自主驅動端口（Model Context Protocol / FastMCP）」，內建 SQLite 7 天 TTL 快取與圖譜拓撲運算。

---

## 系統核心架構

```mermaid
flowchart TD
    subgraph Interfaces ["操作端口 (Interfaces)"]
        CLI["人類 CLI (ariadns / recon.py)"]
        REPL["互動式終端控制台 (ariadns repl)"]
        MCP["Agent FastMCP Server (ariadns-mcp)"]
    end

    subgraph CoreEngine ["核心排程引擎 (Core Engine)"]
        M5["M5: 降噪過濾、置信度評分與遞迴控制器"]
        M1["M1: 本地 DNS/Banner/TLS/通訊埠探測"]
        M2["M2: 被動憑證透明度 & 子網域即時探測"]
        M3["M3: 歷史 pDNS 回溯與 Host 標頭源站穿透驗證"]
        M4["M4: 多維度樞紐反查 (Reverse IP/MX/NS/Token)"]
        M6["M6: 結構化匯出 (result.json, topology.json, report.md)"]
    end

    subgraph Storage ["狀態與圖譜 (Storage)"]
        SQLITE["SQLite (7 天 TTL 快取, 配額計數, 案件記錄)"]
        GRAPH["NetworkX 異質屬性圖 (邊權重累加, 置信度判定)"]
    end

    CLI --> M5
    REPL --> M5
    MCP --> M5
    M5 --> M1 & M2 & M3 & M4 & M6
    M1 & M2 & M3 & M4 & M6 --> SQLITE & GRAPH
```

---

## 一、安裝與環境準備

### 1. 系統需求
- Python 3.10+
- 支援環境：Windows 10/11、Linux (Ubuntu/Debian/CentOS)、macOS、WSL2

### 2. 套件安裝
```bash
git clone https://github.com/<your-username>/Ariadns.git
cd Ariadns

# 建立並啟動虛擬環境 (建議)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 安裝套件及依賴
pip install -e .
```

### 3. 本地外部工具檢查（非強制，系統支援原生自動降級）
Ariadns 原生支援純 Python 解析。若本機安裝有 ProjectDiscovery 的 `subfinder`、`httpx` 或 `nmap`，系統將自動調用以獲得最高性能：
```bash
ariadns doctor
```
- 若要一鍵安裝外部工具：
  - **Linux / macOS / WSL**: 執行 `bash scripts/install_tools.sh`
  - **Windows (PowerShell)**: 執行 `.\scripts\install_tools.ps1`

### 4. 設定檔初始化
```bash
ariadns init
```
此指令會從 `config.yaml.example` 複製產生 `config.yaml`（已列入 `.gitignore`，可在此填寫 VirusTotal、AlienVault OTX 等免費 API Key）。

---

## 二、人類使用說明書（Human Operator Manual）

Ariadns 為人類使用者提供兩種操作模式：**一鍵全流程 CLI** 與 **互動式 REPL 控制台**。

### 1. 一鍵全流程 CLI 模式

- **基礎掃描（L1 網域）**：
  ```bash
  ariadns run -d example.com --output-dir ./reports
  ```
  *(相容原始需求指令：`python recon.py -d example.com --no-portscan`)*

- **二級關聯深度掃描（L1 + 高信度 L2 遞迴）**：
  ```bash
  ariadns run -d example.com --depth 2 --output-dir ./reports
  ```

- **啟用通訊埠探測（針對非 CDN IP）**：
  ```bash
  ariadns run -d example.com
  # 預設 --no-portscan 會跳過通訊埠掃描，不加該參數或在配置中啟用即會掃描非 CDN 目標
  ```

### 2. 互動式 REPL 控制台模式

適合分析人員「先看初步拓撲、再挑選特定二級資產手動深入擴展」：
```bash
ariadns repl
```
**REPL 內建常用指令**：
- `target <domain>`：指定當前調查的目標主網域（如 `target example.com`）。
- `scan [depth]`：對目標執行掃描（`depth 1` 或 `depth 2`）。
- `nodes`：列出該案件在圖譜中已記錄的所有節點（IP、子網域、Token、Email、MX 等）。
- `l2`：列出經樞紐反查挖掘出的所有 L2 網域及其置信度評分（`HIGH` / `MEDIUM` / `LOW`）。
- `expand <l2_domain>`：針對指定的高價值 L2 網域發起深度二次探測，並自動將新發現節點合併至主拓撲圖。
- `help` / `exit`：查看說明或退出。

### 3. 輸出報告說明
執行完畢後，預設於指定目錄（如 `./reports/`）產出標準鑑識檔案：
1. `<domain>_result.json`：符合 SRS Section 5.2 規範之純資料結構。
2. `<domain>_topology.json`：Cytoscape.js 與 D3.js 相容之節點/關聯邊拓撲圖檔案。
3. `<domain>_evidence.svg` / `<domain>_evidence.png`：純 Python 渲染之靜態非拖拽證據架構圖，附帶密碼學浮水印戳記。
4. `<domain>_manifest.json`：包含所有檔案雙層 SHA-256 摘要與狀態 Payload Hash 之鑑識清單。
5. `<domain>_report.md`：人類可讀之 Markdown 鑑識評估報告（包含個資、CDN 穿透、子網域、調閱機關矩陣與稽核日誌）。

### 4. 本地視覺鑑識工作台（Local Web UI Workbench）

包裝完整 CLI 能力的高密度視覺化操作介面（遵循 Impeccable 設計系統，零無效卡片）：
```bash
ariadns ui --port 8000 --open-browser
```
**工作台核心介面特性**：
- **頂部輕量狀態列**：即時顯示目前執行項目（Module）、標的（Target）、進度（Status）、已過秒數（Elapsed），以及 7 天 MISP 誤報清單同步狀態。
- **可視化操作指令卡片（CLI Command Cards）**：視覺化包裝 M1、M2、M3、M4 與 M7 指令，清楚說明使用目的、CLI 等價語法，並針對主動探測（M7）設置嚴格 OPSEC 風險確認閥門。
- **下一步調查建議面板（Next-Step Recommendations）**：由當前案件事實自動推導規則建議，一鍵「Apply & Run」分步執行。
- **證據節點篩選與主動畫圖（Deferred Rendering）**：分步執行時不即時運算圖檔以保證排版不崩潰；在主動點選「Generate Evidence Architecture Graph」前，使用者可勾選核心節點（預設已勾選核心成果，略過雜訊），生成不可動之純靜態圖檔與 SHA-256 戳記。
- **三大結構化鑑識矩陣**：
  - **Data Custodians Matrix**：依命題節點標的自動對應法規調閱機關（Registrar、CDN 業者、主機商、平台商）與可調閱紀錄清單。
  - **Session Audit Trail**：記錄每次分步執行步驟、時間戳、模組、標的、新增 Fact ID 與狀態 Hash。
  - **Cryptographic Manifest & Integrity**：呈現所有檔案雜湊，一鍵發起雙層 SHA-256 位元級驗證。

### 5. 分步執行與鑑識驗證 CLI 指令集

- **分步推進工作階段（Stepwise Execution）**：
  ```bash
  ariadns step -d example.com -m m1
  ariadns step -d example.com -m m2
  ariadns step -d example.com -m m3
  ariadns step -d example.com -m m4 --target 1.2.3.4
  ```
- **取得下一步調查建議（Next-Step Inference）**：
  ```bash
  ariadns recommend -d example.com
  ```
- **生成靜態證據圖譜與清單（Render Evidence Graph）**：
  ```bash
  ariadns render-graph -d example.com --select F1,C1,F_ORIGIN,C_ORIGIN
  ```
- **檢視結構化命題與稽核日誌（Show Graph Propositions）**：
  ```bash
  ariadns show-graph -d example.com
  ```
- **檔案密碼學完整性驗證（Forensic Verification Tool）**：
  ```bash
  ariadns verify --case-dir ./reports/example.com
  ```
- **手動同步 7 天 MISP 誤報特徵清單**：
  ```bash
  ariadns sync-lists --force
  ```

---

## 三、AI Agent 驅動說明書（Agentic MCP Manual）

Ariadns 內建遵循 Model Context Protocol（MCP）標準的 stdio 伺服器，專為 Claude、Antigravity（agy）、Cursor 等 LLM Agent 設計。

### 1. Token 節流設計原則（Summary-First Architecture）
為防止大網域（數百個子網域與反查記錄）灌爆 Agent Context Window：
- **`osint_scan` 與 `osint_expand`**：所有原始資料全量存入本機 SQLite，**回傳給 Agent 的僅為高密度摘要（$\le 600$ tokens）**。
- **`osint_inspect`**：Agent 僅在需要細節時，才依需求查詢「局部鄰居節點」、「特定 L2 候選」或執行「唯讀 SQL」。

### 2. MCP 工具清單（Tools）

| 工具名稱 | 參數 | 功能說明與回傳範疇 |
| :--- | :--- | :--- |
| **`osint_scan`** | `domain: str`<br>`depth: int = 1`<br>`portscan: bool = False`<br>`mode: str = "full"` | 對指定網域發起全自動情報探測。回傳精簡 JSON 摘要（包含 CDN 狀態、真實 IP 推斷、管理員信箱、Top 10 關聯網域）。 |
| **`osint_inspect`** | `domain: str`<br>`query_type: str = "summary"`<br>`target_node: str = ""`<br>`sql_query: str = ""` | 零運算直接讀取 SQLite 4 張正規化證據表。支援 `"summary"`、`"neighbors"`、`"l2_candidates"`、`"evidence_chain"`、`"custodians"`，以及以 `mode=ro` 執行的唯讀 `"sql"`。預設僅撈取繪製節點，嚴格限制回傳 $\le 500$ Tokens。 |
| **`osint_run_step`** | `session_id: str`<br>`module_name: str`<br>`target: str`<br>`params: dict` | 分步執行指定模組（`m1`, `m2`, `m3`, `m4`, `m7`），將新事實增量合併入案件資料庫，並產生不可變稽核日誌（不自動畫圖）。 |
| **`osint_recommend_next`** | `session_id: str` | 依據當前已發掘之事實（如 CDN 存在、非 CDN IP 發現、未探測二級網域）推導具最高優先級之下一步調查建議。 |
| **`osint_render_graph`** | `session_id: str`<br>`output_dir: str = "./reports"`<br>`selected_prop_ids: list[str] = None` | 依據指定（或預設核心）命題節點集合，在磁碟上生成靜態 SVG/PNG 與 `_manifest.json`，並回傳 `payload_sha256`。 |
| **`osint_read_evidence_graph`** | `session_id: str`<br>`rendered_only: bool = True`<br>`limit: int = 20` | Agent 專用結構化因果 DAG 檢索小工具。直讀 `evidence_propositions` 與 `evidence_custodians`，防止讀取龐大圖像原始碼導致 Context 溢出。 |
| **`osint_verify_case`** | `case_dir: str` | 針對案卷資料夾執行雙層 SHA-256 驗證（包含各實體檔案 Hash 與 DAG 狀態 Payload Hash），驗證產出物未遭篡改。 |
| **`osint_sync_lists`** | `force: bool = False` | 同步或檢查 7 天 MISP 停車網域與共享郵箱清單，離線時自動回退本機快取與靜態黑名單。 |
| **`osint_expand`** | `parent_domain: str`<br>`l2_domain: str` | 對特定 L2 網域進行深度展開，並將節點合併至主圖譜。 |
| **`osint_report`** | `domain: str`<br>`output_dir: str = "./reports"` | 觸發在磁碟上產生 JSON、Topology、SVG/PNG 與 Markdown 報告，並回傳絕對路徑給 Agent。 |

### 3. MCP 唯讀資源（Resources）
- `ariadns://sessions`：列出 SQLite 中所有歷史調查案件與時間戳。
- `ariadns://graph/{domain}/summary`：即時檢視目標網域的圖譜節點與邊數統計。

### 4. 如何在 Agent 環境中註冊 Ariadns MCP

#### 在 Claude Desktop / Antigravity / Cline 設定
將以下內容新增至你的 MCP 設定檔（例如 `claude_desktop_config.json` 或本機 IDE 的 MCP 設定中）：

```json
{
  "mcpServers": {
    "ariadns": {
      "command": "python",
      "args": [
        "-m",
        "ariadns.interfaces.mcp_server"
      ],
      "cwd": "d:/cykuan/geminiCLI/DNSA"
    }
  }
}
```
*(若在虛擬環境中，可將 `command` 替換為虛擬環境內的 Python 執行檔路徑)*

### 5. Agent 典型驅動範例情境
1. **Agent 發起初探**：
   `Call osint_scan(domain="target-company.com", depth=1)`
   Agent 取得摘要：發現目標使用 Cloudflare 防護，並自 SOA 記錄中取得 `sec-admin@target-company.com`。
2. **Agent 擴展二級樞紐**：
   `Call osint_inspect(domain="target-company.com", query_type="l2_candidates")`
   Agent 發現高信度關聯網域 `internal-portal.net`。
3. **Agent 深入穿透**：
   `Call osint_expand(parent_domain="target-company.com", l2_domain="internal-portal.net")`
   成功穿透並獲取真實源站 IP。
4. **Agent 產出總結報告**：
   `Call osint_report(domain="target-company.com")`
   回傳 Markdown 報告檔案路徑，向使用者交付調查結論。

---

## 四、安全與防禦規範（OPSEC）

1. **API Key 遮罩**：所有控制台輸出與日誌紀錄一律對 API Key 實施 `abc***` 遮罩處理。
2. **7 天 TTL 熔斷保護**：相同查詢 7 天內全數命中 SQLite 快取，零重複發送外部請求。
3. **公共服務過濾**：自動阻斷 Google Workspace、Microsoft Outlook、Cloudflare 等知名郵件/名稱伺服器的無效反查，避免關聯膨脹。
4. **SQL 防護**：Agent 透過 `osint_inspect` 執行 SQL 時，底層強制以 SQLite `mode=ro` 唯讀連線執行，嚴禁變更資料庫。

---

## 五、授權條款
MIT License.
