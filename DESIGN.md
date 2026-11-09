# Ariadns Forensic Workbench Design System (`DESIGN.md`)

## 1. Design Direction & Surface Mode
- **Surface Mode**: **Operate** (OSINT Investigation & Forensic Evidence Workbench).
- **Core Directive**: Dense, utilitarian, high-contrast, zero generic AI cards/gradients. Built for security analysts and forensic investigators examining evidence chains and data custodians.
- **Visual Truth**: Monospaced cryptographic hashes, strictly bordered tabular data, distinct status indicators, and non-draggable deterministic SVG/PNG diagram display with cryptographic watermark verification.

---

## 2. Token System

### 2.1 Color Palette
- **Canvas / Background**: `#090d16` (Deep Obsidian Navy)
- **Surface 1 (Header, Sidebars, Main Panels)**: `#0f172a` (Slate 900)
- **Surface 2 (Command Cards, Modals, Table Rows)**: `#1e293b` (Slate 800)
- **Surface Active / Hover**: `#24334a`
- **Border Default**: `#334155` (Slate 700)
- **Border Focus / Accent**: `#38bdf8` (Sky 400)
- **Text Primary**: `#f8fafc` (Slate 50)
- **Text Secondary**: `#94a3b8` (Slate 400)
- **Text Muted / Timestamp**: `#64748b` (Slate 500)
- **Status / Accent**:
  - **Verified / Success**: `#22c55e` (Emerald 500)
  - **OPSEC Warning / Attention**: `#eab308` (Amber 500)
  - **Critical / Mismatch / Danger**: `#ef4444` (Red 500)
  - **Action / Command / Focus**: `#38bdf8` (Sky 400)
  - **Badge Background (Verified)**: `rgba(34, 197, 94, 0.12)`
  - **Badge Background (Warning)**: `rgba(234, 179, 8, 0.12)`
  - **Badge Background (Danger)**: `rgba(239, 68, 68, 0.12)`

### 2.2 Typography
- **UI / Headings / Body**:
  `system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif`
- **Monospace (Hashes, CLI Syntax, Identifiers, Timestamps, Tables)**:
  `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace`
- **Scale**:
  - Page Title / Header: `16px` / `1.3` (Semibold 600)
  - Section Headings: `14px` / `1.4` (Medium 500, uppercase letter-spacing: `0.05em`)
  - Body / Data: `13px` / `1.5` (Regular 400)
  - Monospace Data / Code: `12px` / `1.4`
  - Badges / Status Tags: `11px` / `1.2` (Semibold 600, uppercase)

### 2.3 Layout & Spacing Rhythm
- **Top Status Bar**: Compact fixed height (`44px`), border-bottom `1px solid #334155`, displays:
  - Active Session Domain
  - Active Module & Target
  - Execution Status & Stage Progress
  - Elapsed Time Counter
  - 7-Day Warninglist Sync Badge
- **Two-Column Workbench Grid**:
  - Left Panel (`420px` width):
    - Visual CLI Command Cards (M1, M2, M3, M4, M7 with OPSEC warning)
    - Next-Step Recommendations with direct "Run Step" execution trigger
    - Node Selection Matrix (filter propositions before rendering)
  - Right Panel (Flexible):
    - Evidence Architecture Graph Display (rendered static SVG/PNG, zoom preview, payload SHA-256 watermark)
    - Tabbed Forensic Matrices:
      1. Data Custodians Matrix
      2. Stepwise Session Audit Trail
      3. Cryptographic Artifact Manifest & Verification Badge

---

## 3. Component Standards

### 3.1 Visual CLI Command Cards
- Every card visually documents:
  - Module ID and Name (e.g. `M1 Local DNS & Identity Probe`)
  - Equivalent CLI Command (`ariadns step -d <session> -m m1`)
  - Investigation Purpose
  - Parameters input form
  - Direct "Execute" button with state spinner
  - For M7: Prominent OPSEC warning badge requiring explicit risk checkbox.

### 3.2 Next-Step Recommendation Panel
- Rule-based dynamic cards with:
  - Recommendation ID & Module
  - Triggering Fact IDs
  - Rationale & Expected Evidence
  - Instant "Apply & Run" button

### 3.3 Evidence Proposition Filter & Deferred Graph Rendering
- Grouped propositions with checkboxes:
  - Core nodes (`CONFIRMED` origins, L2 High, Custodian conclusions) default to `CHECKED`.
  - Noise / subdomains default to `UNCHECKED`.
  - Primary button: `Generate Evidence Architecture Graph` (initiates `POST /api/render`).

### 3.4 Static Forensic Graph & Watermark Display
- Display area: non-draggable, crisp render.
- Watermark pill: `Payload SHA-256: [hash]` with click-to-copy.
- Download buttons: `.svg`, `.png`, and verification report.
