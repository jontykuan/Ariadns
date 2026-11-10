"""Module 6: Reporting Engine & Deterministic Static Evidence Graph Renderer (SVG/PNG)."""

import hashlib
import json
import re
import textwrap
from pathlib import Path
from typing import Any, Optional
try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    Image = ImageDraw = ImageFont = None
from ariadns.models.entities import ArtifactManifest, InvestigationResult, PropositionNode
from ariadns.storage.db import DatabaseManager
from ariadns.storage.evidence_dag import EvidenceChainDAG
from ariadns.storage.graph_store import PropertyGraphStore


def _wrap_statement_lines(statement: str, max_visual_width: int = 50, max_lines: int = 5) -> list[str]:
    """Split statement on 【依據】/【方法】/【結果】 (or [Source]/[Method]/[Result]) onto separate lines and wrap by CJK-aware visual width."""
    segments = [
        s.strip()
        for s in re.split(r"\s*(?=【依據】|【方法】|【結果】|\[Source\]|\[Method\]|\[Result\])", statement.strip())
        if s.strip()
    ]
    if not segments:
        return [statement]

    lines: list[str] = []
    for seg in segments:
        cur_line = ""
        cur_width = 0
        for ch in seg:
            ch_w = 2 if ord(ch) > 127 else 1
            if cur_width + ch_w > max_visual_width and cur_line:
                lines.append(cur_line)
                cur_line = "  " + ch
                cur_width = 2 + ch_w
            else:
                cur_line += ch
                cur_width += ch_w
        if cur_line:
            lines.append(cur_line)
    return lines[:max_lines]

def compute_file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def render_evidence_artifacts(
    session_id: str,
    db: DatabaseManager,
    output_dir: str | Path,
    selected_prop_ids: Optional[list[str]] = None,
    color_coding: bool = True,
    show_legend: bool = True,
    lang: str = "zh"
) -> tuple[Path, Path, Path, ArtifactManifest]:
    """Deterministically render non-draggable static SVG/PNG evidence DAG and forensic manifest."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    clean_session = session_id.strip().lower()
    base_name = clean_session.replace(".", "_")

    all_props = db.get_normalized_propositions(clean_session, rendered_only=False)

    # Update selection if explicitly passed
    if selected_prop_ids is not None:
        sel_set = set(selected_prop_ids)
        with db.get_connection() as conn:
            for p in all_props:
                is_rend = 1 if p.prop_id in sel_set else 0
                conn.execute(
                    "UPDATE evidence_propositions SET is_rendered = ? WHERE session_id = ? AND prop_id = ?",
                    (is_rend, clean_session, p.prop_id)
                )
        rendered_props = [p for p in all_props if p.prop_id in sel_set]
        excluded_props = [p for p in all_props if p.prop_id not in sel_set]
    else:
        rendered_props = [p for p in all_props if p.is_rendered]
        excluded_props = [p for p in all_props if not p.is_rendered]

    rendered_ids = [p.prop_id for p in rendered_props]
    excluded_ids = [p.prop_id for p in excluded_props]

    all_edges = db.get_normalized_edges(clean_session)
    rendered_edges = [(u, v) for u, v in all_edges if u in rendered_ids and v in rendered_ids]
    logs = db.get_audit_logs(clean_session)

    # Compute Canonical Payload SHA-256
    payload_obj = {
        "session_id": clean_session,
        "rendered_propositions": [{"id": p.prop_id, "rank": p.rank, "statement": p.statement} for p in rendered_props],
        "edges": rendered_edges,
        "audit_logs": [{"step": l.step_seq, "module": l.module_name, "target": l.target, "time": l.timestamp} for l in logs]
    }
    canonical_payload = json.dumps(payload_obj, sort_keys=True)
    payload_sha256 = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

    # Layout computation for deterministic coordinates with 4:3 ~ 16:9 aspect ratio balance
    eff_ranks: dict[str, int] = {p.prop_id: p.rank for p in rendered_props}
    for _ in range(len(rendered_props) + 1):
        changed = False
        for u, v in rendered_edges:
            if u in eff_ranks and v in eff_ranks and eff_ranks[v] <= eff_ranks[u]:
                eff_ranks[v] = eff_ranks[u] + 1
                changed = True
        if not changed:
            break

    rank_groups: dict[int, list[PropositionNode]] = {}
    for p in rendered_props:
        rank_groups.setdefault(eff_ranks[p.prop_id], []).append(p)

    ranks = sorted(rank_groups.keys())
    box_w = 340
    box_h = 132
    h_gap = 44
    base_v_gap = 120
    pad_x = 70
    pad_y = 60
    legend_h = 55 if show_legend else 0
    footer_h = 55 + legend_h

    max_per_row = 3 if len(rendered_props) <= 10 else 4
    visual_rows: list[list[PropositionNode]] = []
    for r in ranks:
        r_nodes = rank_groups[r]
        for idx in range(0, len(r_nodes), max_per_row):
            visual_rows.append(r_nodes[idx : idx + max_per_row])

    num_rows = max(1, len(visual_rows))
    max_cols = max((len(row) for row in visual_rows), default=1)
    svg_w = max(1280, pad_x * 2 + max_cols * box_w + max(0, max_cols - 1) * h_gap)

    # Target height to keep svg_w / svg_h within [4/3 (1.33), 16/9 (1.78)]
    min_h_16_9 = int(svg_w * 9 / 16)
    v_gap = base_v_gap
    raw_content_h = num_rows * box_h + max(0, num_rows - 1) * v_gap
    if num_rows > 1 and (raw_content_h + pad_y * 2 + footer_h) < min_h_16_9:
        needed_extra = min_h_16_9 - (raw_content_h + pad_y * 2 + footer_h)
        v_gap = min(200, base_v_gap + needed_extra // (num_rows - 1))
        raw_content_h = num_rows * box_h + max(0, num_rows - 1) * v_gap

    svg_h = max(min_h_16_9, raw_content_h + pad_y * 2 + footer_h)
    if svg_w / svg_h < (4 / 3):
        svg_w = int(svg_h * 4 / 3)

    top_offset = max(pad_y, (svg_h - footer_h - raw_content_h) // 2)

    positions: dict[str, tuple[int, int]] = {}
    prop_lookup: dict[str, PropositionNode] = {p.prop_id: p for p in rendered_props}
    for row_idx, row_nodes in enumerate(visual_rows):
        total_w = len(row_nodes) * box_w + max(0, len(row_nodes) - 1) * h_gap
        start_x = (svg_w - total_w) // 2
        y = top_offset + row_idx * (box_h + v_gap)
        for n_idx, p in enumerate(row_nodes):
            x = start_x + n_idx * (box_w + h_gap)
            positions[p.prop_id] = (x, y)

    def _classify_node_colors(node: PropositionNode) -> tuple[str, str]:
        if not color_coding:
            return ("#38bdf8", "#0284c7") if node.node_kind == "FACT" else ("#94a3b8", "#475569")
        pid = node.prop_id.upper()
        if "ORIGIN" in pid or "UNPROXIED" in pid or "TRACE" in pid or node.rule_name == "RULE_ACTIVE_TRACEROUTE":
            return ("#f59e0b", "#d97706")  # Amber: Origin / Route Breakthrough
        if "PIVOT" in pid or node.entity_type == "DOMAIN_L2":
            return ("#818cf8", "#6366f1")  # Indigo: Correlated L2 Pivot
        if node.node_kind == "CONCLUSION" or node.custodians:
            return ("#10b981", "#059669")  # Emerald: Actionable Custodian Conclusion
        return ("#38bdf8", "#0284c7")      # Cyan: Direct Fact

    def _classify_edge_style(u_id: str, v_id: str) -> tuple[str, str]:
        if not color_coding:
            return ("#64748b", "")
        u_node = prop_lookup.get(u_id)
        v_node = prop_lookup.get(v_id)
        combined = f"{u_id}_{v_id}".upper()
        if "TRACE" in combined or "OOB" in combined or (v_node and v_node.rule_name == "RULE_ACTIVE_TRACEROUTE"):
            return ("#f97316", ' stroke-dasharray="2,4"')  # Dotted orange: Active Trace / OOB
        if "PIVOT" in combined or (u_node and u_node.entity_type == "DOMAIN_L2") or (v_node and v_node.entity_type == "DOMAIN_L2"):
            return ("#a855f7", ' stroke-dasharray="6,4"')  # Dashed purple: Pivot correlation
        return ("#94a3b8", "")                             # Solid slate: Direct deduction

    def _derive_edge_label(u_id: str, v_id: str, lang: str = "zh") -> str:
        is_zh = (lang == "zh")
        v_node = prop_lookup.get(v_id)
        v_pid = v_id.upper()

        if v_node and (v_node.node_kind == "CONCLUSION" or v_node.custodians):
            return ""
        if "TRACE" in v_pid or (v_node and v_node.rule_name == "RULE_ACTIVE_TRACEROUTE"):
            return "路由躍遷追蹤" if is_zh else "Route Hop Trace"
        if "OOB" in v_pid or (v_node and v_node.rule_name == "RULE_ACTIVE_OOB_PROBE"):
            return "主動回連探測" if is_zh else "Active OOB Probe"
        if "SUB" in v_pid:
            return "網域 ➔ 子網域枚舉" if is_zh else "Domain ➔ Subdomain Enum"
        if "ORIGIN" in v_pid:
            return "受保護網域 ➔ 來源碰撞探測" if is_zh else "Domain ➔ Origin Probe"
        if "PIVOT" in v_pid:
            return "橫向共構轉向" if is_zh else "Pivot Correlation"
        if "F1" in v_pid and ("F1" in u_id or u_id == "F1"):
            return "A紀錄 ➔ ASN歸屬探測" if is_zh else "A Rec ➔ ASN Probe"
        return ""

    def _derive_node_method_badge(node: PropositionNode, lang: str = "zh") -> str:
        is_zh = (lang == "zh")
        pid = node.prop_id.upper()
        if node.node_kind == "CONCLUSION":
            return "鑑識調閱" if is_zh else "Custody"
        if "TRACE" in pid or node.rule_name == "RULE_ACTIVE_TRACEROUTE":
            return "M9:路由追蹤" if is_zh else "M9:Trace"
        if "OOB" in pid or node.rule_name == "RULE_ACTIVE_OOB_PROBE":
            return "M7:回連探測" if is_zh else "M7:OOB"
        if "ORIGIN" in pid or "UNPROXIED" in pid:
            return "M3:來源探測" if is_zh else "M3:Origin"
        if "SUB" in pid:
            return "M2:子網域" if is_zh else "M2:Subdomain"
        if "PIVOT" in pid:
            return "M4:關聯轉向" if is_zh else "M4:Pivot"
        if "F1" in pid:
            if node.entity_type == "IP":
                return "M1:ASN/BGP" if is_zh else "M1:ASN/BGP"
            return "M1:DNS探測" if is_zh else "M1:DNS"
        if "F2" in pid:
            return "M1:RDAP/TXT" if is_zh else "M1:RDAP"
        return "M1:探測" if is_zh else "M1:Probe"

    # 1. Generate Static SVG
    svg_lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_w} {svg_h}" width="{svg_w}" height="{svg_h}" style="background-color: #0f172a; font-family: sans-serif;">',
        '  <defs>',
        '    <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '      <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8"/>',
        '    </marker>',
        '  </defs>',
    ]

    # Draw edges with midpoint method pills
    for u, v in rendered_edges:
        if u in positions and v in positions:
            ux, uy = positions[u]
            vx, vy = positions[v]
            x1 = ux + box_w // 2
            y1 = uy + box_h
            x2 = vx + box_w // 2
            y2 = vy
            e_color, e_dash = _classify_edge_style(u, v)
            edge_lbl = _derive_edge_label(u, v, lang=lang)
            svg_lines.append(f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{e_color}" stroke-width="2"{e_dash} marker-end="url(#arrow)"/>')

            # Midpoint pill badge (only when edge_lbl is non-empty)
            if edge_lbl:
                mx = (x1 + x2) // 2
                my = (y1 + y2) // 2
                pill_w = max(76, len(edge_lbl) * 12 + 18)
                pill_h = 20
                px = mx - pill_w // 2
                py = my - pill_h // 2
                svg_lines.extend([
                    f'  <rect x="{px}" y="{py}" width="{pill_w}" height="{pill_h}" rx="4" fill="#0b1329" stroke="{e_color}" stroke-width="1.2"/>',
                    f'  <text x="{mx}" y="{my + 4}" fill="#cbd5e1" font-size="10" font-weight="bold" text-anchor="middle">{edge_lbl}</text>'
                ])

    # Draw nodes with multi-line wrapped statements (依據 / 方法 / 結果 on separate lines)
    for p in rendered_props:
        x, y = positions[p.prop_id]
        is_fact = (p.node_kind == "FACT")
        stroke_color, header_color = _classify_node_colors(p)
        badge = "FACT" if is_fact else "CONCLUSION"
        method_badge = _derive_node_method_badge(p, lang=lang)

        wrapped_lines = _wrap_statement_lines(p.statement, max_visual_width=50, max_lines=5)

        svg_lines.extend([
            f'  <rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="6" fill="#1e293b" stroke="{stroke_color}" stroke-width="2"/>',
            f'  <rect x="{x}" y="{y}" width="{box_w}" height="24" rx="6" fill="{header_color}"/>',
            f'  <text x="{x + 8}" y="{y + 16}" fill="#ffffff" font-size="11" font-weight="bold">[{badge}] {p.prop_id} | {method_badge}</text>',
        ])
        for line_idx, w_line in enumerate(wrapped_lines):
            safe_line = w_line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            ty = y + 42 + line_idx * 16
            svg_lines.append(f'  <text x="{x + 8}" y="{ty}" fill="#e2e8f0" font-size="11">{safe_line}</text>')

    # Optional Embedded Legend
    if show_legend:
        leg_y = svg_h - 45 - legend_h
        is_zh = (lang == "zh")
        leg_title = "圖例說明 (Legend):" if is_zh else "Visual Legend:"
        lbl_fact = "直接觀測事實 (Direct Fact)" if is_zh else "Direct Fact"
        lbl_orig = "來源突破/路由追蹤 (Origin/Trace)" if is_zh else "Origin / Route Trace"
        lbl_piv = "關聯轉向標的 (Pivot L2)" if is_zh else "Correlated Pivot"
        lbl_conc = "可調閱結論 (Custodian Conclusion)" if is_zh else "Actionable Conclusion"
        lbl_solid = "實線: 直接解析歸屬" if is_zh else "Solid: Direct Deduction"
        lbl_dash = "虛線: 橫向共構關聯" if is_zh else "Dashed: Pivot Correlation"
        lbl_dot = "點線: 主動路由/回連驗證" if is_zh else "Dotted: Active Trace/OOB"

        svg_lines.extend([
            f'  <rect x="20" y="{leg_y}" width="{svg_w - 40}" height="{legend_h - 8}" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>',
            f'  <text x="35" y="{leg_y + 18}" fill="#f8fafc" font-size="11" font-weight="bold">{leg_title}</text>',
            f'  <rect x="160" y="{leg_y + 8}" width="12" height="12" fill="#0284c7" stroke="#38bdf8" stroke-width="1.5"/>',
            f'  <text x="178" y="{leg_y + 18}" fill="#cbd5e1" font-size="11">{lbl_fact}</text>',
            f'  <rect x="350" y="{leg_y + 8}" width="12" height="12" fill="#d97706" stroke="#f59e0b" stroke-width="1.5"/>',
            f'  <text x="368" y="{leg_y + 18}" fill="#cbd5e1" font-size="11">{lbl_orig}</text>',
            f'  <rect x="570" y="{leg_y + 8}" width="12" height="12" fill="#6366f1" stroke="#818cf8" stroke-width="1.5"/>',
            f'  <text x="588" y="{leg_y + 18}" fill="#cbd5e1" font-size="11">{lbl_piv}</text>',
            f'  <rect x="755" y="{leg_y + 8}" width="12" height="12" fill="#059669" stroke="#10b981" stroke-width="1.5"/>',
            f'  <text x="773" y="{leg_y + 18}" fill="#cbd5e1" font-size="11">{lbl_conc}</text>',
            f'  <line x1="160" y1="{leg_y + 34}" x2="195" y2="{leg_y + 34}" stroke="#94a3b8" stroke-width="2"/>',
            f'  <text x="202" y="{leg_y + 38}" fill="#cbd5e1" font-size="11">{lbl_solid}</text>',
            f'  <line x1="350" y1="{leg_y + 34}" x2="385" y2="{leg_y + 34}" stroke="#a855f7" stroke-width="2" stroke-dasharray="6,4"/>',
            f'  <text x="392" y="{leg_y + 38}" fill="#cbd5e1" font-size="11">{lbl_dash}</text>',
            f'  <line x1="570" y1="{leg_y + 34}" x2="605" y2="{leg_y + 34}" stroke="#f97316" stroke-width="2" stroke-dasharray="2,4"/>',
            f'  <text x="612" y="{leg_y + 38}" fill="#cbd5e1" font-size="11">{lbl_dot}</text>',
        ])

    # Watermark stamp
    svg_lines.extend([
        f'  <rect x="0" y="{svg_h - 45}" width="{svg_w}" height="45" fill="#020617"/>',
        f'  <text x="30" y="{svg_h - 24}" fill="#94a3b8" font-family="monospace" font-size="12">Ariadns Forensic Watermark | Session: {clean_session} | Payload SHA-256: {payload_sha256}</text>',
        '</svg>'
    ])

    svg_path = out_path / f"{base_name}_evidence.svg"
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write("\n".join(svg_lines))

    # 2. Generate Static PNG using Pillow if available, otherwise write minimal PNG fallback
    png_path = out_path / f"{base_name}_evidence.png"
    if HAS_PIL and Image is not None and ImageDraw is not None:
        img = Image.new("RGB", (svg_w, svg_h), color="#0f172a")
        draw = ImageDraw.Draw(img)

        for u, v in rendered_edges:
            if u in positions and v in positions:
                ux, uy = positions[u]
                vx, vy = positions[v]
                x1, y1 = ux + box_w // 2, uy + box_h
                x2, y2 = vx + box_w // 2, vy
                e_color, _ = _classify_edge_style(u, v)
                draw.line([(x1, y1), (x2, y2)], fill=e_color, width=2)
                edge_lbl = _derive_edge_label(u, v, lang=lang)
                if edge_lbl:
                    mx = (x1 + x2) // 2
                    my = (y1 + y2) // 2
                    pill_w = max(76, len(edge_lbl) * 11 + 16)
                    pill_h = 18
                    draw.rounded_rectangle([mx - pill_w // 2, my - pill_h // 2, mx + pill_w // 2, my + pill_h // 2], radius=4, fill="#0b1329", outline=e_color, width=1)
                    draw.text((mx - pill_w // 2 + 6, my - 6), edge_lbl, fill="#cbd5e1")

        for p in rendered_props:
            x, y = positions[p.prop_id]
            is_fact = (p.node_kind == "FACT")
            stroke_c, header_c = _classify_node_colors(p)
            badge = "FACT" if is_fact else "CONCLUSION"
            method_badge = _derive_node_method_badge(p, lang=lang)

            draw.rounded_rectangle([x, y, x + box_w, y + box_h], radius=6, fill="#1e293b", outline=stroke_c, width=2)
            draw.rectangle([x, y, x + box_w, y + 24], fill=header_c)
            draw.text((x + 8, y + 5), f"[{badge}] {p.prop_id} | {method_badge}", fill="#ffffff")
            wrapped_lines = _wrap_statement_lines(p.statement, max_visual_width=50, max_lines=5)
            for l_idx, w_line in enumerate(wrapped_lines):
                draw.text((x + 8, y + 32 + l_idx * 16), w_line, fill="#e2e8f0")

        draw.rectangle([0, svg_h - 45, svg_w, svg_h], fill="#020617")
        draw.text((30, svg_h - 30), f"Ariadns Forensic Watermark | Session: {clean_session} | Payload SHA-256: {payload_sha256}", fill="#94a3b8")

        img.save(png_path, format="PNG")
    else:
        minimal_png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x00\x00\x00\x00:~\x9bU\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02"
            b"\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        png_path.write_bytes(minimal_png)

    # 3. Generate Report Markdown with SVG/PNG hashes
    svg_hash = compute_file_sha256(svg_path)
    png_hash = compute_file_sha256(png_path)

    md_lines = [
        f"# Ariadns Forensic Investigation Report: {clean_session}",
        "",
        f"- **Session ID**: `{clean_session}`",
        f"- **Evidence DAG Payload Hash**: `{payload_sha256}`",
        "",
        "## 1. Evidence Architecture & Graph",
        f"![Evidence DAG SVG](./{svg_path.name})",
        "",
        "## 2. Session Audit Log (工作階段分步稽核紀錄)",
        "| Step | Timestamp (UTC) | Module | Target | Added Facts | State Hash |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for l in logs:
        md_lines.append(f"| {l.step_seq} | `{l.timestamp}` | `{l.module_name}` | `{l.target}` | `{','.join(l.added_fact_ids)}` | `{l.artifact_sha256[:16]}...` |")

    md_lines.extend([
        "",
        "## 3. Data Custodians Matrix",
        "| Conclusion ID | Target Entity | Custodian | Role | Queryable Records |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ])
    for p in rendered_props:
        if p.node_kind == "CONCLUSION" and p.custodians:
            for c in p.custodians:
                rec_fmt = ", ".join(c.queryable_records)
                md_lines.append(f"| **{p.prop_id}** | `{p.target_entity}` | **{c.custodian_name}** | {c.custodian_role} | {rec_fmt} |")

    md_lines.extend([
        "",
        "## 4. Forensic Manifest & Artifact Hashes",
        "| Artifact File | SHA-256 Digest |",
        "| :--- | :--- |",
        f"| `{svg_path.name}` | `{svg_hash}` |",
        f"| `{png_path.name}` | `{png_hash}` |",
    ])

    md_path = out_path / f"{base_name}_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    # 4. Compute file hashes and export Manifest
    file_hashes = {
        svg_path.name: svg_hash,
        png_path.name: png_hash,
        md_path.name: compute_file_sha256(md_path),
    }

    manifest = ArtifactManifest(
        session_id=clean_session,
        payload_sha256=payload_sha256,
        rendered_prop_ids=rendered_ids,
        excluded_prop_ids=excluded_ids,
        file_hashes=file_hashes,
        verified=True
    )

    manifest_path = out_path / f"{base_name}_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest.__dict__, f, indent=2)

    return svg_path, png_path, md_path, manifest

class ReportingEngine:
    def __init__(self, output_dir: str | Path = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_all(
        self,
        result: InvestigationResult,
        graph_store: PropertyGraphStore | None = None
    ) -> dict[str, Path]:
        domain = result.target_domain
        base_name = domain.replace(".", "_")

        json_path = self.output_dir / f"{base_name}_result.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        topo_path = self.output_dir / f"{base_name}_topology.json"
        topo_data = graph_store.export_topology() if graph_store else {"nodes": [], "edges": []}
        with open(topo_path, "w", encoding="utf-8") as f:
            json.dump(topo_data, f, indent=2, ensure_ascii=False)

        evidence_path = self.output_dir / f"{base_name}_evidence_chain.json"
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict().get("evidence_chain", []), f, indent=2, ensure_ascii=False)

        md_path = self.output_dir / f"{base_name}_report.md"
        report_content = self.generate_markdown_report(result)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        return {
            "result_json": json_path,
            "topology_json": topo_path,
            "evidence_chain_json": evidence_path,
            "report_md": md_path,
        }

    def generate_markdown_report(self, result: InvestigationResult) -> str:
        infra = result.infrastructure
        id_prof = result.identity_profile
        lines = [
            f"# Ariadns OSINT Investigation Report: {result.target_domain}",
            "",
            f"- **Timestamp**: `{result.investigation_timestamp}`",
            f"- **Target Domain**: `{result.target_domain}`",
            "",
            "## 1. Identity Profile",
            f"- **Registrar**: {id_prof.registrar_name or 'N/A'}",
            f"- **Registrant Name**: {id_prof.registrant_name or 'N/A'}",
            f"- **Registrant Email**: {id_prof.registrant_email or 'N/A'}",
            f"- **SOA Admin Email**: `{id_prof.soa_admin_email or 'N/A'}`",
            "",
            "### Verification & Tracking Tokens",
        ]
        tokens_all = dict(id_prof.verification_tokens)
        tokens_all.update(id_prof.html_tracking_tokens)
        if tokens_all:
            for k, v in tokens_all.items():
                lines.append(f"- **{k}**: `{v}`")
        else:
            lines.append("- *No verification or tracking tokens detected.*")

        lines.extend([
            "",
            "## 2. Infrastructure & Origin Inference",
            f"- **Current Resolved IP**: `{infra.current_ip or 'N/A'}`",
            f"- **CDN Detected**: `{'Yes' if infra.is_cdn else 'No'}` ({infra.cdn_provider or 'Direct / VPS'})",
            f"- **ASN**: `{infra.asn or 'N/A'}` ({infra.asn_org_name or 'N/A'}, {infra.country or '-'})",
            f"- **Suspected Origin IP**: `{infra.suspected_origin_ip or 'N/A'}`",
            f"- **Origin Verification Status**: **{infra.origin_verification_status}**",
            f"- **Server Banner**: `{infra.server_banner or 'N/A'}`",
            f"- **Favicon SHA-256**: `{infra.favicon_sha256 or 'N/A'}`",
            f"- **Open Ports**: `{infra.open_ports if infra.open_ports else 'None / Filtered'}`",
            "",
            "## 3. Discovered Subdomains",
            f"Total discovered and probed: {len(result.subdomains)}",
        ])
        if result.subdomains:
            lines.extend([
                "",
                "| Subdomain | IP | Status | Web Server | Title |",
                "| :--- | :--- | :--- | :--- | :--- |"
            ])
            for s in result.subdomains[:20]:
                lines.append(f"| `{s.subdomain}` | `{s.ip or '-'}` | `{s.status_code or '-'}` | `{s.server or '-'}` | {s.title or '-'} |")

        lines.extend([
            "",
            "## 4. Associated Assets (Domain-L2)",
            f"Total correlated assets: {len(result.l2_recursive_results)}",
        ])
        if result.l2_recursive_results:
            lines.extend([
                "",
                "| Correlated Domain | Relation Type | Confidence | Resolved IP | Registrar | Admin Email |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |"
            ])
            for l2 in result.l2_recursive_results:
                badge = f"**{l2.confidence}**"
                lines.append(f"| `{l2.domain}` | {l2.relation_type} | {badge} | `{l2.resolved_ip or '-'}` | `{l2.registrar_name or '-'}` | `{l2.registrant_email or '-'}` |")
        else:
            lines.append("- *No secondary associated domains identified.*")

        # 5. Causal Evidence DAG & Data Custodians
        lines.extend([
            "",
            "## 5. Causal Evidence Chain (因果證據鏈有向無環圖)",
            "> 結構依據「因為前提觀測事實 A 與 B，推導出結論節點 C」，方向嚴格保證有向無環（DAG）。",
            "",
            "```mermaid",
        ])

        dag = EvidenceChainDAG(session_id=result.target_domain)
        for p in result.evidence_chain:
            dag.add_proposition(
                prop_id=p.prop_id,
                node_kind=p.node_kind,
                statement=p.statement,
                premises=p.premises,
                rule_name=p.rule_name,
                target_entity=p.target_entity,
                entity_type=p.entity_type,
                custodians=p.custodians,
            )
        mermaid_content = dag.generate_mermaid_flowchart()
        lines.append(mermaid_content)
        lines.extend([
            "```",
            "",
            "### 結論節點對應資料管理源清單 (Data Custodians Matrix)",
            "",
            "| 結論 ID | 推論標的實體 (Target) | 實體類型 | 規則名稱 | 對應資料管理源 (Data Custodian) | 角色分類 | 該管理源持有之可查紀錄清單 |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        conclusion_count = 0
        for p in result.evidence_chain:
            if p.node_kind == "CONCLUSION" and p.custodians:
                conclusion_count += 1
                for c in p.custodians:
                    records_fmt = "<br/>• ".join(c.queryable_records)
                    lines.append(f"| **{p.prop_id}** | `{p.target_entity}` | `{p.entity_type}` | `{p.rule_name}` | **{c.custodian_name}** | {c.custodian_role} | • {records_fmt} |")

        if conclusion_count == 0:
            lines.append("| - | - | - | - | - | - | *無推論結論或無可對應管理源* |")

        lines.append("")
        return "\n".join(lines)
