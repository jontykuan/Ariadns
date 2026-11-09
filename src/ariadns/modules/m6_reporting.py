"""Module 6: Reporting Engine & Deterministic Static Evidence Graph Renderer (SVG/PNG)."""

import hashlib
import json
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
    selected_prop_ids: Optional[list[str]] = None
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

    # Layout computation for deterministic coordinates
    rank_groups: dict[int, list[PropositionNode]] = {}
    for p in rendered_props:
        rank_groups.setdefault(p.rank, []).append(p)

    ranks = sorted(rank_groups.keys())
    box_w = 260
    box_h = 70
    h_gap = 40
    v_gap = 120
    pad_x = 60
    pad_y = 60

    max_nodes_in_rank = max((len(nodes) for nodes in rank_groups.values()), default=1)
    svg_w = max(1000, pad_x * 2 + max_nodes_in_rank * (box_w + h_gap))
    svg_h = pad_y * 2 + max(1, len(ranks)) * (box_h + v_gap) + 80

    positions: dict[str, tuple[int, int]] = {}
    for r_idx, r in enumerate(ranks):
        nodes = rank_groups[r]
        total_w = len(nodes) * box_w + (len(nodes) - 1) * h_gap
        start_x = (svg_w - total_w) // 2
        y = pad_y + r_idx * (box_h + v_gap)
        for n_idx, p in enumerate(nodes):
            x = start_x + n_idx * (box_w + h_gap)
            positions[p.prop_id] = (x, y)

    # 1. Generate Static SVG
    svg_lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_w} {svg_h}" width="{svg_w}" height="{svg_h}" style="background-color: #0f172a; font-family: sans-serif;">',
        '  <defs>',
        '    <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '      <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"/>',
        '    </marker>',
        '  </defs>',
    ]

    # Draw edges
    for u, v in rendered_edges:
        if u in positions and v in positions:
            ux, uy = positions[u]
            vx, vy = positions[v]
            x1 = ux + box_w // 2
            y1 = uy + box_h
            x2 = vx + box_w // 2
            y2 = vy
            svg_lines.append(f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#64748b" stroke-width="2" marker-end="url(#arrow)"/>')

    # Draw nodes
    for p in rendered_props:
        x, y = positions[p.prop_id]
        is_fact = (p.node_kind == "FACT")
        stroke_color = "#38bdf8" if is_fact else "#818cf8"
        header_color = "#0284c7" if is_fact else "#6366f1"
        badge = "FACT" if is_fact else "CONCLUSION"

        stmt_preview = (p.statement[:32] + "...") if len(p.statement) > 35 else p.statement
        safe_stmt = stmt_preview.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        svg_lines.extend([
            f'  <rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="6" fill="#1e293b" stroke="{stroke_color}" stroke-width="2"/>',
            f'  <rect x="{x}" y="{y}" width="{box_w}" height="24" rx="6" fill="{header_color}"/>',
            f'  <text x="{x + 8}" y="{y + 16}" fill="#ffffff" font-size="11" font-weight="bold">[{badge}] {p.prop_id}</text>',
            f'  <text x="{x + 8}" y="{y + 48}" fill="#e2e8f0" font-size="11">{safe_stmt}</text>',
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
                draw.line([(x1, y1), (x2, y2)], fill="#64748b", width=2)

        for p in rendered_props:
            x, y = positions[p.prop_id]
            is_fact = (p.node_kind == "FACT")
            stroke_c = "#38bdf8" if is_fact else "#818cf8"
            header_c = "#0284c7" if is_fact else "#6366f1"
            badge = "FACT" if is_fact else "CONCLUSION"

            draw.rounded_rectangle([x, y, x + box_w, y + box_h], radius=6, fill="#1e293b", outline=stroke_c, width=2)
            draw.rectangle([x, y, x + box_w, y + 24], fill=header_c)
            draw.text((x + 8, y + 5), f"[{badge}] {p.prop_id}", fill="#ffffff")
            stmt_preview = (p.statement[:32] + "...") if len(p.statement) > 35 else p.statement
            draw.text((x + 8, y + 36), stmt_preview, fill="#e2e8f0")

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
