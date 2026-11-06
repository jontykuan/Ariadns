"""Module 6: Reporting Engine (result.json, topology.json, report.md)."""

import json
from pathlib import Path
from typing import Any
from ariadns.models.entities import InvestigationResult
from ariadns.storage.graph_store import PropertyGraphStore

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

        # 1. result.json (SRS 5.2 Schema)
        json_path = self.output_dir / f"{base_name}_result.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        # 2. topology.json (Cytoscape / D3)
        topo_path = self.output_dir / f"{base_name}_topology.json"
        topo_data = graph_store.export_topology() if graph_store else {"nodes": [], "edges": []}
        with open(topo_path, "w", encoding="utf-8") as f:
            json.dump(topo_data, f, indent=2, ensure_ascii=False)

        # 3. report.md
        md_path = self.output_dir / f"{base_name}_report.md"
        report_content = self.generate_markdown_report(result)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        return {
            "result_json": json_path,
            "topology_json": topo_path,
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
            f"- **Registrant Name**: {id_prof.registrant_name or 'N/A'}",
            f"- **Registrant Email**: {id_prof.registrant_email or 'N/A'}",
            f"- **SOA Admin Email**: `{id_prof.soa_admin_email or 'N/A'}`",
            "",
            "### Verification Tokens",
        ]
        if id_prof.verification_tokens:
            for k, v in id_prof.verification_tokens.items():
                lines.append(f"- **{k}**: `{v}`")
        else:
            lines.append("- *No verification tokens detected.*")

        lines.extend([
            "",
            "## 2. Infrastructure & Origin Inference",
            f"- **Current Resolved IP**: `{infra.current_ip or 'N/A'}`",
            f"- **CDN Detected**: `{'Yes' if infra.is_cdn else 'No'}` ({infra.cdn_provider or 'Direct / VPS'})",
            f"- **Suspected Origin IP**: `{infra.suspected_origin_ip or 'N/A'}`",
            f"- **Origin Verification Status**: **{infra.origin_verification_status}**",
            f"- **Server Banner**: `{infra.server_banner or 'N/A'}`",
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
                "| Correlated Domain | Relation Type | Confidence | Resolved IP | Admin Email |",
                "| :--- | :--- | :--- | :--- | :--- |"
            ])
            for l2 in result.l2_recursive_results:
                badge = f"**{l2.confidence}**"
                lines.append(f"| `{l2.domain}` | {l2.relation_type} | {badge} | `{l2.resolved_ip or '-'}` | `{l2.registrant_email or '-'}` |")
        else:
            lines.append("- *No secondary associated domains identified.*")

        lines.append("")
        return "\n".join(lines)
