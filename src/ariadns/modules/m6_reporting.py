"""Module 6: Reporting Engine (result.json, topology.json, evidence_chain.json, report.md)."""

import json
from pathlib import Path
from typing import Any
from ariadns.models.entities import InvestigationResult
from ariadns.storage.evidence_dag import EvidenceChainDAG
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

        # 1. result.json (SRS 5.2 Schema + evidence_chain)
        json_path = self.output_dir / f"{base_name}_result.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        # 2. topology.json (Cytoscape / D3)
        topo_path = self.output_dir / f"{base_name}_topology.json"
        topo_data = graph_store.export_topology() if graph_store else {"nodes": [], "edges": []}
        with open(topo_path, "w", encoding="utf-8") as f:
            json.dump(topo_data, f, indent=2, ensure_ascii=False)

        # 3. evidence_chain.json
        evidence_path = self.output_dir / f"{base_name}_evidence_chain.json"
        evidence_data = [p.__dict__ if hasattr(p, "__dict__") else p for p in result.evidence_chain]
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict().get("evidence_chain", []), f, indent=2, ensure_ascii=False)

        # 4. report.md
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

        # Reconstruct DAG to generate mermaid
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
