"""FastMCP Server Interface for Ariadns (Token-Economic OSINT Tools & Resources)."""

import json
from pathlib import Path
from typing import Any, Optional
try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:
    from mcp.server.mcpserver import MCPServer as FastMCP
from ariadns.models.config import AppConfig
from ariadns.models.enums import ConfidenceLevel, NodeType
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.modules.m6_reporting import ReportingEngine, render_evidence_artifacts
from ariadns.modules.m7_manual_oob import trigger_manual_oob
from ariadns.modules.m8_recommender import NextStepRecommender
from ariadns.storage.forensic_verifier import verify_case_artifacts
from ariadns.storage.graph_store import PropertyGraphStore
from ariadns.utils.warninglist_sync import WarninglistSynchronizer

mcp = FastMCP("ariadns-mcp")

_orchestrator: Orchestrator | None = None

def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator

@mcp.tool()
def osint_scan(
    domain: str,
    depth: int = 1,
    run_portscan: bool = False
) -> dict[str, Any]:
    """Execute domain OSINT recon pipeline (M1-M5) returning a compact, token-economic summary (<600 tokens)."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    res = orchestrator.run_investigation(clean_domain, depth=depth, run_portscan=run_portscan)

    return {
        "domain": clean_domain,
        "resolved_ip": res.infrastructure.current_ip,
        "is_cdn": res.infrastructure.is_cdn,
        "cdn_provider": res.infrastructure.cdn_provider,
        "suspected_origin_ip": res.infrastructure.suspected_origin_ip,
        "origin_status": res.infrastructure.origin_verification_status,
        "registrar": res.identity_profile.registrar_name,
        "subdomains_count": len(res.subdomains),
        "l2_pivots_count": len(res.l2_recursive_results),
        "high_confidence_pivots": [
            {"domain": l2.domain, "relation": l2.relation_type}
            for l2 in res.l2_recursive_results
            if l2.confidence == ConfidenceLevel.HIGH.value
        ],
    }

@mcp.tool()
def osint_inspect(
    domain: str,
    query_type: str = "summary",
    target_node: str = "",
    sql_query: str = "",
    limit: int = 20
) -> dict[str, Any]:
    """Inspect investigation graph details, normalized evidence chain, custodians, or execute guarded read-only SELECT SQL."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    store = PropertyGraphStore(orchestrator.db, session_id=clean_domain)

    if query_type == "sql":
        if not sql_query:
            return {"error": "Missing sql_query parameter."}
        try:
            rows = orchestrator.db.execute_readonly_sql(sql_query)
            return {"rows": rows[:limit]}
        except Exception as e:
            return {"error": str(e)}

    elif query_type == "evidence_chain":
        rendered_props = orchestrator.db.get_normalized_propositions(clean_domain, rendered_only=True)
        if not rendered_props:
            res = orchestrator.run_investigation(clean_domain, depth=1)
            rendered_props = res.evidence_chain
        propositions = [
            {
                "prop_id": p.prop_id,
                "node_kind": p.node_kind,
                "rank": p.rank,
                "statement": p.statement,
                "premises": p.premises,
                "rule_name": p.rule_name,
                "target_entity": p.target_entity,
                "entity_type": p.entity_type,
            }
            for p in rendered_props[:limit]
        ]
        return {"session_id": clean_domain, "evidence_chain": propositions}

    elif query_type == "custodians":
        custodians = orchestrator.db.get_normalized_custodians(clean_domain)
        if not custodians:
            res = orchestrator.run_investigation(clean_domain, depth=1)
            for p in res.evidence_chain:
                if p.node_kind == "CONCLUSION" and p.custodians:
                    for c in p.custodians:
                        custodians.append({
                            "conclusion_id": p.prop_id,
                            "target_entity": p.target_entity,
                            "entity_type": p.entity_type,
                            "custodian_name": c.custodian_name,
                            "custodian_role": c.custodian_role,
                            "queryable_records": c.queryable_records,
                        })
        return {"session_id": clean_domain, "custodians": custodians[:limit]}

    elif query_type == "neighbors":
        if not target_node:
            target_node = f"{NodeType.DOMAIN_L1.value}:{clean_domain}"
        if not store.graph.has_node(target_node):
            return {"error": f"Node {target_node} not found in session graph."}
        neighbors = list(store.graph.neighbors(target_node))
        return {
            "node": target_node,
            "neighbors": [
                {"id": n, "type": store.graph.nodes[n].get("node_type"), "label": store.graph.nodes[n].get("label")}
                for n in neighbors[:limit]
            ]
        }

    elif query_type == "l2_candidates":
        l2_nodes = [
            {"id": n, "label": store.graph.nodes[n].get("label")}
            for n in store.graph.nodes
            if store.graph.nodes[n].get("node_type") == NodeType.DOMAIN_L2.value
        ]
        return {"session_id": clean_domain, "l2_candidates": l2_nodes[:limit]}

    elif query_type == "summary":
        return {
            "session_id": clean_domain,
            "total_nodes": store.graph.number_of_nodes(),
            "total_edges": store.graph.number_of_edges(),
            "origin_node": f"{NodeType.DOMAIN_L1.value}:{clean_domain}",
        }

    return {"error": f"Unknown query_type: '{query_type}'"}

@mcp.tool()
def osint_run_step(
    domain: str,
    module_name: str,
    target: str = "",
    params_json: str = "{}"
) -> dict[str, Any]:
    """Execute a single investigation module stepwise against a case session, merging facts and logging audit trail."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    step_target = (target or clean_domain).strip().lower()
    params = json.loads(params_json) if params_json else {}

    entry = orchestrator.run_step(clean_domain, module_name, step_target, params=params)
    return {
        "status": "STEP_COMPLETED",
        "session_id": clean_domain,
        "step_seq": entry.step_seq,
        "module_name": entry.module_name,
        "target": entry.target,
        "added_fact_ids": entry.added_fact_ids,
        "artifact_sha256": entry.artifact_sha256,
    }

@mcp.tool()
def osint_recommend_next(domain: str) -> dict[str, Any]:
    """Derive prioritized next-step investigative action recommendations based on known session propositions and history."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    recommender = NextStepRecommender(orchestrator.db, orchestrator.config)
    recs = recommender.recommend(clean_domain)

    return {
        "session_id": clean_domain,
        "recommendations": [
            {
                "rec_id": r.rec_id,
                "trigger_fact_ids": r.trigger_fact_ids,
                "recommended_module": r.recommended_module,
                "recommended_target": r.recommended_target,
                "rationale": r.rationale,
                "expected_evidence": r.expected_evidence,
                "cli_command": r.cli_command,
            }
            for r in recs
        ]
    }

@mcp.tool()
def osint_render_graph(
    domain: str,
    output_dir: str = "./reports",
    selected_prop_ids: Optional[list[str]] = None
) -> dict[str, Any]:
    """Render non-draggable static SVG/PNG evidence DAG and forensic manifest on disk."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    svg_path, png_path, md_path, manifest = render_evidence_artifacts(
        session_id=clean_domain,
        db=orchestrator.db,
        output_dir=output_dir,
        selected_prop_ids=selected_prop_ids
    )

    return {
        "status": "OK",
        "session_id": clean_domain,
        "svg_path": str(svg_path.resolve()),
        "png_path": str(png_path.resolve()),
        "report_md": str(md_path.resolve()),
        "payload_sha256": manifest.payload_sha256,
        "rendered_nodes_count": len(manifest.rendered_prop_ids),
        "excluded_nodes_count": len(manifest.excluded_prop_ids),
    }

@mcp.tool()
def osint_read_evidence_graph(
    session_id: str,
    rendered_only: bool = True
) -> dict[str, Any]:
    """Read the structured evidence graph and audit trail from SQLite without re-running scans (<500 tokens)."""
    orchestrator = get_orchestrator()
    clean_session = session_id.strip().lower()
    props = orchestrator.db.get_normalized_propositions(clean_session, rendered_only=rendered_only)
    edges = orchestrator.db.get_normalized_edges(clean_session)
    prop_ids = {p.prop_id for p in props}
    filtered_edges = [[u, v] for u, v in edges if u in prop_ids and v in prop_ids]
    logs = orchestrator.db.get_audit_logs(clean_session)

    return {
        "session_id": clean_session,
        "propositions": [
            {
                "prop_id": p.prop_id,
                "node_kind": p.node_kind,
                "rank": p.rank,
                "statement": p.statement,
                "premises": p.premises,
                "is_rendered": p.is_rendered,
            }
            for p in props
        ],
        "edges": filtered_edges,
        "audit_logs": [
            {
                "step": l.step_seq,
                "module": l.module_name,
                "target": l.target,
                "added_facts": l.added_fact_ids,
            }
            for l in logs
        ]
    }

@mcp.tool()
def osint_verify_case(case_dir: str) -> dict[str, Any]:
    """Verify dual-layer cryptographic integrity (File SHA-256 + Canonical Payload Hash) of a case artifacts directory."""
    orchestrator = get_orchestrator()
    return verify_case_artifacts(case_dir, db=orchestrator.db)

@mcp.tool()
def osint_sync_lists(force: bool = False) -> dict[str, Any]:
    """Synchronize open-source false-positive warninglists (MISP and Freemail feeds) into local SQLite."""
    orchestrator = get_orchestrator()
    syncer = WarninglistSynchronizer(orchestrator.db, orchestrator.http_client, orchestrator.config)
    status = syncer.ensure_warninglists_synced(force=force)
    last_synced = orchestrator.db.get_warninglist_last_synced()
    return {
        "status": status.value,
        "last_synced_at": last_synced,
    }

@mcp.tool()
def osint_expand(
    parent_domain: str,
    l2_domain: str,
    run_portscan: bool = False
) -> dict[str, Any]:
    """Expand and deeply investigate an associated L2 domain candidate discovered during pivoting."""
    orchestrator = get_orchestrator()
    clean_parent = parent_domain.strip().lower()
    clean_l2 = l2_domain.strip().lower()

    store = PropertyGraphStore(orchestrator.db, session_id=clean_parent)
    l2_node_id = f"{NodeType.DOMAIN_L2.value}:{clean_l2}"
    if not store.graph.has_node(l2_node_id):
        return {"error": f"L2 domain '{clean_l2}' is not an associated candidate in session '{clean_parent}'."}

    l2_result = orchestrator.run_investigation(clean_l2, depth=1, run_portscan=run_portscan)

    return {
        "status": "EXPANDED",
        "parent_domain": clean_parent,
        "expanded_domain": clean_l2,
        "resolved_ip": l2_result.infrastructure.current_ip,
        "is_cdn": l2_result.infrastructure.is_cdn,
        "subdomains_found": len(l2_result.subdomains),
    }

@mcp.tool()
def osint_manual_oob(
    target_endpoint_url: str,
    callback_url: str,
    param_name: str = "url",
    http_method: str = "GET",
    acknowledge_opsec_risk: bool = False
) -> dict[str, Any]:
    """Execute isolated manual OOB callback probe. Mandatory: Requires acknowledge_opsec_risk=True."""
    return trigger_manual_oob(
        target_endpoint_url=target_endpoint_url,
        callback_url=callback_url,
        param_name=param_name,
        http_method=http_method,
        acknowledge_opsec_risk=acknowledge_opsec_risk,
    )

@mcp.tool()
def osint_report(
    domain: str,
    output_dir: str = "./reports"
) -> dict[str, Any]:
    """Generate result.json, topology.json, evidence_chain.json and report.md on disk and return paths."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    result = orchestrator.run_investigation(clean_domain, depth=1)
    graph_store = PropertyGraphStore(orchestrator.db, session_id=clean_domain)
    reporter = ReportingEngine(output_dir=output_dir)
    paths = reporter.export_all(result, graph_store=graph_store)

    return {
        "domain": clean_domain,
        "result_json": str(paths["result_json"].resolve()),
        "evidence_chain_json": str(paths["evidence_chain_json"].resolve()),
        "topology_json": str(paths["topology_json"].resolve()),
        "report_md": str(paths["report_md"].resolve()),
    }

@mcp.resource("ariadns://sessions")
def list_sessions() -> str:
    """List all active investigation sessions stored in the SQLite database."""
    orchestrator = get_orchestrator()
    rows = orchestrator.db.execute_readonly_sql(
        "SELECT session_id, target_domain, depth, status, created_at FROM investigation_sessions ORDER BY created_at DESC"
    )
    return json.dumps(rows, indent=2)

@mcp.resource("ariadns://graph/{domain}/summary")
def get_graph_summary(domain: str) -> str:
    """Retrieve node and edge counts and degree distribution for a domain session graph."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    store = PropertyGraphStore(orchestrator.db, session_id=clean_domain)
    return json.dumps({
        "domain": clean_domain,
        "nodes_count": store.graph.number_of_nodes(),
        "edges_count": store.graph.number_of_edges(),
    }, indent=2)

def main():
    mcp.run()

if __name__ == "__main__":
    main()
