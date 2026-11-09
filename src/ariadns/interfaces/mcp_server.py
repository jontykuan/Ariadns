"""Ariadns FastMCP Server for Agentic Access."""

import json
from pathlib import Path
from typing import Any
try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:
    from mcp.server.fastmcp import FastMCP

from ariadns.models.config import AppConfig
from ariadns.models.enums import NodeType
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.modules.m6_reporting import ReportingEngine
from ariadns.modules.m7_manual_oob import trigger_manual_oob
from ariadns.storage.db import DatabaseManager
from ariadns.storage.graph_store import PropertyGraphStore

mcp = FastMCP("ariadns-mcp")

def get_orchestrator() -> Orchestrator:
    config = AppConfig.load()
    db = DatabaseManager(config.db_path)
    return Orchestrator(config=config, db=db)

@mcp.tool()
def osint_scan(
    domain: str,
    mode: str = "full",
    depth: int = 1,
    portscan: bool = False
) -> dict[str, Any]:
    """Execute domain OSINT scan. Saves full details in SQLite and returns a compact digest (<= 600 tokens)."""
    orchestrator = get_orchestrator()
    clean_domain = domain.strip().lower()
    result = orchestrator.run_investigation(
        domain=clean_domain,
        depth=depth,
        run_portscan=portscan
    )

    infra = result.infrastructure
    id_prof = result.identity_profile

    return {
        "status": "COMPLETED",
        "target_domain": clean_domain,
        "current_ip": infra.current_ip,
        "is_cdn": infra.is_cdn,
        "cdn_provider": infra.cdn_provider,
        "asn_org_name": infra.asn_org_name,
        "registrar_name": id_prof.registrar_name,
        "suspected_origin_ip": infra.suspected_origin_ip,
        "origin_verification_status": infra.origin_verification_status,
        "server_banner": infra.server_banner,
        "soa_admin_email": id_prof.soa_admin_email,
        "verification_tokens": id_prof.verification_tokens,
        "html_tracking_tokens": id_prof.html_tracking_tokens,
        "subdomains_count": len(result.subdomains),
        "l2_domains_count": len(result.l2_recursive_results),
        "evidence_propositions_count": len(result.evidence_chain),
        "top_l2_candidates": [
            {"domain": l2.domain, "relation": l2.relation_type, "confidence": l2.confidence}
            for l2 in result.l2_recursive_results[:10]
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
    """Inspect investigation graph details, evidence chain, custodians, or execute guarded read-only SELECT SQL."""
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
        # Load from session result
        cached = orchestrator.db.get_dns_cache(clean_domain, "A")
        # Run lightweight investigation if not present
        res = orchestrator.run_investigation(clean_domain, depth=1)
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
            for p in res.evidence_chain[:limit]
        ]
        return {"session_id": clean_domain, "evidence_chain": propositions}

    elif query_type == "custodians":
        res = orchestrator.run_investigation(clean_domain, depth=1)
        custodian_matrix = []
        for p in res.evidence_chain:
            if p.node_kind == "CONCLUSION" and p.custodians:
                for c in p.custodians:
                    custodian_matrix.append({
                        "conclusion_id": p.prop_id,
                        "target_entity": p.target_entity,
                        "entity_type": p.entity_type,
                        "custodian_name": c.custodian_name,
                        "custodian_role": c.custodian_role,
                        "queryable_records": c.queryable_records,
                    })
        return {"session_id": clean_domain, "custodians": custodian_matrix[:limit]}

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
            n for n, d in store.graph.nodes(data=True)
            if d.get("node_type") == NodeType.DOMAIN_L2.value
        ]
        candidates = []
        for n in l2_nodes:
            lbl = store.graph.nodes[n].get("label", n)
            score, conf = store.score_l2_domain(clean_domain, lbl)
            candidates.append({"domain": lbl, "score": score, "confidence": conf})
        return {"l2_candidates": sorted(candidates, key=lambda x: x["score"], reverse=True)[:limit]}

    else:
        return {
            "session_id": clean_domain,
            "total_nodes": store.graph.number_of_nodes(),
            "total_edges": store.graph.number_of_edges(),
        }

@mcp.tool()
def osint_expand(
    parent_domain: str,
    l2_domain: str,
    modules: list[str] | None = None
) -> dict[str, Any]:
    """Execute on-demand deep probing on a specific L2 domain and merge results into the session graph."""
    orchestrator = get_orchestrator()
    clean_parent = parent_domain.strip().lower()
    clean_l2 = l2_domain.strip().lower()

    l2_result = orchestrator.run_investigation(domain=clean_l2, depth=1)

    parent_store = PropertyGraphStore(orchestrator.db, session_id=clean_parent)
    l2_store = PropertyGraphStore(orchestrator.db, session_id=clean_l2)

    for n_id, data in l2_store.graph.nodes(data=True):
        parent_store.add_node(data.get("node_type", "UNKNOWN"), data.get("label", n_id))

    for u, v, data in l2_store.graph.edges(data=True):
        parent_store.add_edge(u, v, data.get("relation_type", "RELATED"), weight=data.get("weight", 0.5))

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
