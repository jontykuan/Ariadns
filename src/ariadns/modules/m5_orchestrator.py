"""Module 5: Evidence-Chained Orchestration, Noise Filtering, and Case Session Stepwise Execution."""

import datetime
import hashlib
import json
from typing import Any, Optional
from ariadns.models.config import AppConfig
from ariadns.models.entities import (
    IdentityProfile,
    Infrastructure,
    InvestigationResult,
    L2Result,
    PivotResult,
    PropositionNode,
    SessionAuditEntry,
    SubdomainRecord,
)
from ariadns.models.enums import (
    ConfidenceLevel,
    EdgeType,
    NodeType,
    OriginVerificationStatus,
    PropositionKind,
)
from ariadns.modules.m1_local_probe import LocalDnsResolver
from ariadns.modules.m2_subdomain import SubdomainEnumerator
from ariadns.modules.m3_origin import OriginDetector
from ariadns.modules.m4_pivoting import PivotingEngine
from ariadns.storage.db import DatabaseManager
from ariadns.storage.evidence_dag import EvidenceChainDAG, map_custodians_for_node
from ariadns.storage.graph_store import PropertyGraphStore
from ariadns.utils.rate_limiter import HttpClient, RateLimiter
from ariadns.utils.warninglist_sync import WarninglistSynchronizer

class Orchestrator:
    def __init__(self, config: AppConfig | None = None, db: DatabaseManager | None = None):
        self.config = config or AppConfig.load()
        self.db = db or DatabaseManager(self.config.db_path)
        self.rate_limiter = RateLimiter(self.db, self.config)
        self.http_client = HttpClient(self.rate_limiter, self.config)

        # Lazy 7-day warninglist check on initialization
        try:
            WarninglistSynchronizer(self.db, self.http_client, self.config).ensure_warninglists_synced()
        except Exception:
            pass

        self.m1 = LocalDnsResolver(self.db, self.http_client, self.config)
        self.m2 = SubdomainEnumerator(self.db, self.http_client, self.config)
        self.m3 = OriginDetector(self.db, self.http_client, self.config)
        self.m4 = PivotingEngine(self.db, self.http_client, self.config)

    def run_investigation(self, domain: str, depth: int = 1, run_portscan: bool = False) -> InvestigationResult:
        domain = domain.lower().strip()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        graph_store = PropertyGraphStore(self.db, session_id=domain)
        evidence_dag = EvidenceChainDAG(session_id=domain)

        l1_node_id = graph_store.add_node(NodeType.DOMAIN_L1.value, domain)

        # 1. Module 1: DNS & Identity & Banner
        dns_records = self.m1.resolve_records(domain)
        identity = self.m1.get_identity_profile(domain, dns_records)
        infra = self.m1.probe_infrastructure(domain, dns_records.get("A", []), run_portscan=run_portscan)

        # Store graph nodes & edges
        for a_rec in dns_records.get("A", []):
            ip_id = graph_store.add_node(NodeType.IP.value, a_rec)
            graph_store.add_edge(l1_node_id, ip_id, EdgeType.RESOLVES_TO.value)
        if infra.asn:
            asn_id = graph_store.add_node(NodeType.ASN.value, infra.asn)
            for a_rec in dns_records.get("A", []):
                ip_id = f"{NodeType.IP.value}:{a_rec}"
                graph_store.add_edge(ip_id, asn_id, EdgeType.RESOLVES_TO.value)
        for mx_entry in dns_records.get("MX", []):
            parts = mx_entry.split()
            mx_host = parts[1] if len(parts) > 1 else parts[0]
            mx_id = graph_store.add_node(NodeType.MX.value, mx_host)
            graph_store.add_edge(l1_node_id, mx_id, EdgeType.USES_MX.value)
        for ns_host in dns_records.get("NS", []):
            ns_id = graph_store.add_node(NodeType.NS.value, ns_host)
            graph_store.add_edge(l1_node_id, ns_id, EdgeType.USES_NS.value)
        for tok_k, tok_v in identity.verification_tokens.items():
            tok_id = graph_store.add_node(NodeType.TOKEN.value, f"{tok_k}:{tok_v}")
            graph_store.add_edge(l1_node_id, tok_id, EdgeType.HAS_TOKEN.value)

        # Add Base Facts to Evidence DAG
        resolved_ips_str = str(dns_records.get("A", []))
        evidence_dag.add_proposition(
            "F1",
            PropositionKind.FACT.value,
            f"Domain {domain} resolves to A:{resolved_ips_str}, CDN:{infra.is_cdn} ({infra.cdn_provider or 'None'}), Server:{infra.server_banner or 'Unknown'}",
            target_entity=domain,
            entity_type="DOMAIN_L1"
        )
        evidence_dag.add_proposition(
            "F2",
            PropositionKind.FACT.value,
            f"Domain {domain} registered via '{identity.registrar_name or 'Unknown'}', SOA Admin '{identity.soa_admin_email or 'N/A'}', Tokens: {list(identity.verification_tokens.keys())}",
            target_entity=domain,
            entity_type="DOMAIN_L1"
        )

        l1_custodians = map_custodians_for_node("DOMAIN_L1", domain, {
            "registrar_name": identity.registrar_name,
            "ns_list": dns_records.get("NS", []),
            "cdn_provider": infra.cdn_provider,
            "current_ip": infra.current_ip,
        })
        evidence_dag.add_proposition(
            "C1",
            PropositionKind.CONCLUSION.value,
            f"Active infrastructure and registration authority identified for {domain}",
            premises=["F1", "F2"],
            rule_name="RULE_DIRECT_OBSERVATION",
            target_entity=domain,
            entity_type="DOMAIN_L1",
            custodians=l1_custodians,
        )

        # 2. Module 2: Subdomain Enumeration
        subdomains: list[SubdomainRecord] = self.m2.run(domain)
        for sub in subdomains:
            s_id = graph_store.add_node(NodeType.SUBDOMAIN.value, sub.subdomain)
            graph_store.add_edge(l1_node_id, s_id, EdgeType.HAS_SUBDOMAIN.value)
            if sub.ip:
                ip_id = graph_store.add_node(NodeType.IP.value, sub.ip)
                graph_store.add_edge(s_id, ip_id, EdgeType.RESOLVES_TO.value)

        # 3. Module 3: Origin Detection
        target_pivot_ip = infra.current_ip
        if infra.is_cdn:
            first_ip = dns_records.get("A", [None])[0] if dns_records.get("A") else None
            origin_ip, status = self.m3.detect_origin(domain, first_ip)
            status_val = status.value if hasattr(status, "value") else str(status)
            if origin_ip:
                infra.suspected_origin_ip = origin_ip
                infra.origin_verification_status = status_val
                target_pivot_ip = origin_ip
                orig_id = graph_store.add_node(NodeType.IP.value, origin_ip)
                graph_store.add_edge(l1_node_id, orig_id, EdgeType.HISTORICAL_A.value)

                evidence_dag.add_proposition(
                    "F_ORIGIN",
                    PropositionKind.FACT.value,
                    f"Historical/Subdomain analysis found candidate origin IP {origin_ip} for {domain} (Status: {status_val})",
                    target_entity=origin_ip,
                    entity_type="IP"
                )
                origin_custodians = map_custodians_for_node("IP", origin_ip, {
                    "asn_org_name": infra.asn_org_name or "Cloud/Hosting Provider",
                    "asn": infra.asn or "AS_UNKNOWN",
                    "country": infra.country or "UNKNOWN",
                })
                evidence_dag.add_proposition(
                    "C_ORIGIN",
                    PropositionKind.CONCLUSION.value,
                    f"Candidate Origin Server {origin_ip} confirmed/identified for protected domain {domain}",
                    premises=["C1", "F_ORIGIN"],
                    rule_name="RULE_ORIGIN_CONFIRMATION",
                    target_entity=origin_ip,
                    entity_type="IP",
                    custodians=origin_custodians,
                )

        # 4. Module 4: Pivoting
        pivot_result = PivotResult()
        discovered_l2_domains: set[str] = set()

        if target_pivot_ip and not infra.is_cdn:
            if not graph_store.is_shared_hosting_ip(target_pivot_ip, threshold=self.config.shared_ip_threshold):
                same_ip_domains = self.m4.reverse_ip(target_pivot_ip)
                if len(same_ip_domains) <= self.config.shared_ip_threshold:
                    pivot_result.same_origin_domains = [d for d in same_ip_domains if d != domain]
                    for d in pivot_result.same_origin_domains:
                        discovered_l2_domains.add(d)
                        d_id = graph_store.add_node(NodeType.DOMAIN_L2.value, d)
                        ip_node_id = f"{NodeType.IP.value}:{target_pivot_ip}"
                        graph_store.add_edge(ip_node_id, d_id, EdgeType.SAME_ORIGIN_IP.value)

        # Reverse MX
        for mx_entry in dns_records.get("MX", []):
            parts = mx_entry.split()
            mx_host = parts[1] if len(parts) > 1 else parts[0]
            if not self.config.is_mx_blacklisted(mx_host):
                same_mx = self.m4.reverse_mx(mx_host)
                for d in same_mx:
                    if d != domain:
                        pivot_result.same_mx_domains.append(d)
                        discovered_l2_domains.add(d)
                        d_id = graph_store.add_node(NodeType.DOMAIN_L2.value, d)
                        mx_node_id = f"{NodeType.MX.value}:{mx_host}"
                        graph_store.add_edge(mx_node_id, d_id, EdgeType.SAME_MX.value)

        # 5. Score L2 Domains and Recursion if depth >= 2
        l2_results: list[L2Result] = []
        l2_idx = 1
        for l2_d in sorted(list(discovered_l2_domains)):
            score, conf_level = graph_store.score_l2_domain(domain, l2_d)
            rel_type = "Same Origin IP" if l2_d in pivot_result.same_origin_domains else "Same MX"
            l2_item = L2Result(
                domain=l2_d,
                relation_type=rel_type,
                confidence=conf_level,
            )

            # If depth >= 2 and HIGH confidence, execute lightweight L2 probe
            if depth >= 2 and conf_level == ConfidenceLevel.HIGH.value:
                l2_dns = self.m1.resolve_records(l2_d)
                l2_ips = l2_dns.get("A", [])
                l2_item.resolved_ip = l2_ips[0] if l2_ips else None
                l2_id = self.m1.get_identity_profile(l2_d, l2_dns)
                l2_item.registrant_email = l2_id.soa_admin_email or l2_id.registrant_email
                l2_item.registrar_name = l2_id.registrar_name

            l2_results.append(l2_item)

            # Add Evidence Proposition for L2 Domain
            premise_for_l2 = ["C_ORIGIN"] if ("C_ORIGIN" in evidence_dag.propositions and rel_type == "Same Origin IP") else ["C1"]
            f_l2_id = f"F_L2_{l2_idx}"
            c_l2_id = f"C_L2_{l2_idx}"
            evidence_dag.add_proposition(
                f_l2_id,
                PropositionKind.FACT.value,
                f"Reverse lookup matched {l2_d} via {rel_type}",
                target_entity=l2_d,
                entity_type="DOMAIN_L2"
            )
            l2_custodians = map_custodians_for_node("DOMAIN_L2", l2_d, {
                "registrar_name": l2_item.registrar_name,
            })
            evidence_dag.add_proposition(
                c_l2_id,
                PropositionKind.CONCLUSION.value,
                f"{l2_d} is co-attributed to the same infrastructure ({rel_type}, Confidence: {conf_level})",
                premises=premise_for_l2 + [f_l2_id],
                rule_name="RULE_PIVOT_CORRELATION",
                target_entity=l2_d,
                entity_type="DOMAIN_L2",
                custodians=l2_custodians,
            )
            l2_idx += 1

        ordered_props = evidence_dag.get_ordered_propositions()
        edges = [(u, p.prop_id) for p in ordered_props for u in p.premises]
        self.db.save_normalized_evidence(domain, ordered_props, edges, replace=True)

        result = InvestigationResult(
            target_domain=domain,
            investigation_timestamp=timestamp,
            identity_profile=identity,
            infrastructure=infra,
            subdomains=subdomains,
            pivots=pivot_result,
            l2_recursive_results=l2_results,
            evidence_chain=ordered_props,
        )

        return result

    def run_step(
        self,
        session_id: str,
        module_name: str,
        target: str,
        params: Optional[dict[str, Any]] = None
    ) -> SessionAuditEntry:
        """Execute a single module stepwise against a case session, merging facts and logging audit trail."""
        session_id = session_id.strip().lower()
        module_name = module_name.strip().lower()
        target = target.strip().lower()
        params = params or {}
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        existing_props = self.db.get_normalized_propositions(session_id, rendered_only=False)
        existing_prop_ids = {p.prop_id for p in existing_props}
        new_props: list[PropositionNode] = []
        new_edges: list[tuple[str, str]] = []
        added_fact_ids: list[str] = []

        if module_name == "m1":
            dns_records = self.m1.resolve_records(target)
            identity = self.m1.get_identity_profile(target, dns_records)
            infra = self.m1.probe_infrastructure(target, dns_records.get("A", []), run_portscan=params.get("run_portscan", False))

            is_secondary = (target != session_id)
            target_slug = target.replace(".", "_").replace(":", "_").replace("-", "_")
            prefix = f"{target_slug}_" if is_secondary else ""
            f1_id = f"{prefix}F1"
            f2_id = f"{prefix}F2"
            c1_id = f"{prefix}C1"

            f1 = PropositionNode(
                prop_id=f1_id,
                node_kind=PropositionKind.FACT.value,
                rank=0,
                statement=f"Domain {target} resolves to A:{dns_records.get('A', [])}, CDN:{infra.is_cdn} ({infra.cdn_provider or 'None'}), Server:{infra.server_banner or 'Unknown'}",
                target_entity=target,
                entity_type="DOMAIN_L2" if is_secondary else "DOMAIN_L1"
            )
            f2 = PropositionNode(
                prop_id=f2_id,
                node_kind=PropositionKind.FACT.value,
                rank=0,
                statement=f"Domain {target} registered via '{identity.registrar_name or 'Unknown'}', SOA Admin '{identity.soa_admin_email or 'N/A'}', Tokens: {list(identity.verification_tokens.keys())}",
                target_entity=target,
                entity_type="DOMAIN_L2" if is_secondary else "DOMAIN_L1"
            )
            l1_custodians = map_custodians_for_node("DOMAIN_L1", target, {
                "registrar_name": identity.registrar_name,
                "ns_list": dns_records.get("NS", []),
                "cdn_provider": infra.cdn_provider,
                "current_ip": infra.current_ip,
            })
            c1_premises = [f1_id, f2_id]
            # Link to pivot origin if target was discovered via pivoting/unproxied IP
            for p in existing_props:
                if p.target_entity == target and p.prop_id not in c1_premises:
                    c1_premises.append(p.prop_id)
                    new_edges.append((p.prop_id, c1_id))

            c1 = PropositionNode(
                prop_id=c1_id,
                node_kind=PropositionKind.CONCLUSION.value,
                rank=1,
                statement=f"Active infrastructure and registration authority identified for {target}",
                premises=c1_premises,
                rule_name="RULE_DIRECT_OBSERVATION",
                target_entity=target,
                entity_type="DOMAIN_L2" if is_secondary else "DOMAIN_L1",
                custodians=l1_custodians
            )
            new_props.extend([f1, f2, c1])
            new_edges.extend([(f1_id, c1_id), (f2_id, c1_id)])
            added_fact_ids.extend([f1_id, f2_id])

        elif module_name == "m2":
            subdomains = self.m2.run(target)
            sub_idx = 1
            for sub in subdomains:
                if sub.ip:
                    f_id = f"F_SUB_{sub_idx}"
                    f_node = PropositionNode(
                        prop_id=f_id,
                        node_kind=PropositionKind.FACT.value,
                        rank=0,
                        statement=f"Subdomain {sub.subdomain} resolves to {sub.ip} (Server: {sub.server or 'Unknown'})",
                        target_entity=sub.subdomain,
                        entity_type="SUBDOMAIN"
                    )
                    new_props.append(f_node)
                    added_fact_ids.append(f_id)

                    # If unproxied / non-CDN IP found
                    if "47." in sub.ip or "192." in sub.ip or "10." in sub.ip or not sub.server == "cloudflare":
                        c_id = f"C_UNPROXIED_{sub_idx}"
                        c_node = PropositionNode(
                            prop_id=c_id,
                            node_kind=PropositionKind.CONCLUSION.value,
                            rank=2,
                            statement=f"Unproxied backend origin host detected at {sub.ip} via {sub.subdomain}",
                            premises=["C1", f_id] if "C1" in existing_prop_ids else [f_id],
                            rule_name="RULE_ORIGIN_CONFIRMATION",
                            target_entity=sub.ip,
                            entity_type="IP"
                        )
                        new_props.append(c_node)
                        new_edges.append((f_id, c_id))
                        if "C1" in existing_prop_ids:
                            new_edges.append(("C1", c_id))
                    sub_idx += 1

        elif module_name == "m3":
            # Origin detection
            current_ips = params.get("current_ips", [])
            origin_ip, status = self.m3.detect_origin(target, current_ips)
            if origin_ip:
                f_id = "F_ORIGIN"
                f_node = PropositionNode(
                    prop_id=f_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=0,
                    statement=f"Passive DNS / collision detected candidate origin IP {origin_ip} (Status: {status.value})",
                    target_entity=origin_ip,
                    entity_type="IP"
                )
                c_node = PropositionNode(
                    prop_id="C_ORIGIN",
                    node_kind=PropositionKind.CONCLUSION.value,
                    rank=2,
                    statement=f"Candidate Origin Server {origin_ip} confirmed/identified for {target}",
                    premises=["C1", f_id] if "C1" in existing_prop_ids else [f_id],
                    rule_name="RULE_ORIGIN_CONFIRMATION",
                    target_entity=origin_ip,
                    entity_type="IP"
                )
                new_props.extend([f_node, c_node])
                new_edges.append((f_id, "C_ORIGIN"))
                if "C1" in existing_prop_ids:
                    new_edges.append(("C1", "C_ORIGIN"))
                added_fact_ids.append(f_id)

        elif module_name == "m4":
            # Pivoting
            pivot_type = params.get("type", "reverse_ip")
            pivoted: list[str] = []
            if pivot_type == "reverse_ip":
                pivoted = self.m4.reverse_ip(target)
            elif pivot_type == "reverse_mx":
                pivoted = self.m4.reverse_mx(target)
            elif pivot_type == "reverse_ns":
                pivoted = self.m4.reverse_ns(target)

            for idx, p_dom in enumerate(pivoted[:10], start=1):
                f_id = f"F_PIVOT_{idx}"
                f_node = PropositionNode(
                    prop_id=f_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=0,
                    statement=f"Pivoting on {target} ({pivot_type}) discovered correlated domain {p_dom}",
                    target_entity=p_dom,
                    entity_type="DOMAIN_L2"
                )
                new_props.append(f_node)
                added_fact_ids.append(f_id)

        # Save merged propositions without overwriting previous steps
        self.db.save_normalized_evidence(session_id, new_props, new_edges, replace=False)

        # Calculate state SHA-256
        all_props = self.db.get_normalized_propositions(session_id, rendered_only=False)
        canon = json.dumps([{"id": p.prop_id, "stmt": p.statement} for p in all_props], sort_keys=True)
        artifact_sha256 = hashlib.sha256(canon.encode("utf-8")).hexdigest()

        # Append audit log
        logs = self.db.get_audit_logs(session_id)
        step_seq = len(logs) + 1
        entry = SessionAuditEntry(
            session_id=session_id,
            step_seq=step_seq,
            timestamp=timestamp,
            module_name=module_name,
            target=target,
            params_json=json.dumps(params),
            added_fact_ids=added_fact_ids,
            artifact_sha256=artifact_sha256
        )
        self.db.append_audit_log(entry)
        return entry
