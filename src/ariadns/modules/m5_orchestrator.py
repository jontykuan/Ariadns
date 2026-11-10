"""Module 5: Evidence-Chained Orchestration, Noise Filtering, and Case Session Stepwise Execution."""

import datetime
import hashlib
import ipaddress
import json
import re
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
from ariadns.modules.m9_traceroute import run_active_trace
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

        lang = params.get("lang", "en")
        is_zh = (lang == "zh")

        try:
            ipaddress.ip_address(target)
            is_ip_target = True
        except ValueError:
            is_ip_target = False

        if module_name == "m1":
            is_secondary = (target != session_id)
            target_slug = target.replace(".", "_").replace(":", "_").replace("-", "_")
            prefix = f"{target_slug}_" if is_secondary else ""
            f1_id = f"{prefix}F1"
            f2_id = f"{prefix}F2"
            c1_id = f"{prefix}C1"

            parent_p = None
            if is_secondary:
                for p in existing_props:
                    if p.target_entity == target or target in p.statement:
                        parent_p = p
                        break
                if not parent_p:
                    for p in existing_props:
                        if p.prop_id == "F1":
                            parent_p = p
                            break
            parent_id = parent_p.prop_id if parent_p else None
            parent_rank = parent_p.rank if parent_p else 0

            if is_ip_target:
                infra = self.m1.probe_infrastructure(target, [target], run_portscan=params.get("run_portscan", False))
                asn_label = f"{infra.asn or 'AS_UNKNOWN'} ({infra.asn_org_name or ('網路機房服務商' if is_zh else 'Hosting Provider')})"
                f1_premises = [parent_id] if parent_id else []
                f1_rank = (parent_rank + 1) if parent_id else 0
                stmt_f1 = (
                    f"【依據】{parent_id or target}（解析紀錄包含 {target}） 【方法】Team Cymru BGP/ASN 與 HTTP 標頭探測 【結果】主機 IP {target} 歸屬於 {asn_label}，Server 標頭: {infra.server_banner or '未知'}，CDN 代理: {infra.is_cdn}"
                    if is_zh else
                    f"[Source] {parent_id or target} (Resolves to {target}) [Method] Team Cymru BGP/ASN & HTTP Banner Probe [Result] Host IP {target} belongs to {asn_label}, Server:{infra.server_banner or 'Unknown'}, CDN:{infra.is_cdn}"
                )
                f1 = PropositionNode(
                    prop_id=f1_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=f1_rank,
                    statement=stmt_f1,
                    premises=f1_premises,
                    target_entity=target,
                    entity_type="IP"
                )
                ip_custodians = map_custodians_for_node("IP", target, {
                    "is_cdn": infra.is_cdn,
                    "cdn_provider": infra.cdn_provider,
                    "asn": infra.asn,
                    "asn_org_name": infra.asn_org_name,
                    "lang": lang,
                })
                c1_premises = [f1_id]
                for p in existing_props:
                    if (p.target_entity == target or target in p.statement) and p.prop_id not in c1_premises:
                        c1_premises.append(p.prop_id)
                        new_edges.append((p.prop_id, c1_id))

                c1_rank = f1_rank + 1
                stmt_c1 = (
                    f"【依據】{f1_id} 【方法】因果歸納與資料保管單位映射 【結果】已確認主機 IP {target} 之網路電信商與機房歸屬（{asn_label}）"
                    if is_zh else
                    f"[Source] {f1_id} [Method] Causal Induction & Custodian Mapping [Result] Active hosting infrastructure and network operator identified for IP {target} ({asn_label})"
                )
                c1 = PropositionNode(
                    prop_id=c1_id,
                    node_kind=PropositionKind.CONCLUSION.value,
                    rank=c1_rank,
                    statement=stmt_c1,
                    premises=c1_premises,
                    rule_name="RULE_DIRECT_OBSERVATION",
                    target_entity=target,
                    entity_type="IP",
                    custodians=ip_custodians
                )
                new_props.extend([f1, c1])
                if parent_id:
                    new_edges.append((parent_id, f1_id))
                new_edges.append((f1_id, c1_id))
                added_fact_ids.append(f1_id)
            else:
                dns_records = self.m1.resolve_records(target)
                identity = self.m1.get_identity_profile(target, dns_records)
                infra = self.m1.probe_infrastructure(target, dns_records.get("A", []), run_portscan=params.get("run_portscan", False))
                ent_type = "DOMAIN_L2" if is_secondary else "DOMAIN_L1"

                f1_premises = [parent_id] if (is_secondary and parent_id) else []
                f1_rank = (parent_rank + 1) if (is_secondary and parent_id) else 0

                stmt_f1 = (
                    f"【依據】{parent_id or ('調查目標網域 ' + target)} 【方法】本地 DNS 解析與 HTTP 標頭探測 【結果】解析至 A:{dns_records.get('A', [])}，CDN:{infra.is_cdn} ({infra.cdn_provider or '無'})，Server:{infra.server_banner or '未知'}"
                    if is_zh else
                    f"[Source] {parent_id or ('Target Domain ' + target)} [Method] Local DNS & HTTP Banner Probe [Result] Resolves to A:{dns_records.get('A', [])}, CDN:{infra.is_cdn} ({infra.cdn_provider or 'None'}), Server:{infra.server_banner or 'Unknown'}"
                )
                stmt_f2 = (
                    f"【依據】{parent_id or ('調查目標網域 ' + target)} 【方法】RDAP 註冊資訊與 DNS TXT 查詢 【結果】註冊商為 '{identity.registrar_name or '未知'}'，SOA 信箱 '{identity.soa_admin_email or '無'}'，驗證標記: {list(identity.verification_tokens.keys())}"
                    if is_zh else
                    f"[Source] {parent_id or ('Target Domain ' + target)} [Method] RDAP Registration & DNS TXT Probe [Result] Registered via '{identity.registrar_name or 'Unknown'}', SOA Admin '{identity.soa_admin_email or 'N/A'}', Tokens: {list(identity.verification_tokens.keys())}"
                )
                f1 = PropositionNode(
                    prop_id=f1_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=f1_rank,
                    statement=stmt_f1,
                    premises=f1_premises,
                    target_entity=target,
                    entity_type=ent_type
                )
                f2 = PropositionNode(
                    prop_id=f2_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=f1_rank,
                    statement=stmt_f2,
                    premises=f1_premises,
                    target_entity=target,
                    entity_type=ent_type
                )
                l1_custodians = map_custodians_for_node(ent_type, target, {
                    "registrar_name": identity.registrar_name,
                    "ns_list": dns_records.get("NS", []),
                    "cdn_provider": infra.cdn_provider,
                    "current_ip": infra.current_ip,
                    "lang": lang,
                })
                c1_premises = [f1_id, f2_id]
                for p in existing_props:
                    if (p.target_entity == target or target in p.statement) and p.prop_id not in c1_premises:
                        c1_premises.append(p.prop_id)
                        new_edges.append((p.prop_id, c1_id))

                c1_rank = f1_rank + 1
                stmt_c1 = (
                    f"【依據】{f1_id}, {f2_id} 【方法】因果歸納與資料保管單位映射 【結果】已確認網域 {target} 之基礎建設與註冊管理機構（{identity.registrar_name or '未知'}）"
                    if is_zh else
                    f"[Source] {f1_id}, {f2_id} [Method] Causal Induction & Custodian Mapping [Result] Active infrastructure and registration authority identified for {target}"
                )
                c1 = PropositionNode(
                    prop_id=c1_id,
                    node_kind=PropositionKind.CONCLUSION.value,
                    rank=c1_rank,
                    statement=stmt_c1,
                    premises=c1_premises,
                    rule_name="RULE_DIRECT_OBSERVATION",
                    target_entity=target,
                    entity_type=ent_type,
                    custodians=l1_custodians
                )
                new_props.extend([f1, f2, c1])
                if is_secondary and parent_id:
                    new_edges.extend([(parent_id, f1_id), (parent_id, f2_id)])
                new_edges.extend([(f1_id, c1_id), (f2_id, c1_id)])
                added_fact_ids.extend([f1_id, f2_id])

        elif module_name == "m2":
            subdomains = self.m2.run(target)
            parent_p = next((p for p in existing_props if p.prop_id in ("F1", f"{target}_F1")), None)
            if not parent_p and existing_props:
                parent_p = existing_props[0]
            parent_id = parent_p.prop_id if parent_p else None
            parent_rank = parent_p.rank if parent_p else 0

            sub_idx = 1
            for sub in subdomains:
                if sub.ip:
                    f_id = f"F_SUB_{sub_idx}"
                    stmt_sub = (
                        f"【依據】{parent_id or target}（根網域 {target}） 【方法】被動憑證透明度 (CT) 與 DNS 字典枚舉 【結果】子網域 {sub.subdomain} 解析至 {sub.ip}（伺服器: {sub.server or '未知'}）"
                        if is_zh else
                        f"[Source] {parent_id or target} (Root Domain {target}) [Method] Passive CT Logs & DNS Wordlist Enumeration [Result] Subdomain {sub.subdomain} resolves to {sub.ip} (Server: {sub.server or 'Unknown'})"
                    )
                    f_node = PropositionNode(
                        prop_id=f_id,
                        node_kind=PropositionKind.FACT.value,
                        rank=parent_rank + 1,
                        statement=stmt_sub,
                        premises=[parent_id] if parent_id else [],
                        target_entity=sub.subdomain,
                        entity_type="SUBDOMAIN"
                    )
                    new_props.append(f_node)
                    if parent_id:
                        new_edges.append((parent_id, f_id))
                    added_fact_ids.append(f_id)

                    # If unproxied / non-CDN IP found
                    if "47." in sub.ip or "192." in sub.ip or "10." in sub.ip or not sub.server == "cloudflare":
                        c_id = f"C_UNPROXIED_{sub_idx}"
                        stmt_unp = (
                            f"【依據】{f_id} 【方法】IP 特徵比對與非 CDN 源站辨識 【結果】透過子網域 {sub.subdomain} 發現未經 CDN 代理之後端真實主機 {sub.ip}"
                            if is_zh else
                            f"[Source] {f_id} [Method] IP Signature & Non-CDN Backend Detection [Result] Unproxied backend origin host detected at {sub.ip} via {sub.subdomain}"
                        )
                        c_node = PropositionNode(
                            prop_id=c_id,
                            node_kind=PropositionKind.CONCLUSION.value,
                            rank=f_node.rank + 1,
                            statement=stmt_unp,
                            premises=["C1", f_id] if "C1" in existing_prop_ids else [f_id],
                            rule_name="RULE_ORIGIN_CONFIRMATION",
                            target_entity=sub.ip,
                            entity_type="IP",
                            custodians=map_custodians_for_node("IP", sub.ip, {"is_cdn": False, "lang": lang})
                        )
                        new_props.append(c_node)
                        new_edges.append((f_id, c_id))
                        if "C1" in existing_prop_ids:
                            new_edges.append(("C1", c_id))
                    sub_idx += 1

        elif module_name == "m3":
            # Origin detection
            parent_p = next((p for p in existing_props if p.prop_id in ("F1", f"{target}_F1")), None)
            if not parent_p and existing_props:
                parent_p = existing_props[0]
            parent_id = parent_p.prop_id if parent_p else None
            parent_rank = parent_p.rank if parent_p else 0

            current_ips = params.get("current_ips", [])
            first_ip = current_ips[0] if isinstance(current_ips, list) and current_ips else (current_ips if isinstance(current_ips, str) else None)
            origin_ip, status = self.m3.detect_origin(target, first_ip)
            status_val = status.value if hasattr(status, "value") else str(status)
            if origin_ip:
                f_id = "F_ORIGIN"
                stmt_forig = (
                    f"【依據】{parent_id or target}（受保護網域 {target}） 【方法】被動 DNS 歷史紀錄回溯與 HTTP Host / Favicon 碰撞探測 【結果】發現候選真實來源主機 IP {origin_ip}（狀態: {status_val}）"
                    if is_zh else
                    f"[Source] {parent_id or target} (Protected Domain {target}) [Method] Historical pDNS & HTTP Host / Favicon Collision [Result] Passive DNS / collision detected candidate origin IP {origin_ip} (Status: {status_val})"
                )
                f_node = PropositionNode(
                    prop_id=f_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=parent_rank + 1,
                    statement=stmt_forig,
                    premises=[parent_id] if parent_id else [],
                    target_entity=origin_ip,
                    entity_type="IP"
                )
                stmt_corig = (
                    f"【依據】{f_id} 【方法】特徵碰撞驗證與來源歸納 【結果】已確認受保護網域 {target} 之候選真實來源伺服器為 {origin_ip}"
                    if is_zh else
                    f"[Source] {f_id} [Method] Fingerprint Match & Origin Attribution [Result] Candidate Origin Server {origin_ip} confirmed/identified for {target}"
                )
                c_node = PropositionNode(
                    prop_id="C_ORIGIN",
                    node_kind=PropositionKind.CONCLUSION.value,
                    rank=f_node.rank + 1,
                    statement=stmt_corig,
                    premises=["C1", f_id] if "C1" in existing_prop_ids else [f_id],
                    rule_name="RULE_ORIGIN_CONFIRMATION",
                    target_entity=origin_ip,
                    entity_type="IP",
                    custodians=map_custodians_for_node("IP", origin_ip, {"is_cdn": False, "lang": lang})
                )
                new_props.extend([f_node, c_node])
                if parent_id:
                    new_edges.append((parent_id, f_id))
                new_edges.append((f_id, "C_ORIGIN"))
                if "C1" in existing_prop_ids:
                    new_edges.append(("C1", "C_ORIGIN"))
                added_fact_ids.append(f_id)

        elif module_name == "m4":
            # Pivoting
            pivot_type = params.get("type", "reverse_ip")
            pivoted: list[str] = []
            pivot_source_target = target
            parent_prop = None
            if pivot_type == "reverse_ip":
                if not is_ip_target:
                    # Extract resolved IP from existing propositions for this domain
                    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
                    for p in existing_props:
                        if p.target_entity == target or p.prop_id == "F1":
                            found_ips = ip_regex.findall(p.statement)
                            if found_ips:
                                pivot_source_target = found_ips[0]
                                parent_prop = p
                                break
                pivoted = self.m4.reverse_ip(pivot_source_target)
            elif pivot_type == "reverse_mx":
                pivoted = self.m4.reverse_mx(target)
            elif pivot_type == "reverse_ns":
                pivoted = self.m4.reverse_ns(target)

            if not parent_prop:
                for p in existing_props:
                    if p.target_entity == pivot_source_target or pivot_source_target in p.statement:
                        parent_prop = p
                        break
                if not parent_prop and existing_props:
                    parent_prop = existing_props[0]

            parent_prop_id = parent_prop.prop_id if parent_prop else None
            parent_rank = parent_prop.rank if parent_prop else 0

            for idx, p_dom in enumerate(pivoted[:10], start=1):
                if p_dom.lower() == session_id or p_dom.lower() == target:
                    continue
                f_id = f"F_PIVOT_{idx}"
                stmt_piv = (
                    f"【依據】{parent_prop_id or pivot_source_target}（{pivot_source_target}） 【方法】{pivot_type} 關聯反查與 7 天誤報過濾 【結果】橫向轉向發現共構關聯網域 {p_dom}"
                    if is_zh else
                    f"[Source] {parent_prop_id or pivot_source_target} ({pivot_source_target}) [Method] {pivot_type} Pivoting with 7-Day Warninglist Filtering [Result] Discovered correlated domain {p_dom}"
                )
                f_node = PropositionNode(
                    prop_id=f_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=parent_rank + 1,
                    statement=stmt_piv,
                    premises=[parent_prop_id] if parent_prop_id else [],
                    target_entity=p_dom,
                    entity_type="DOMAIN_L2"
                )
                new_props.append(f_node)
                if parent_prop_id:
                    new_edges.append((parent_prop_id, f_id))
                added_fact_ids.append(f_id)

        elif module_name in ("trace", "m9"):
            ack_opsec = bool(params.get("ack_opsec", False) or params.get("acknowledge_risk", False))
            if not ack_opsec:
                raise ValueError("OPSEC authorization required (ack_opsec=True) to execute active route trace.")
            no_rdns = bool(params.get("no_rdns", True))
            max_hops = int(params.get("max_hops", 20))
            timeout_ms = int(params.get("timeout_ms", 500))
            tail_hops = int(params.get("tail_hops", 3))

            trace_target = target
            parent_p = None
            if not is_ip_target:
                ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
                for p in existing_props:
                    if p.target_entity == target or p.prop_id == "F1":
                        found = ip_regex.findall(p.statement)
                        if found:
                            trace_target = found[0]
                            parent_p = p
                            break

            if not parent_p:
                for p in existing_props:
                    if p.target_entity == trace_target or trace_target in p.statement:
                        parent_p = p
                        break
            if not parent_p and existing_props:
                parent_p = existing_props[0]

            parent_id = parent_p.prop_id if parent_p else None
            parent_rank = parent_p.rank if parent_p else 0
            parent_premises = [parent_id] if parent_id else []

            trace_res = run_active_trace(
                target=trace_target,
                no_rdns=no_rdns,
                max_hops=max_hops,
                timeout_ms=timeout_ms,
                tail_hops=tail_hops,
                ack_opsec=True,
            )
            hops_list = trace_res.get("tail_hops", [])
            f_trace_id = "F_TRACE"
            c_trace_id = "C_TRACE"

            if hops_list:
                hop_summaries = [
                    f"Hop#{h['hop']}:{h['ip']}({h.get('asn') or 'AS?'}/{h.get('ptr') or h.get('asn_org_name') or 'Router'})"
                    for h in hops_list
                ]
                hops_str = " -> ".join(hop_summaries)
                last_hop = hops_list[-1]
                upstream_org = last_hop.get("asn_org_name") or last_hop.get("asn") or ("上游電信路由機房" if is_zh else "Upstream Transit ISP")

                stmt_f = (
                    f"【依據】{parent_id or trace_target}（目標 IP {trace_target}） 【方法】tracert 路由躍遷追蹤與 Team Cymru 骨幹 ASN 查詢 【結果】路由躍遷追蹤（末 {len(hops_list)} 跳）至 {trace_target}: {hops_str}"
                    if is_zh else
                    f"[Source] {parent_id or trace_target} (Target IP {trace_target}) [Method] tracert Route Hop Trace & Team Cymru Backbone ASN Lookup [Result] Route hop trace (last {len(hops_list)} hops) to {trace_target}: {hops_str}"
                )
                f_node = PropositionNode(
                    prop_id=f_trace_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=parent_rank + 1,
                    statement=stmt_f,
                    premises=parent_premises,
                    rule_name="RULE_ACTIVE_TRACEROUTE",
                    target_entity=trace_target,
                    entity_type="IP"
                )
                stmt_c = (
                    f"【依據】{f_trace_id} 【方法】上游電信接入點識別與調閱單位對應 【結果】路由躍遷確認 {trace_target} 之上游實體接入機房與骨幹電信商為 {upstream_org}"
                    if is_zh else
                    f"[Source] {f_trace_id} [Method] Upstream Transit Identification & Custodian Mapping [Result] Upstream transit and physical colocation provider for {trace_target} confirmed via route trace: {upstream_org}"
                )
                trace_custodians = map_custodians_for_node("IP", last_hop["ip"], {
                    "is_cdn": False,
                    "asn": last_hop.get("asn"),
                    "asn_org_name": upstream_org,
                    "lang": lang,
                })
                c_node = PropositionNode(
                    prop_id=c_trace_id,
                    node_kind=PropositionKind.CONCLUSION.value,
                    rank=f_node.rank + 1,
                    statement=stmt_c,
                    premises=[f_trace_id],
                    rule_name="RULE_ACTIVE_TRACEROUTE",
                    target_entity=last_hop["ip"],
                    entity_type="IP",
                    custodians=trace_custodians
                )
                new_props.extend([f_node, c_node])
                if parent_id:
                    new_edges.append((parent_id, f_trace_id))
                new_edges.append((f_trace_id, c_trace_id))
                added_fact_ids.append(f_trace_id)
            else:
                stmt_f = (
                    f"【依據】{parent_id or trace_target}（目標 IP {trace_target}） 【方法】tracert 路由躍遷追蹤（-h {max_hops} -w {timeout_ms}） 【結果】沿途公網節點均封鎖 ICMP 或逾時未回應"
                    if is_zh else
                    f"[Source] {parent_id or trace_target} (Target IP {trace_target}) [Method] tracert Route Hop Trace (-h {max_hops} -w {timeout_ms}) [Result] Intermediate public hops filtered ICMP or timed out"
                )
                f_node = PropositionNode(
                    prop_id=f_trace_id,
                    node_kind=PropositionKind.FACT.value,
                    rank=parent_rank + 1,
                    statement=stmt_f,
                    premises=parent_premises,
                    rule_name="RULE_ACTIVE_TRACEROUTE",
                    target_entity=trace_target,
                    entity_type="IP"
                )
                new_props.append(f_node)
                if parent_id:
                    new_edges.append((parent_id, f_trace_id))
                added_fact_ids.append(f_trace_id)

        elif module_name == "m7":
            ack_opsec = bool(params.get("ack_opsec", False) or params.get("acknowledge_risk", False))
            if not ack_opsec:
                raise ValueError("OPSEC authorization required (ack_opsec=True) to execute active callback probe.")
            from ariadns.modules.m7_manual_oob import trigger_manual_oob
            target_url = params.get("target_url") or f"http://{target}/"
            callback_url = params.get("callback_url") or "http://127.0.0.1:8080/oob-canary"
            oob_res = trigger_manual_oob(
                target_endpoint_url=target_url,
                callback_url=callback_url,
                acknowledge_opsec_risk=True,
                timeout_seconds=3.0,
            )
            f_oob_id = "F_OOB"
            status_code = oob_res.get("target_status_code", "TIMEOUT")
            parent_p = next((p for p in existing_props if p.prop_id == "F1"), None)
            if not parent_p and existing_props:
                parent_p = existing_props[0]
            parent_id = parent_p.prop_id if parent_p else None
            parent_rank = parent_p.rank if parent_p else 0

            stmt_oob = (
                f"【依據】{parent_id or target_url}（調查端點 {target_url}） 【方法】主動 Out-Of-Band 回連探測 【結果】已發送驗證請求（HTTP 狀態: {status_code}）"
                if is_zh else
                f"[Source] {parent_id or target_url} (Target Endpoint {target_url}) [Method] Active Out-Of-Band Probe [Result] Verification probe delivered (HTTP Status: {status_code})"
            )
            f_node = PropositionNode(
                prop_id=f_oob_id,
                node_kind=PropositionKind.FACT.value,
                rank=parent_rank + 1,
                statement=stmt_oob,
                premises=[parent_id] if parent_id else [],
                rule_name="RULE_ACTIVE_OOB_PROBE",
                target_entity=target,
                entity_type="IP" if is_ip_target else "DOMAIN_L1"
            )
            new_props.append(f_node)
            if parent_id:
                new_edges.append((parent_id, f_oob_id))
            added_fact_ids.append(f_oob_id)

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
