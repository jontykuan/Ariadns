"""Module 5: Filter, Graph Orchestrator & L1->L2 Recursion Controller."""

import datetime
from typing import Any
from ariadns.models.config import AppConfig
from ariadns.models.entities import (
    IdentityProfile,
    Infrastructure,
    InvestigationResult,
    L2Result,
    PivotResult,
    SubdomainRecord,
)
from ariadns.models.enums import (
    ConfidenceLevel,
    EdgeType,
    ModuleStatus,
    NodeType,
    OriginVerificationStatus,
)
from ariadns.modules.m1_local_probe import LocalDnsResolver
from ariadns.modules.m2_subdomain import SubdomainEnumerator
from ariadns.modules.m3_origin import OriginDetector
from ariadns.modules.m4_pivoting import PivotingEngine
from ariadns.storage.db import DatabaseManager
from ariadns.storage.graph_store import PropertyGraphStore
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

class Orchestrator:
    def __init__(self, config: AppConfig | None = None, db: DatabaseManager | None = None):
        self.config = config or AppConfig.load()
        self.db = db or DatabaseManager(self.config.db_path)
        self.rate_limiter = RateLimiter(self.db, self.config)
        self.http_client = HttpClient(self.rate_limiter, self.config)

        self.m1 = LocalDnsResolver(self.db, self.http_client, self.config)
        self.m2 = SubdomainEnumerator(self.db, self.http_client, self.config)
        self.m3 = OriginDetector(self.db, self.http_client, self.config)
        self.m4 = PivotingEngine(self.db, self.http_client, self.config)

    def run_investigation(self, domain: str, depth: int = 1, run_portscan: bool = False) -> InvestigationResult:
        domain = domain.lower().strip()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        graph_store = PropertyGraphStore(self.db, session_id=domain)

        l1_node_id = graph_store.add_node(NodeType.DOMAIN_L1.value, domain)

        # 1. Module 1: DNS & Identity & Banner
        dns_records = self.m1.resolve_records(domain)
        identity = self.m1.get_identity_profile(domain, dns_records)
        infra = self.m1.probe_infrastructure(domain, dns_records.get("A", []), run_portscan=run_portscan)

        # Populate graph nodes & edges
        for ip in dns_records.get("A", []):
            ip_id = graph_store.add_node(NodeType.IP.value, ip)
            graph_store.add_edge(l1_node_id, ip_id, EdgeType.RESOLVES_TO.value)

        for mx_entry in dns_records.get("MX", []):
            parts = mx_entry.split()
            mx_host = parts[1] if len(parts) > 1 else parts[0]
            mx_id = graph_store.add_node(NodeType.MX.value, mx_host)
            graph_store.add_edge(l1_node_id, mx_id, EdgeType.USES_MX.value)

        for ns_host in dns_records.get("NS", []):
            ns_id = graph_store.add_node(NodeType.NS.value, ns_host.rstrip("."))
            graph_store.add_edge(l1_node_id, ns_id, EdgeType.USES_NS.value)

        for token_provider, token_val in identity.verification_tokens.items():
            tok_id = graph_store.add_node(NodeType.TOKEN.value, token_val, label=f"{token_provider}:{token_val}")
            graph_store.add_edge(l1_node_id, tok_id, EdgeType.HAS_TOKEN.value)

        if identity.soa_admin_email:
            em_id = graph_store.add_node(NodeType.EMAIL.value, identity.soa_admin_email)
            graph_store.add_edge(l1_node_id, em_id, EdgeType.REGISTERED_BY.value)

        # 2. Module 2: Subdomains
        subdomains = self.m2.run(domain)
        for s in subdomains:
            sub_id = graph_store.add_node(NodeType.SUBDOMAIN.value, s.subdomain)
            graph_store.add_edge(l1_node_id, sub_id, EdgeType.HAS_SUBDOMAIN.value)
            if s.ip:
                sub_ip_id = graph_store.add_node(NodeType.IP.value, s.ip)
                graph_store.add_edge(sub_id, sub_ip_id, EdgeType.RESOLVES_TO.value)

        # 3. Module 3: Origin Detection
        current_ip = infra.current_ip
        suspected_origin, origin_status = self.m3.detect_origin(domain, current_ip)
        infra.suspected_origin_ip = suspected_origin
        infra.origin_verification_status = origin_status

        target_pivot_ip = suspected_origin if (suspected_origin and origin_status == OriginVerificationStatus.CONFIRMED.value) else current_ip

        # 4. Module 4: Pivoting
        pivot_result = PivotResult()
        discovered_l2_domains: set[str] = set()

        if target_pivot_ip and not infra.is_cdn:
            # Check circuit breaker
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

            l2_results.append(l2_item)

        result = InvestigationResult(
            target_domain=domain,
            investigation_timestamp=timestamp,
            identity_profile=identity,
            infrastructure=infra,
            subdomains=subdomains,
            pivots=pivot_result,
            l2_recursive_results=l2_results,
        )

        return result
