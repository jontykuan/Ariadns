"""Chained Propositional Evidence DAG Engine & Data Custodian Mapper."""

from typing import Any, Optional
import networkx as nx
from ariadns.models.entities import DataCustodian, PropositionNode
from ariadns.models.enums import PropositionKind

class EvidenceChainDAG:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.propositions: dict[str, PropositionNode] = {}
        self.graph = nx.DiGraph()

    def add_proposition(
        self,
        prop_id: str,
        node_kind: str,
        statement: str,
        premises: list[str] | None = None,
        rule_name: str = "DIRECT_OBSERVATION",
        target_entity: str = "",
        entity_type: str = "",
        custodians: list[DataCustodian] | None = None,
    ) -> PropositionNode:
        prems = premises or []
        # Calculate Rank
        if not prems:
            rank = 0
        else:
            rank = 1 + max(self.propositions[p].rank for p in prems if p in self.propositions)

        node = PropositionNode(
            prop_id=prop_id,
            node_kind=node_kind,
            rank=rank,
            statement=statement,
            premises=prems,
            rule_name=rule_name,
            target_entity=target_entity,
            entity_type=entity_type,
            custodians=custodians or [],
        )

        self.propositions[prop_id] = node
        self.graph.add_node(
            prop_id,
            node_kind=node_kind,
            rank=rank,
            statement=statement,
            target_entity=target_entity,
            entity_type=entity_type,
        )

        for p in prems:
            self.graph.add_edge(p, prop_id)

        # Enforce DAG property (cycle check)
        if not nx.is_directed_acyclic_graph(self.graph):
            self.graph.remove_node(prop_id)
            del self.propositions[prop_id]
            raise ValueError(f"Cycle detected! Proposition {prop_id} invalidates DAG.")

        return node

    def is_valid_dag(self) -> bool:
        return nx.is_directed_acyclic_graph(self.graph)

    def get_ordered_propositions(self) -> list[PropositionNode]:
        """Return propositions sorted by rank and ID."""
        return sorted(self.propositions.values(), key=lambda p: (p.rank, p.prop_id))

    def generate_mermaid_flowchart(self) -> str:
        """Generate layered flowchart TD showing Rank 0 Facts -> Rank 1..N Conclusions -> Custodians."""
        lines = ["flowchart TD"]
        ranks: dict[int, list[PropositionNode]] = {}
        for p in self.get_ordered_propositions():
            ranks.setdefault(p.rank, []).append(p)

        for r in sorted(ranks.keys()):
            sub_title = f"Rank {r}: {'Base Facts (觀測事實)' if r == 0 else f'Order {r} Conclusions (推論結論)'}"
            lines.append(f'    subgraph Rank_{r} ["{sub_title}"]')
            for p in ranks[r]:
                kind_badge = "FACT" if p.node_kind == PropositionKind.FACT.value else "CONCLUSION"
                safe_stmt = p.statement.replace('"', "'")
                lines.append(f'        {p.prop_id}["[{kind_badge} {p.prop_id}] {safe_stmt}"]')
            lines.append("    end")

        # Add edges between propositions
        for u, v in self.graph.edges():
            lines.append(f"    {u} --> {v}")

        # Add Data Custodian subgraphs & links
        custodian_nodes: dict[str, str] = {}
        has_custodians = False
        for p in self.get_ordered_propositions():
            for idx, c in enumerate(p.custodians):
                has_custodians = True
                c_key = f"DC_{p.prop_id}_{idx}"
                custodian_nodes[c_key] = f'可查節點: {c.queryable_node}<br/>管理源: {c.custodian_name} ({c.custodian_role})'

        if has_custodians:
            lines.append('    subgraph Custodians ["Queryable Nodes & Data Custodians (資料管理源)"]')
            for c_key, c_label in custodian_nodes.items():
                lines.append(f'        {c_key}["{c_label}"]')
            lines.append("    end")

            for p in self.get_ordered_propositions():
                for idx, c in enumerate(p.custodians):
                    c_key = f"DC_{p.prop_id}_{idx}"
                    lines.append(f"    {p.prop_id} -.-> {c_key}")

        return "\n".join(lines)

def map_custodians_for_node(
    entity_type: str,
    target_entity: str,
    meta: dict[str, Any] | None = None
) -> list[DataCustodian]:
    """Map a conclusion target entity to its deterministic Data Custodians and queryable records."""
    meta = meta or {}
    custodians: list[DataCustodian] = []

    if entity_type in ("DOMAIN_L1", "DOMAIN_L2"):
        registrar = meta.get("registrar_name") or "Domain Registrar (Unknown)"
        custodians.append(DataCustodian(
            custodian_name=registrar,
            custodian_role="Domain Registrar / Registry",
            queryable_node=f"{entity_type}:{target_entity}",
            queryable_records=[
                "Registrant KYC & Identity Documents",
                "Domain Registration & Renewal Payment Records (Credit Card / PayPal / Crypto)",
                "DNS Record Modification Audit Log & Source Login IPs"
            ]
        ))
        ns_hosts = meta.get("ns_hosts", [])
        if ns_hosts:
            custodians.append(DataCustodian(
                custodian_name=", ".join(ns_hosts[:2]),
                custodian_role="DNS Nameserver Host",
                queryable_node=f"NS:{target_entity}",
                queryable_records=["Zone File Configuration History", "DNS Management Account Credentials & Login IPs"]
            ))

    elif entity_type == "IP":
        is_cdn = meta.get("is_cdn", False)
        asn_org = meta.get("asn_org_name") or meta.get("asn") or "Hosting / ISP Operator"
        if is_cdn:
            provider = meta.get("cdn_provider") or asn_org
            custodians.append(DataCustodian(
                custodian_name=provider,
                custodian_role="CDN / Reverse Proxy Provider",
                queryable_node=f"CDN_IP:{target_entity}",
                queryable_records=[
                    "Configured Origin IP Address (Backend Forwarding Target)",
                    "Account Registration Email & Billing / Cardholder Records",
                    "Tunnel / Proxy Configuration Audit Logs & Access IPs"
                ]
            ))
        else:
            custodians.append(DataCustodian(
                custodian_name=asn_org,
                custodian_role="Host / Server Infrastructure Provider",
                queryable_node=f"ORIGIN_IP:{target_entity}",
                queryable_records=[
                    "VPS / Dedicated Server Subscriber KYC & Identity Records",
                    "Billing & Payment Records (Cardholder, Invoice, Crypto TX)",
                    "Console, SSH, and Admin Access IP Logs with Timestamps"
                ]
            ))

    elif entity_type in ("TOKEN", "HTML_TOKEN"):
        lower_target = target_entity.lower()
        if "google" in lower_target or target_entity.startswith("G-") or target_entity.startswith("UA-") or target_entity.startswith("GTM-"):
            custodians.append(DataCustodian(
                custodian_name="Google LLC",
                custodian_role="Platform Authority (Google Search Console / Analytics / GTM)",
                queryable_node=f"TOKEN:{target_entity}",
                queryable_records=[
                    "Google Account UID Bound to Property / Tracking ID",
                    "Account Recovery Email & Verification Phone Number",
                    "Historical Login Timestamps & Source IP Addresses"
                ]
            ))
        elif "facebook" in lower_target or meta.get("token_type") == "fb_pixel":
            custodians.append(DataCustodian(
                custodian_name="Meta Platforms, Inc.",
                custodian_role="Platform Authority (Meta Business / Facebook Pixel)",
                queryable_node=f"TOKEN:{target_entity}",
                queryable_records=[
                    "Meta Business Manager / Facebook Ad Account ID",
                    "User Profile & Linked Payment / Credit Card Data",
                    "Account Creation & Management Login IPs"
                ]
            ))
        else:
            custodians.append(DataCustodian(
                custodian_name="Third-Party Verification Provider",
                custodian_role="SaaS / Identity Authority",
                queryable_node=f"TOKEN:{target_entity}",
                queryable_records=["Subscriber Account Information", "Verification Configuration Logs"]
            ))

    elif entity_type in ("EMAIL", "MX"):
        custodians.append(DataCustodian(
            custodian_name=meta.get("email_operator") or "Mail Server Operator / ISP",
            custodian_role="Mail Service Provider",
            queryable_node=f"{entity_type}:{target_entity}",
            queryable_records=[
                "Mailbox Account Holder Registration Info",
                "Account Recovery Phone Numbers / Alternate Emails",
                "SMTP / POP3 / IMAP / Webmail Login IP Access Logs"
            ]
        ))

    return custodians
