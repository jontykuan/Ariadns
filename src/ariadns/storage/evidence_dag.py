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
    lang = meta.get("lang", "en")
    is_zh = (lang == "zh")
    custodians: list[DataCustodian] = []

    if entity_type in ("DOMAIN_L1", "DOMAIN_L2"):
        registrar = meta.get("registrar_name") or ("未知網域註冊商" if is_zh else "Domain Registrar (Unknown)")
        custodians.append(DataCustodian(
            custodian_name=registrar,
            custodian_role="網域註冊商 / 註冊局" if is_zh else "Domain Registrar / Registry",
            queryable_node=f"{entity_type}:{target_entity}",
            queryable_records=[
                "網域申請人實名 KYC 與身分證明文件",
                "網域註冊與續約付款紀錄（信用卡 / PayPal / 虛擬貨幣）",
                "DNS 解析紀錄異動稽核日誌與管理後台登入來源 IP"
            ] if is_zh else [
                "Registrant KYC & Identity Documents",
                "Domain Registration & Renewal Payment Records (Credit Card / PayPal / Crypto)",
                "DNS Record Modification Audit Log & Source Login IPs"
            ]
        ))
        ns_hosts = meta.get("ns_hosts", [])
        if ns_hosts:
            custodians.append(DataCustodian(
                custodian_name=", ".join(ns_hosts[:2]),
                custodian_role="權威 DNS 託管服務商" if is_zh else "DNS Nameserver Host",
                queryable_node=f"NS:{target_entity}",
                queryable_records=["Zone File 解析設定歷史紀錄", "DNS 管理帳號憑證與登入來源 IP"] if is_zh else ["Zone File Configuration History", "DNS Management Account Credentials & Login IPs"]
            ))

    elif entity_type == "IP":
        is_cdn = meta.get("is_cdn", False)
        asn_org = meta.get("asn_org_name") or meta.get("asn") or ("網路電信商 / 雲端主機商" if is_zh else "Hosting / ISP Operator")
        if is_cdn:
            provider = meta.get("cdn_provider") or asn_org
            custodians.append(DataCustodian(
                custodian_name=provider,
                custodian_role="CDN / 反向代理服務商" if is_zh else "CDN / Reverse Proxy Provider",
                queryable_node=f"CDN_IP:{target_entity}",
                queryable_records=[
                    "後端真實來源主機 IP 設定（Origin Forwarding Target）",
                    "帳號註冊信箱與帳務付款紀錄",
                    "代理通道設定異動日誌與管理端存取 IP"
                ] if is_zh else [
                    "Configured Origin IP Address (Backend Forwarding Target)",
                    "Account Registration Email & Billing / Cardholder Records",
                    "Tunnel / Proxy Configuration Audit Logs & Access IPs"
                ]
            ))
        else:
            custodians.append(DataCustodian(
                custodian_name=asn_org,
                custodian_role="主機機房 / 電信網路服務商 (ISP / Hosting)" if is_zh else "Host / Server Infrastructure Provider",
                queryable_node=f"ORIGIN_IP:{target_entity}",
                queryable_records=[
                    "VPS / 實體主機或固網 IP 承租人實名 KYC 與聯絡資料",
                    "帳務與付款金流紀錄（持卡人、發票、虛擬貨幣交易雜湊）",
                    "機房控制面板、SSH 與遠端管理登入來源 IP 及時間戳記"
                ] if is_zh else [
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
                custodian_role="第三方平台驗證機構 (Google Search Console / Analytics)" if is_zh else "Platform Authority (Google Search Console / Analytics / GTM)",
                queryable_node=f"TOKEN:{target_entity}",
                queryable_records=[
                    "綁定該驗證碼或追蹤碼之 Google 帳號 UID",
                    "帳號備援信箱與驗證電話號碼",
                    "歷史登入時間戳記與來源 IP 位址"
                ] if is_zh else [
                    "Google Account UID Bound to Property / Tracking ID",
                    "Account Recovery Email & Verification Phone Number",
                    "Historical Login Timestamps & Source IP Addresses"
                ]
            ))
        elif "facebook" in lower_target or meta.get("token_type") == "fb_pixel":
            custodians.append(DataCustodian(
                custodian_name="Meta Platforms, Inc.",
                custodian_role="第三方平台驗證機構 (Meta 企業管理平台 / Pixel)" if is_zh else "Platform Authority (Meta Business / Facebook Pixel)",
                queryable_node=f"TOKEN:{target_entity}",
                queryable_records=[
                    "Meta 企業管理平台或廣告帳號 ID",
                    "管理員個人檔案與綁定之信用卡付款資料",
                    "帳號建立與廣告投放管理登入 IP"
                ] if is_zh else [
                    "Meta Business Manager / Facebook Ad Account ID",
                    "User Profile & Linked Payment / Credit Card Data",
                    "Account Creation & Management Login IPs"
                ]
            ))
        else:
            custodians.append(DataCustodian(
                custodian_name="第三方平台服務商" if is_zh else "Third-Party Verification Provider",
                custodian_role="SaaS / 身分驗證機構" if is_zh else "SaaS / Identity Authority",
                queryable_node=f"TOKEN:{target_entity}",
                queryable_records=["用戶帳號註冊資訊", "驗證設定存取日誌"] if is_zh else ["Subscriber Account Information", "Verification Configuration Logs"]
            ))

    elif entity_type in ("EMAIL", "MX"):
        custodians.append(DataCustodian(
            custodian_name=meta.get("email_operator") or ("郵件伺服器營運商 / ISP" if is_zh else "Mail Server Operator / ISP"),
            custodian_role="電子郵件服務商" if is_zh else "Mail Service Provider",
            queryable_node=f"{entity_type}:{target_entity}",
            queryable_records=[
                "信箱申請人註冊身分資料",
                "帳號備援電話號碼與備用信箱",
                "SMTP / IMAP / Webmail 登入來源 IP 存取紀錄"
            ] if is_zh else [
                "Mailbox Account Holder Registration Info",
                "Account Recovery Phone Numbers / Alternate Emails",
                "SMTP / POP3 / IMAP / Webmail Login IP Access Logs"
            ]
        ))

    return custodians
