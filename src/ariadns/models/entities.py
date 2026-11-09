from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from ariadns.models.enums import OriginVerificationStatus, ConfidenceLevel, NodeType, EdgeType, PropositionKind

@dataclass
class IdentityProfile:
    registrant_name: Optional[str] = None
    registrant_email: Optional[str] = None
    registrar_name: Optional[str] = None
    soa_admin_email: Optional[str] = None
    verification_tokens: dict[str, str] = field(default_factory=dict)
    html_tracking_tokens: dict[str, str] = field(default_factory=dict)

@dataclass
class Infrastructure:
    current_ip: Optional[str] = None
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    asn: Optional[str] = None
    asn_org_name: Optional[str] = None
    country: Optional[str] = None
    suspected_origin_ip: Optional[str] = None
    origin_verification_status: str = OriginVerificationStatus.UNVERIFIED.value
    server_banner: Optional[str] = None
    favicon_sha256: Optional[str] = None
    open_ports: list[int] = field(default_factory=list)

@dataclass
class SubdomainRecord:
    subdomain: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None

@dataclass
class PivotResult:
    same_origin_domains: list[str] = field(default_factory=list)
    same_mx_domains: list[str] = field(default_factory=list)
    same_token_domains: list[str] = field(default_factory=list)

@dataclass
class L2Result:
    domain: str
    relation_type: str
    resolved_ip: Optional[str] = None
    registrant_email: Optional[str] = None
    registrar_name: Optional[str] = None
    asn_org_name: Optional[str] = None
    confidence: str = ConfidenceLevel.LOW.value

@dataclass
class DataCustodian:
    custodian_name: str
    custodian_role: str
    queryable_node: str
    queryable_records: list[str] = field(default_factory=list)

@dataclass
class PropositionNode:
    prop_id: str
    node_kind: str
    rank: int
    statement: str
    premises: list[str] = field(default_factory=list)
    rule_name: str = "DIRECT_OBSERVATION"
    target_entity: str = ""
    entity_type: str = ""
    custodians: list[DataCustodian] = field(default_factory=list)

@dataclass
class InvestigationResult:
    target_domain: str
    investigation_timestamp: str
    identity_profile: IdentityProfile = field(default_factory=IdentityProfile)
    infrastructure: Infrastructure = field(default_factory=Infrastructure)
    subdomains: list[SubdomainRecord] = field(default_factory=list)
    pivots: PivotResult = field(default_factory=PivotResult)
    l2_recursive_results: list[L2Result] = field(default_factory=list)
    evidence_chain: list[PropositionNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
