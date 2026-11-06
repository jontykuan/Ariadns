from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from ariadns.models.enums import OriginVerificationStatus, ConfidenceLevel, NodeType, EdgeType

@dataclass
class IdentityProfile:
    registrant_name: Optional[str] = None
    registrant_email: Optional[str] = None
    soa_admin_email: Optional[str] = None
    verification_tokens: dict[str, str] = field(default_factory=dict)

@dataclass
class Infrastructure:
    current_ip: Optional[str] = None
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    suspected_origin_ip: Optional[str] = None
    origin_verification_status: str = OriginVerificationStatus.UNVERIFIED.value
    server_banner: Optional[str] = None
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
    confidence: str = ConfidenceLevel.LOW.value

@dataclass
class InvestigationResult:
    target_domain: str
    investigation_timestamp: str
    identity_profile: IdentityProfile = field(default_factory=IdentityProfile)
    infrastructure: Infrastructure = field(default_factory=Infrastructure)
    subdomains: list[SubdomainRecord] = field(default_factory=list)
    pivots: PivotResult = field(default_factory=PivotResult)
    l2_recursive_results: list[L2Result] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
