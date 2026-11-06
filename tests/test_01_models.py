from ariadns.models.enums import OriginVerificationStatus, ConfidenceLevel, ModuleStatus
from ariadns.models.entities import (
    IdentityProfile,
    Infrastructure,
    SubdomainRecord,
    PivotResult,
    L2Result,
    InvestigationResult,
)

def test_enums():
    assert OriginVerificationStatus.CONFIRMED.value == "CONFIRMED"
    assert ConfidenceLevel.HIGH.value == "HIGH"
    assert ModuleStatus.CACHED.value == "CACHED"

def test_investigation_result_to_dict():
    res = InvestigationResult(
        target_domain="example.com",
        investigation_timestamp="2026-11-06T16:04:00Z",
        identity_profile=IdentityProfile(
            registrant_name="Redacted",
            registrant_email="proxy@example.com",
            soa_admin_email="admin@example.com",
            verification_tokens={"google": "token123"},
        ),
        infrastructure=Infrastructure(
            current_ip="104.21.23.45",
            is_cdn=True,
            cdn_provider="Cloudflare",
            suspected_origin_ip="198.51.100.24",
            origin_verification_status="CONFIRMED",
            server_banner="nginx",
            open_ports=[80, 443],
        ),
        subdomains=[
            SubdomainRecord(
                subdomain="api.example.com",
                ip="198.51.100.24",
                status_code=200,
                server="nginx",
            )
        ],
        pivots=PivotResult(
            same_origin_domains=["test-example.org"],
            same_mx_domains=[],
            same_token_domains=[],
        ),
        l2_recursive_results=[
            L2Result(
                domain="test-example.org",
                relation_type="Same Origin IP",
                resolved_ip="198.51.100.24",
                confidence="HIGH",
            )
        ],
    )
    d = res.to_dict()
    assert d["target_domain"] == "example.com"
    assert d["infrastructure"]["is_cdn"] is True
    assert d["subdomains"][0]["subdomain"] == "api.example.com"
    assert d["l2_recursive_results"][0]["confidence"] == "HIGH"
