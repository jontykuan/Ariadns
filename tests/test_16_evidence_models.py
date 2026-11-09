from ariadns.models.enums import PropositionKind, OriginVerificationStatus
from ariadns.models.entities import (
    IdentityProfile,
    Infrastructure,
    DataCustodian,
    PropositionNode,
    InvestigationResult,
)

def test_evidence_models_serialization():
    custodian = DataCustodian(
        custodian_name="Google LLC",
        custodian_role="Platform Authority",
        queryable_node="TOKEN:G-12345678",
        queryable_records=["Google Analytics Account UID", "Login IP History"]
    )
    fact = PropositionNode(
        prop_id="F1",
        node_kind=PropositionKind.FACT.value,
        rank=0,
        statement="Domain has HTML tracking token G-12345678",
        premises=[],
        rule_name="DIRECT_OBSERVATION",
        target_entity="G-12345678",
        entity_type="TOKEN",
        custodians=[custodian]
    )
    conclusion = PropositionNode(
        prop_id="C1",
        node_kind=PropositionKind.CONCLUSION.value,
        rank=1,
        statement="Domain shares tracking ID G-12345678 with developer asset",
        premises=["F1"],
        rule_name="RULE_PIVOT_CORRELATION",
        target_entity="G-12345678",
        entity_type="TOKEN",
        custodians=[custodian]
    )

    inv = InvestigationResult(
        target_domain="example.com",
        investigation_timestamp="2026-11-09T08:00:00Z",
        identity_profile=IdentityProfile(
            registrar_name="Namecheap, Inc.",
            html_tracking_tokens={"ga4": "G-12345678"}
        ),
        infrastructure=Infrastructure(
            current_ip="198.51.100.24",
            asn="AS14061",
            asn_org_name="DigitalOcean, LLC",
            country="US",
            favicon_sha256="abc123sha"
        ),
        evidence_chain=[fact, conclusion]
    )

    d = inv.to_dict()
    assert d["identity_profile"]["registrar_name"] == "Namecheap, Inc."
    assert d["identity_profile"]["html_tracking_tokens"]["ga4"] == "G-12345678"
    assert d["infrastructure"]["asn_org_name"] == "DigitalOcean, LLC"
    assert d["infrastructure"]["favicon_sha256"] == "abc123sha"
    assert len(d["evidence_chain"]) == 2
    assert d["evidence_chain"][1]["node_kind"] == "CONCLUSION"
    assert d["evidence_chain"][1]["premises"] == ["F1"]
    assert d["evidence_chain"][1]["custodians"][0]["custodian_name"] == "Google LLC"
