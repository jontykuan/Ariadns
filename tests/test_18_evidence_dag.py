import pytest
from ariadns.models.enums import PropositionKind
from ariadns.storage.evidence_dag import EvidenceChainDAG, map_custodians_for_node

def test_evidence_dag_acyclic_and_ranks():
    dag = EvidenceChainDAG(session_id="example.com")

    # Base Facts (Rank 0)
    f1 = dag.add_proposition("F1", PropositionKind.FACT.value, "L1 resolves to IP 1.2.3.4")
    f2 = dag.add_proposition("F2", PropositionKind.FACT.value, "pDNS shows historical IP 5.6.7.8")
    assert f1.rank == 0
    assert f2.rank == 0

    # Conclusion 1 (Rank 1)
    c1 = dag.add_proposition(
        "C1",
        PropositionKind.CONCLUSION.value,
        "IP 5.6.7.8 confirmed as origin",
        premises=["F1", "F2"],
        rule_name="RULE_ORIGIN_CONFIRMATION",
        target_entity="5.6.7.8",
        entity_type="IP"
    )
    assert c1.rank == 1

    # Base Fact 3 (Rank 0)
    f3 = dag.add_proposition("F3", PropositionKind.FACT.value, "Reverse IP on 5.6.7.8 reveals domain2.com")
    assert f3.rank == 0

    # Conclusion 2 (Rank 2) derived from C1 and F3
    c2 = dag.add_proposition(
        "C2",
        PropositionKind.CONCLUSION.value,
        "domain2.com co-hosted on origin server",
        premises=["C1", "F3"],
        rule_name="RULE_PIVOT_CORRELATION",
        target_entity="domain2.com",
        entity_type="DOMAIN_L2"
    )
    assert c2.rank == 2
    assert dag.is_valid_dag() is True

    # Test Cycle Rejection
    with pytest.raises(ValueError, match="Cycle detected"):
        dag.add_proposition("C_BAD", PropositionKind.CONCLUSION.value, "Bad cycle", premises=["C2"])
        # Attempt to make F1 depend on C2
        dag.add_proposition("F1", PropositionKind.FACT.value, "Mutate", premises=["C2"])

def test_map_custodians():
    # Domain custodian
    d_cust = map_custodians_for_node("DOMAIN_L1", "example.com", {"registrar_name": "Namecheap, Inc."})
    assert len(d_cust) >= 1
    assert d_cust[0].custodian_name == "Namecheap, Inc."

    # Origin IP custodian
    ip_cust = map_custodians_for_node("IP", "5.6.7.8", {"is_cdn": False, "asn_org_name": "DigitalOcean, LLC"})
    assert len(ip_cust) == 1
    assert ip_cust[0].custodian_name == "DigitalOcean, LLC"

    # Token custodian
    tok_cust = map_custodians_for_node("TOKEN", "G-12345678")
    assert len(tok_cust) == 1
    assert tok_cust[0].custodian_name == "Google LLC"

def test_mermaid_generation():
    dag = EvidenceChainDAG(session_id="example.com")
    f1 = dag.add_proposition("F1", PropositionKind.FACT.value, "L1 resolves to IP 1.2.3.4")
    c1 = dag.add_proposition("C1", PropositionKind.CONCLUSION.value, "Conclusion 1", premises=["F1"])
    mermaid = dag.generate_mermaid_flowchart()
    assert "flowchart TD" in mermaid
    assert "F1 --> C1" in mermaid
