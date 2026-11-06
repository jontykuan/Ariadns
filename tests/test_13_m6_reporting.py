import json
from ariadns.models.entities import (
    IdentityProfile,
    Infrastructure,
    InvestigationResult,
    L2Result,
    SubdomainRecord,
)
from ariadns.modules.m6_reporting import ReportingEngine

def test_reporting_engine_exports(tmp_path):
    engine = ReportingEngine(output_dir=tmp_path)
    res = InvestigationResult(
        target_domain="example.com",
        investigation_timestamp="2026-11-06T16:04:00Z",
        identity_profile=IdentityProfile(soa_admin_email="admin@example.com"),
        infrastructure=Infrastructure(current_ip="93.184.216.34", is_cdn=False),
        subdomains=[SubdomainRecord(subdomain="api.example.com", ip="93.184.216.34", status_code=200)],
        l2_recursive_results=[L2Result(domain="example.org", relation_type="Same Origin IP", confidence="HIGH")]
    )

    paths = engine.export_all(res)
    assert paths["result_json"].exists()
    assert paths["topology_json"].exists()
    assert paths["report_md"].exists()

    with open(paths["result_json"], "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["target_domain"] == "example.com"
        assert len(data["subdomains"]) == 1

    content = paths["report_md"].read_text(encoding="utf-8")
    assert "Ariadns OSINT Investigation Report: example.com" in content
    assert "**HIGH**" in content
