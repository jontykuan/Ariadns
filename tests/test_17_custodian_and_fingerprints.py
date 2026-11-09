from unittest.mock import MagicMock
from ariadns.models.config import AppConfig
from ariadns.modules.m1_local_probe import (
    LocalDnsResolver,
    extract_html_tracking_tokens,
)
from ariadns.modules.m3_origin import OriginDetector
from ariadns.storage.db import DatabaseManager
from ariadns.utils.asn_cdn import resolve_ip_asn_details
from ariadns.utils.rate_limiter import HttpClient, RateLimiter

def test_extract_html_tracking_tokens():
    html = """
    <html>
      <head>
        <script>gtag('config', 'G-ABC1234567');</script>
        <script>dataLayer.push({'gtm.start': new Date().getTime(),event:'gtm.js'});</script>
        <noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XYZ987"></iframe></noscript>
        <script>fbq('init', '1234567890123'); fbq('track', 'PageView');</script>
      </head>
      <body>Hello</body>
    </html>
    """
    tokens = extract_html_tracking_tokens(html)
    assert tokens["ga4"] == "G-ABC1234567"
    assert tokens["gtm"] == "GTM-XYZ987"
    assert tokens["fb_pixel"] == "1234567890123"

def test_rdap_registrar_extraction(tmp_path):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    resolver = LocalDnsResolver(db, client, cfg)

    # Mock RDAP JSON response with registrar role
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Namecheap, Inc."]]]
            },
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Privacy Protection"],
                    ["email", {}, "text", "privacy@withheld.com"]
                ]]
            }
        ]
    }
    client.fetch_with_backoff = MagicMock(return_value=(mock_resp, "OK"))

    id_profile = resolver.get_identity_profile("example.com", {})
    assert id_profile.registrar_name == "Namecheap, Inc."
    assert id_profile.registrant_name == "Privacy Protection"
    assert id_profile.registrant_email == "privacy@withheld.com"

def test_origin_favicon_match(tmp_path, monkeypatch):
    db = DatabaseManager(tmp_path / "test.db")
    cfg = AppConfig()
    limiter = RateLimiter(db, cfg)
    client = HttpClient(limiter, cfg)
    detector = OriginDetector(db, client, cfg)

    # Mock candidate origin verification where favicon matches
    monkeypatch.setattr(detector, "verify_candidate_origin", lambda d, ip, **kw: kw.get("reference_favicon_sha256") == "matched_hash")

    ip, status = detector.detect_origin(
        "example.com",
        "104.21.23.45", # Cloudflare
        live_favicon_sha256="matched_hash"
    )
    # With historical pDNS returning candidate
    db.set_dns_cache("example.com", "PDNS_HISTORY", {"ips": ["198.51.100.24"]})
    ip, status = detector.detect_origin(
        "example.com",
        "104.21.23.45",
        live_favicon_sha256="matched_hash"
    )
    assert ip == "198.51.100.24"
    assert status == "CONFIRMED"
