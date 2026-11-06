"""Module 3: Passive OSINT & Origin Detection (pDNS, CDN check, Host Header validation)."""

import hashlib
from typing import Any
import httpx
from ariadns.models.config import AppConfig
from ariadns.models.enums import OriginVerificationStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.asn_cdn import detect_cdn
from ariadns.utils.rate_limiter import HttpClient

class OriginDetector:
    def __init__(self, db: DatabaseManager, http_client: HttpClient, config: AppConfig):
        self.db = db
        self.http_client = http_client
        self.config = config

    def query_pdns_history(self, domain: str) -> list[str]:
        cached = self.db.get_dns_cache(domain, "PDNS_HISTORY")
        if cached is not None:
            return cached.get("ips", [])

        candidate_ips: set[str] = set()

        # 1. VirusTotal API v3
        vt_key = self.config.api_keys.get("virustotal")
        if vt_key:
            headers = {"x-apikey": vt_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/historical_dns"
            resp, status = self.http_client.fetch_with_backoff(
                url,
                provider="virustotal",
                headers=headers
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for item in data.get("data", []):
                        attrs = item.get("attributes", {})
                        if attrs.get("type") == "A":
                            val = attrs.get("value")
                            if val:
                                candidate_ips.add(val)
                except Exception:
                    pass

        # 2. AlienVault OTX API
        otx_key = self.config.api_keys.get("alienvault_otx")
        otx_headers = {"X-OTX-API-KEY": otx_key} if otx_key else {}
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp_otx, _ = self.http_client.fetch_with_backoff(otx_url, provider="alienvault_otx", headers=otx_headers)
        if resp_otx and resp_otx.status_code == 200:
            try:
                data = resp_otx.json()
                for record in data.get("passive_dns", []):
                    if record.get("record_type") == "A":
                        address = record.get("address")
                        if address:
                            candidate_ips.add(address)
            except Exception:
                pass

        ip_list = sorted(list(candidate_ips))
        self.db.set_dns_cache(domain, "PDNS_HISTORY", {"ips": ip_list}, ttl_seconds=self.config.cache_ttl_seconds)
        return ip_list

    def verify_candidate_origin(self, domain: str, candidate_ip: str, reference_title: str | None = None) -> bool:
        """Verify candidate IP via Host Header collision & title/banner matching."""
        is_cdn, _, _ = detect_cdn(candidate_ip)
        if is_cdn:
            return False

        headers = {"Host": domain, "User-Agent": "Ariadns/1.0"}
        for proto in ["https", "http"]:
            try:
                with httpx.Client(timeout=self.config.http_timeout_seconds, verify=False, follow_redirects=True) as client:
                    resp = client.get(f"{proto}://{candidate_ip}/", headers=headers)
                    if resp.status_code == 200:
                        body = resp.text
                        cand_title = None
                        if "<title>" in body and "</title>" in body:
                            cand_title = body.split("<title>")[1].split("</title>")[0].strip()
                        
                        # Match reference title if available
                        if reference_title and cand_title and reference_title.lower() == cand_title.lower():
                            return True
                        # If status 200 returned on matching Host header, consider suspected/confirmed
                        if resp.status_code == 200 and cand_title:
                            return True
            except Exception:
                continue
        return False

    def detect_origin(self, domain: str, current_ip: str | None, live_title: str | None = None) -> tuple[str | None, str]:
        if not current_ip:
            return None, OriginVerificationStatus.NOT_APPLICABLE.value

        is_cdn, _, _ = detect_cdn(current_ip)
        if not is_cdn:
            return current_ip, OriginVerificationStatus.CONFIRMED.value

        candidate_ips = self.query_pdns_history(domain)
        for cand in candidate_ips:
            if cand == current_ip:
                continue
            is_cand_cdn, _, _ = detect_cdn(cand)
            if is_cand_cdn:
                continue
            if self.verify_candidate_origin(domain, cand, reference_title=live_title):
                return cand, OriginVerificationStatus.CONFIRMED.value
            return cand, OriginVerificationStatus.SUSPECTED.value

        return None, OriginVerificationStatus.UNVERIFIED.value
