"""Module 1: Local Active Prober (DNS, RDAP, HTTP Banner, TLS, Ports)."""

import re
from typing import Any
import dns.resolver
from ariadns.models.config import AppConfig
from ariadns.models.entities import IdentityProfile
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient

VERIFICATION_PATTERNS = {
    "google": re.compile(r"google-site-verification=[A-Za-z0-9_-]+"),
    "facebook": re.compile(r"facebook-domain-verification=[A-Za-z0-9_-]+"),
    "ms": re.compile(r"MS=ms[0-9]+"),
    "atlassian": re.compile(r"atlassian-domain-verification=[A-Za-z0-9+/=_-]+"),
}

def parse_soa_rname(rname: str) -> str:
    r"""Convert SOA RNAME (e.g., admin.example.com. or first\.last.example.com.) to email."""
    cleaned = rname.strip().rstrip(".")
    # Replace escaped dot with sentinel
    sentinel = "___ESCAPED_DOT___"
    masked = cleaned.replace(r"\.", sentinel)
    if "." in masked:
        parts = masked.split(".", 1)
        local_part = parts[0].replace(sentinel, ".")
        domain_part = parts[1].replace(sentinel, ".")
        return f"{local_part}@{domain_part}"
    return masked.replace(sentinel, ".")

def extract_verification_tokens(txt_records: list[str]) -> dict[str, str]:
    tokens = {}
    for txt in txt_records:
        for provider, pattern in VERIFICATION_PATTERNS.items():
            match = pattern.search(txt)
            if match:
                tokens[provider] = match.group(0)
    return tokens

class LocalDnsResolver:
    def __init__(self, db: DatabaseManager, http_client: HttpClient, config: AppConfig):
        self.db = db
        self.http_client = http_client
        self.config = config

    def resolve_records(self, domain: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": None
        }
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.http_timeout_seconds
        resolver.lifetime = self.config.http_timeout_seconds

        for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
            cached = self.db.get_dns_cache(domain, rtype)
            if cached is not None:
                result[rtype] = cached.get("records")
                continue

            try:
                answers = resolver.resolve(domain, rtype)
                if rtype == "SOA":
                    for rdata in answers:
                        soa_data = {
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                        }
                        result["SOA"] = soa_data
                        self.db.set_dns_cache(domain, rtype, {"records": soa_data}, ttl_seconds=self.config.cache_ttl_seconds)
                        break
                elif rtype == "MX":
                    records = [f"{rdata.preference} {str(rdata.exchange).rstrip('.')}" for rdata in answers]
                    result[rtype] = records
                    self.db.set_dns_cache(domain, rtype, {"records": records}, ttl_seconds=self.config.cache_ttl_seconds)
                else:
                    records = [rdata.to_text().strip('"') for rdata in answers]
                    result[rtype] = records
                    self.db.set_dns_cache(domain, rtype, {"records": records}, ttl_seconds=self.config.cache_ttl_seconds)
            except Exception:
                result[rtype] = [] if rtype != "SOA" else None

        return result

    def get_identity_profile(self, domain: str, dns_records: dict[str, Any]) -> IdentityProfile:
        profile = IdentityProfile()
        soa = dns_records.get("SOA")
        if soa and isinstance(soa, dict) and "rname" in soa:
            profile.soa_admin_email = parse_soa_rname(soa["rname"])

        txt_records = dns_records.get("TXT") or []
        profile.verification_tokens = extract_verification_tokens(txt_records)

        # Query RDAP
        cached_rdap = self.db.get_dns_cache(domain, "RDAP")
        if cached_rdap is not None:
            profile.registrant_name = cached_rdap.get("name")
            profile.registrant_email = cached_rdap.get("email")
        else:
            resp, status = self.http_client.fetch_with_backoff(
                f"https://rdap.org/domain/{domain}",
                provider="rdap"
            )
            if resp and resp.status_code == 200:
                try:
                    rdap_data = resp.json()
                    # Extract entities
                    entities = rdap_data.get("entities", [])
                    for ent in entities:
                        for vcard in ent.get("vcardArray", [None, []])[1]:
                            if len(vcard) > 3:
                                if vcard[0] == "fn" and not profile.registrant_name:
                                    profile.registrant_name = vcard[3]
                                elif vcard[0] == "email" and not profile.registrant_email:
                                    profile.registrant_email = vcard[3]
                    self.db.set_dns_cache(domain, "RDAP", {
                        "name": profile.registrant_name,
                        "email": profile.registrant_email,
                    }, ttl_seconds=self.config.cache_ttl_seconds)
                except Exception:
                    pass

        return profile
