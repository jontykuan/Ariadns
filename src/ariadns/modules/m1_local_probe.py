"""Module 1: Local Active Prober (DNS, RDAP, HTTP Banner, TLS, Ports)."""

import re
import socket
import ssl
from typing import Any
import dns.resolver
import httpx
from ariadns.models.config import AppConfig
from ariadns.models.entities import IdentityProfile, Infrastructure
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.asn_cdn import detect_cdn
from ariadns.utils.rate_limiter import HttpClient
from ariadns.utils.tool_runner import run_command_safely

VERIFICATION_PATTERNS = {
    "google": re.compile(r"google-site-verification=[A-Za-z0-9_-]+"),
    "facebook": re.compile(r"facebook-domain-verification=[A-Za-z0-9_-]+"),
    "ms": re.compile(r"MS=ms[0-9]+"),
    "atlassian": re.compile(r"atlassian-domain-verification=[A-Za-z0-9+/=_-]+"),
}

def parse_soa_rname(rname: str) -> str:
    r"""Convert SOA RNAME (e.g., admin.example.com. or first\.last.example.com.) to email."""
    cleaned = rname.strip().rstrip(".")
    sentinel = "___ESCAPED_DOT___"
    masked = cleaned.replace(r"\.", sentinel)
    if "." in masked:
        parts = masked.split(".", 1)
        local_part = parts[0].replace(sentinel, ".")
        domain_part = parts[1].replace(sentinel, ".")
        return f"{local_part}@{domain_part}"
    return masked.replace(sentinel, ".")

def grab_http_banner(domain: str, ip: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    """Send standard HEAD / HTTP/1.1 request carrying Host header and extract Server, X-Powered-By, Set-Cookie."""
    target_host = ip if ip else domain
    headers = {"Host": domain, "User-Agent": "Ariadns/1.0"}
    res = {"server": None, "x_powered_by": None, "set_cookie": None, "status_code": None}
    for proto in ["https", "http"]:
        url = f"{proto}://{target_host}/"
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:
                resp = client.head(url, headers=headers)
                res["status_code"] = resp.status_code
                res["server"] = resp.headers.get("server")
                res["x_powered_by"] = resp.headers.get("x-powered-by")
                res["set_cookie"] = resp.headers.get("set-cookie")
                return res
        except Exception:
            continue
    return res

def extract_tls_cert_details(domain: str, ip: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    """Connect to HTTPS 443 port and extract Common Name (CN) and Subject Alternative Names (SANs)."""
    target_host = ip if ip else domain
    result = {"cn": None, "sans": []}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target_host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # In CERT_NONE mode getpeercert() returns empty dict, retrieve in DER form
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        # Fallback simple string search for CN and SANs if cryptography is available
                        try:
                            import cryptography.x509 as x509
                            cert_obj = x509.load_der_x509_certificate(der_cert)
                            for attr in cert_obj.subject:
                                if attr.oid._name == "commonName":
                                    result["cn"] = str(attr.value)
                            try:
                                ext = cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                result["sans"] = [str(n.value) for n in ext.value]
                            except Exception:
                                pass
                        except Exception:
                            pass
                else:
                    subject = cert.get("subject", [])
                    for sub in subject:
                        for key, val in sub:
                            if key == "commonName":
                                result["cn"] = val
                    sans = cert.get("subjectAltName", [])
                    result["sans"] = [val for key, val in sans if key == "DNS"]
    except Exception:
        pass
    return result

def scan_ports(ip: str, ports: list[int] | None = None, timeout: float = 2.0) -> list[int]:
    """Scan common service ports on non-CDN IP using socket fallback or nmap."""
    target_ports = ports or COMMON_SCAN_PORTS
    open_ports = []
    # Fast socket port scan
    for p in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((ip, p))
                if res == 0:
                    open_ports.append(p)
        except Exception:
            continue
    return open_ports
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

    def probe_infrastructure(self, domain: str, a_records: list[str], run_portscan: bool = False) -> Infrastructure:
        infra = Infrastructure()
        current_ip = a_records[0] if a_records else None
        infra.current_ip = current_ip
        if current_ip:
            is_cdn, provider, _ = detect_cdn(current_ip)
            infra.is_cdn = is_cdn
            infra.cdn_provider = provider

        banner = grab_http_banner(domain, current_ip, timeout=self.config.http_timeout_seconds)
        infra.server_banner = banner.get("server")

        if run_portscan and current_ip and not infra.is_cdn:
            infra.open_ports = scan_ports(current_ip, timeout=2.0)

        return infra
