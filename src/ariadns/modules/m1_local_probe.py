"""Module 1: Local Active Prober (DNS, RDAP, HTTP Banner, TLS, Favicon, HTML Tokens, Ports)."""

import hashlib
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
from ariadns.utils.asn_cdn import detect_cdn, resolve_ip_asn_details
from ariadns.utils.rate_limiter import HttpClient
from ariadns.utils.tool_runner import run_command_safely

VERIFICATION_PATTERNS = {
    "google": re.compile(r"google-site-verification=[A-Za-z0-9_-]+"),
    "facebook": re.compile(r"facebook-domain-verification=[A-Za-z0-9_-]+"),
    "ms": re.compile(r"MS=ms[0-9]+"),
    "atlassian": re.compile(r"atlassian-domain-verification=[A-Za-z0-9+/=_-]+"),
}

HTML_TRACKING_PATTERNS = {
    "ga_ua": re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "ga4": re.compile(r"\bG-[A-Z0-9]{8,12}\b"),
    "gtm": re.compile(r"\bGTM-[A-Z0-9]{5,10}\b"),
    "fb_pixel": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"),
}

COMMON_SCAN_PORTS = [21, 22, 25, 80, 443, 3306, 8080, 8443]

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

def extract_verification_tokens(txt_records: list[str]) -> dict[str, str]:
    tokens = {}
    for txt in txt_records:
        for provider, pattern in VERIFICATION_PATTERNS.items():
            match = pattern.search(txt)
            if match:
                tokens[provider] = match.group(0)
    return tokens

def extract_html_tracking_tokens(html_content: str) -> dict[str, str]:
    tokens = {}
    if not html_content:
        return tokens
    for key, pattern in HTML_TRACKING_PATTERNS.items():
        match = pattern.search(html_content)
        if match:
            # If group 1 exists, use it; else full match
            tokens[key] = match.group(1) if match.lastindex else match.group(0)
    return tokens

def grab_http_banner_and_fingerprints(domain: str, ip: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    """Send HEAD and GET requests carrying Host header to extract Server, X-Powered-By, Favicon hash, and HTML tokens."""
    target_host = ip if ip else domain
    headers = {"Host": domain, "User-Agent": "Ariadns/1.0"}
    res: dict[str, Any] = {
        "server": None,
        "x_powered_by": None,
        "set_cookie": None,
        "status_code": None,
        "title": None,
        "favicon_sha256": None,
        "html_tracking_tokens": {},
    }

    # 1. Favicon hash extraction
    for proto in ["https", "http"]:
        fav_url = f"{proto}://{target_host}/favicon.ico"
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                fav_resp = client.get(fav_url, headers=headers)
                if fav_resp.status_code == 200 and len(fav_resp.content) > 10:
                    res["favicon_sha256"] = hashlib.sha256(fav_resp.content).hexdigest()
                    break
        except Exception:
            continue

    # 2. Main page probe
    for proto in ["https", "http"]:
        url = f"{proto}://{target_host}/"
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                resp = client.get(url, headers=headers)
                res["status_code"] = resp.status_code
                res["server"] = resp.headers.get("server")
                res["x_powered_by"] = resp.headers.get("x-powered-by")
                res["set_cookie"] = resp.headers.get("set-cookie")
                body = resp.text
                if "<title>" in body and "</title>" in body:
                    res["title"] = body.split("<title>")[1].split("</title>")[0].strip()
                res["html_tracking_tokens"] = extract_html_tracking_tokens(body)
                return res
        except Exception:
            continue
    return res

def grab_http_banner(domain: str, ip: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    return grab_http_banner_and_fingerprints(domain, ip, timeout)

def extract_tls_cert_details(domain: str, ip: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    target_host = ip if ip else domain
    result: dict[str, Any] = {"cn": None, "sans": []}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target_host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
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
    target_ports = ports or COMMON_SCAN_PORTS
    open_ports = []
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

        cached_rdap = self.db.get_dns_cache(domain, "RDAP")
        if cached_rdap is not None:
            profile.registrant_name = cached_rdap.get("name")
            profile.registrant_email = cached_rdap.get("email")
            profile.registrar_name = cached_rdap.get("registrar")
        else:
            resp, status = self.http_client.fetch_with_backoff(
                f"https://rdap.org/domain/{domain}",
                provider="rdap"
            )
            if resp and resp.status_code == 200:
                try:
                    rdap_data = resp.json()
                    entities = rdap_data.get("entities", [])
                    for ent in entities:
                        roles = ent.get("roles", [])
                        vcard_entries = ent.get("vcardArray", [None, []])[1]
                        fn_val = None
                        email_val = None
                        for v in vcard_entries:
                            if len(v) > 3:
                                if v[0] == "fn":
                                    fn_val = v[3]
                                elif v[0] == "email":
                                    email_val = v[3]

                        if "registrar" in roles and fn_val:
                            profile.registrar_name = fn_val
                        if ("registrant" in roles or not roles) and fn_val and not profile.registrant_name:
                            profile.registrant_name = fn_val
                        if email_val and not profile.registrant_email:
                            profile.registrant_email = email_val

                    self.db.set_dns_cache(domain, "RDAP", {
                        "name": profile.registrant_name,
                        "email": profile.registrant_email,
                        "registrar": profile.registrar_name,
                    }, ttl_seconds=self.config.cache_ttl_seconds)
                except Exception:
                    pass

        return profile

    def probe_infrastructure(self, domain: str, a_records: list[str], run_portscan: bool = False) -> Infrastructure:
        infra = Infrastructure()
        current_ip = a_records[0] if a_records else None
        infra.current_ip = current_ip
        if current_ip:
            is_cdn, provider, asn = detect_cdn(current_ip)
            infra.is_cdn = is_cdn
            infra.cdn_provider = provider
            asn_details = resolve_ip_asn_details(current_ip)
            infra.asn = asn_details.get("asn") or asn
            infra.asn_org_name = asn_details.get("asn_org_name")
            infra.country = asn_details.get("country")

        probe_res = grab_http_banner_and_fingerprints(domain, current_ip, timeout=self.config.http_timeout_seconds)
        infra.server_banner = probe_res.get("server")
        infra.favicon_sha256 = probe_res.get("favicon_sha256")

        if run_portscan and current_ip and not infra.is_cdn:
            infra.open_ports = scan_ports(current_ip, timeout=2.0)

        return infra
