import ipaddress
import dns.resolver

CDN_ASN_MAP = {
    "AS13335": "Cloudflare",
    "AS209242": "Cloudflare",
    "AS16625": "Akamai",
    "AS20940": "Akamai",
    "AS32787": "Akamai",
    "AS54113": "Fastly",
    "AS16509": "Amazon CloudFront",
    "AS14618": "Amazon CloudFront",
    "AS19551": "Imperva",
    "AS15133": "Edgecast / Verizon",
}

# Major known CDN CIDR blocks
KNOWN_CDN_CIDRS = [
    ("104.16.0.0/13", "Cloudflare", "AS13335"),
    ("104.24.0.0/14", "Cloudflare", "AS13335"),
    ("172.64.0.0/13", "Cloudflare", "AS13335"),
    ("198.41.128.0/17", "Cloudflare", "AS13335"),
    ("13.32.0.0/15", "Amazon CloudFront", "AS16509"),
    ("13.224.0.0/14", "Amazon CloudFront", "AS16509"),
    ("151.101.0.0/16", "Fastly", "AS54113"),
    ("23.0.0.0/12", "Akamai", "AS16625"),
]

def resolve_ip_asn(ip: str) -> str:
    """Resolve ASN for an IP using Team Cymru DNS (zero external HTTP quota)."""
    try:
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return ""
        rev_ip = ".".join(reversed(parts))
        query_host = f"{rev_ip}.origin.asn.cymru.com"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        answers = resolver.resolve(query_host, "TXT")
        for rdata in answers:
            # Format: "13335 | 104.16.0.0/12 | US | arin | 2014-03-28"
            txt = rdata.to_text().strip('"')
            asn_raw = txt.split("|")[0].strip()
            if asn_raw:
                return f"AS{asn_raw}"
    except Exception:
        pass
    return ""

def detect_cdn(ip: str) -> tuple[bool, str | None, str | None]:
    """Determine if IP belongs to a CDN via local CIDR match or Cymru DNS ASN."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        # 1. Local CIDR check
        for cidr_str, provider, asn in KNOWN_CDN_CIDRS:
            if ip_obj in ipaddress.ip_network(cidr_str):
                return True, provider, asn
    except ValueError:
        return False, None, None

    # 2. DNS ASN check
    asn = resolve_ip_asn(ip)
    if asn and asn in CDN_ASN_MAP:
        return True, CDN_ASN_MAP[asn], asn
    if asn:
        return False, None, asn
    return False, None, None
