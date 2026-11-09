import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

DEFAULT_MX_BLACKLIST = [
    "google.com", "googlemail.com", "outlook.com", "protection.outlook.com",
    "pphosted.com", "mimecast.com", "zoho.com", "yahoodns.net",
    "icloud.com", "protonmail.ch", "secureserver.net", "privateemail.com", "titan.email", "yandex.net", "mailgun.org", "sendgrid.net"
]

DEFAULT_NS_BLACKLIST = [
    "cloudflare.com", "domaincontrol.com", "awsdns", "googledomains.com",
    "azure-dns", "nsone.net", "linode.com", "digitalocean.com",
    "registrar-servers.com", "hichina.com", "dnspod.net"
]

def mask_secret(secret: str | None, prefix_len: int = 3) -> str:
    if not secret:
        return ""
    if len(secret) <= prefix_len:
        return "***"
    return f"{secret[:prefix_len]}***"

@dataclass
class AppConfig:
    api_keys: dict[str, str] = field(default_factory=dict)
    virustotal_rpm: int = 4
    virustotal_rpd: int = 500
    default_delay_seconds: float = 1.5
    http_timeout_seconds: float = 5.0
    max_retries: int = 3
    mx_blacklist: list[str] = field(default_factory=lambda: list(DEFAULT_MX_BLACKLIST))
    ns_blacklist: list[str] = field(default_factory=lambda: list(DEFAULT_NS_BLACKLIST))
    shared_ip_threshold: int = 100
    cache_ttl_seconds: int = 604800
    db_path: str = "ariadns_state.db"

    def is_mx_blacklisted(self, mx_host: str) -> bool:
        target = mx_host.lower().strip().rstrip(".")
        return any(b in target for b in self.mx_blacklist)

    def is_ns_blacklisted(self, ns_host: str) -> bool:
        target = ns_host.lower().strip().rstrip(".")
        return any(b in target for b in self.ns_blacklist)

    def get_masked_keys(self) -> dict[str, str]:
        return {k: mask_secret(v) for k, v in self.api_keys.items()}

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "AppConfig":
        path_to_try = Path(config_path) if config_path else Path("config.yaml")
        if not path_to_try.exists():
            path_to_try = Path("config.yaml.example")
        data: dict[str, Any] = {}
        if path_to_try.exists():
            with open(path_to_try, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        
        api_keys = data.get("api_keys") or {}
        rl = data.get("rate_limits") or {}
        bl = data.get("blacklists") or {}
        cc = data.get("cache") or {}

        return cls(
            api_keys={k: str(v or "") for k, v in api_keys.items()},
            virustotal_rpm=int(rl.get("virustotal_rpm", 4)),
            virustotal_rpd=int(rl.get("virustotal_rpd", 500)),
            default_delay_seconds=float(rl.get("default_delay_seconds", 1.5)),
            http_timeout_seconds=float(rl.get("http_timeout_seconds", 5.0)),
            max_retries=int(rl.get("max_retries", 3)),
            mx_blacklist=list(bl.get("mx") or DEFAULT_MX_BLACKLIST),
            ns_blacklist=list(bl.get("ns") or DEFAULT_NS_BLACKLIST),
            shared_ip_threshold=int(bl.get("shared_ip_threshold", 100)),
            cache_ttl_seconds=int(cc.get("ttl_seconds", 604800)),
            db_path=str(cc.get("db_path", "ariadns_state.db")),
        )
