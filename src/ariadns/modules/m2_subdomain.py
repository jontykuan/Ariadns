"""Module 2: Subdomain Enumerator (crt.sh, HackerTarget, subfinder wrapper, httpx wrapper & native prober)."""

import json
from typing import Any
import dns.resolver
import httpx
from ariadns.models.config import AppConfig
from ariadns.models.entities import SubdomainRecord
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient
from ariadns.utils.tool_runner import check_binary_available, run_command_safely

class SubdomainEnumerator:
    def __init__(self, db: DatabaseManager, http_client: HttpClient, config: AppConfig):
        self.db = db
        self.http_client = http_client
        self.config = config

    def query_crt_sh(self, domain: str) -> list[str]:
        cached = self.db.get_dns_cache(domain, "CRT_SH")
        if cached is not None:
            return cached.get("subdomains", [])

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp, status = self.http_client.fetch_with_backoff(url, provider="crt_sh")
        subdomains: set[str] = set()

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        clean_name = name.strip().lower()
                        if clean_name.startswith("*."):
                            clean_name = clean_name[2:]
                        if clean_name.endswith(f".{domain.lower()}") or clean_name == domain.lower():
                            subdomains.add(clean_name)
            except Exception:
                pass

        sub_list = sorted(list(subdomains))
        if sub_list:
            self.db.set_dns_cache(domain, "CRT_SH", {"subdomains": sub_list}, ttl_seconds=self.config.cache_ttl_seconds)
        return sub_list

    def query_hackertarget_subdomains(self, domain: str) -> list[str]:
        cached = self.db.get_dns_cache(domain, "HT_HOSTSEARCH")
        if cached is not None:
            return cached.get("subdomains", [])

        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp, status = self.http_client.fetch_with_backoff(url, provider="hackertarget")
        subdomains: set[str] = set()

        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(f".{domain.lower()}") or host == domain.lower():
                        subdomains.add(host)

        sub_list = sorted(list(subdomains))
        if sub_list:
            self.db.set_dns_cache(domain, "HT_HOSTSEARCH", {"subdomains": sub_list}, ttl_seconds=self.config.cache_ttl_seconds)
        return sub_list

    def enumerate_subfinder(self, domain: str) -> list[str]:
        if not check_binary_available("subfinder"):
            return []
        cmd = ["subfinder", "-d", domain, "-silent"]
        code, stdout, _ = run_command_safely(cmd, timeout_seconds=15.0)
        if code == 0:
            return [line.strip().lower() for line in stdout.splitlines() if line.strip()]
        return []

    def probe_subdomains_httpx(self, subdomains: list[str]) -> list[SubdomainRecord]:
        records: list[SubdomainRecord] = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        for sub in subdomains:
            ip = None
            try:
                ans = resolver.resolve(sub, "A")
                for r in ans:
                    ip = r.to_text()
                    break
            except Exception:
                continue

            status_code = None
            title = None
            server = None
            for proto in ["https", "http"]:
                try:
                    with httpx.Client(timeout=self.config.http_timeout_seconds, verify=False, follow_redirects=True) as client:
                        resp = client.get(f"{proto}://{sub}/")
                        status_code = resp.status_code
                        server = resp.headers.get("server")
                        body = resp.text
                        if "<title>" in body and "</title>" in body:
                            title = body.split("<title>")[1].split("</title>")[0].strip()
                        break
                except Exception:
                    continue

            records.append(SubdomainRecord(
                subdomain=sub,
                ip=ip,
                status_code=status_code,
                title=title,
                server=server,
            ))

        return records

    def run(self, domain: str) -> list[SubdomainRecord]:
        cached = self.db.get_dns_cache(domain, "SUBDOMAINS_PROBED")
        if cached is not None:
            return [SubdomainRecord(**r) for r in cached.get("records", [])]

        crt_subs = self.query_crt_sh(domain)
        ht_subs = self.query_hackertarget_subdomains(domain)
        subfinder_subs = self.enumerate_subfinder(domain)
        all_subs = sorted(list(set(crt_subs + ht_subs + subfinder_subs)))

        active_records = self.probe_subdomains_httpx(all_subs[:30])
        self.db.set_dns_cache(
            domain,
            "SUBDOMAINS_PROBED",
            {"records": [r.__dict__ for r in active_records]},
            ttl_seconds=self.config.cache_ttl_seconds
        )
        return active_records
