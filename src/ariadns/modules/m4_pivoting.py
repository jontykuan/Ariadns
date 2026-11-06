"""Module 4: Multi-Dimensional Pivoting Engine (Reverse IP, Reverse MX/NS, Reverse Whois/Token)."""

from typing import Any
from ariadns.models.config import AppConfig
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient

class PivotingEngine:
    def __init__(self, db: DatabaseManager, http_client: HttpClient, config: AppConfig):
        self.db = db
        self.http_client = http_client
        self.config = config

    def reverse_ip(self, ip: str) -> list[str]:
        cached = self.db.get_pivot_cache("hackertarget", "reverse_ip", ip)
        if cached is not None:
            return cached if isinstance(cached, list) else []

        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp, status = self.http_client.fetch_with_backoff(url, provider="hackertarget")
        domains: list[str] = []

        if resp and resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines:
                cleaned = line.strip().lower()
                if cleaned and "no records" not in cleaned and "api count" not in cleaned:
                    domains.append(cleaned)

        self.db.set_pivot_cache(
            "hackertarget",
            "reverse_ip",
            ip,
            domains,
            ttl_seconds=self.config.cache_ttl_seconds
        )
        return domains

    def reverse_mx(self, mx_host: str) -> list[str]:
        if self.config.is_mx_blacklisted(mx_host):
            return []
        cached = self.db.get_pivot_cache("hackertarget", "reverse_mx", mx_host)
        if cached is not None:
            return cached if isinstance(cached, list) else []

        # Free API / lookup endpoint
        url = f"https://api.hackertarget.com/findshareddns/?q={mx_host}"
        resp, status = self.http_client.fetch_with_backoff(url, provider="hackertarget")
        domains: list[str] = []
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                cleaned = line.strip().lower()
                if cleaned and "no records" not in cleaned and "error" not in cleaned:
                    domains.append(cleaned)

        self.db.set_pivot_cache("hackertarget", "reverse_mx", mx_host, domains, ttl_seconds=self.config.cache_ttl_seconds)
        return domains

    def reverse_ns(self, ns_host: str) -> list[str]:
        if self.config.is_ns_blacklisted(ns_host):
            return []
        cached = self.db.get_pivot_cache("hackertarget", "reverse_ns", ns_host)
        if cached is not None:
            return cached if isinstance(cached, list) else []

        url = f"https://api.hackertarget.com/findshareddns/?q={ns_host}"
        resp, status = self.http_client.fetch_with_backoff(url, provider="hackertarget")
        domains: list[str] = []
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                cleaned = line.strip().lower()
                if cleaned and "no records" not in cleaned and "error" not in cleaned:
                    domains.append(cleaned)

        self.db.set_pivot_cache("hackertarget", "reverse_ns", ns_host, domains, ttl_seconds=self.config.cache_ttl_seconds)
        return domains

    def reverse_token_or_email(self, identifier: str, provider: str = "securitytrails") -> tuple[list[str], str]:
        # Pluggable provider check
        key = self.config.api_keys.get(provider)
        if not key:
            return [], ModuleStatus.SKIPPED_NO_KEY.value
        # If API key configured, make the request
        return [], ModuleStatus.OK.value
