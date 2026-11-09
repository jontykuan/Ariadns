import json
import logging
import time
from typing import Any
from ariadns.models.config import AppConfig
from ariadns.models.entities import WarninglistIndicator
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager
from ariadns.utils.rate_limiter import HttpClient

logger = logging.getLogger(__name__)

WARNINGLIST_FEEDS = [
    {
        "name": "parking-domain-ns",
        "url": "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/parking-domain-ns/list.json",
        "default_type": "substring",
    },
    {
        "name": "parking-domain",
        "url": "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/parking-domain/list.json",
        "default_type": "exact",
    },
    {
        "name": "common-contact-emails",
        "url": "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/common-contact-emails/list.json",
        "default_type": "regex",
    },
    {
        "name": "free-email-domains",
        "url": "https://raw.githubusercontent.com/Kikobeats/free-email-domains/master/domains.json",
        "default_type": "exact",
    },
]

class WarninglistSynchronizer:
    SYNC_INTERVAL_SECONDS = 604800  # 7 days

    def __init__(self, db: DatabaseManager, http_client: HttpClient, config: AppConfig):
        self.db = db
        self.http_client = http_client
        self.config = config

    def ensure_warninglists_synced(self, force: bool = False) -> ModuleStatus:
        now = int(time.time())
        last_synced = self.db.get_warninglist_last_synced()

        if not force and last_synced and (now - last_synced < self.SYNC_INTERVAL_SECONDS):
            return ModuleStatus.CACHED

        indicators: list[WarninglistIndicator] = []
        sync_failed = False

        for feed in WARNINGLIST_FEEDS:
            url = feed["url"]
            resp, status = self.http_client.fetch_with_backoff(url, provider="github_raw")
            if not resp or resp.status_code != 200:
                logger.warning("Failed to fetch warninglist feed %s: status %s", feed["name"], status)
                sync_failed = True
                continue

            try:
                data = resp.json()
                items: list[str] = []
                ind_type = feed["default_type"]
                if isinstance(data, dict):
                    items = data.get("list", [])
                    ind_type = data.get("type", ind_type)
                elif isinstance(data, list):
                    items = [str(x) for x in data]

                for item in items:
                    val = str(item).strip().lower()
                    if val:
                        indicators.append(WarninglistIndicator(
                            list_name=feed["name"],
                            indicator_type=ind_type,
                            indicator_value=val,
                            synced_at=now,
                        ))
            except Exception as e:
                logger.warning("Error parsing warninglist feed %s: %s", feed["name"], e)
                sync_failed = True

        if indicators:
            self.db.save_warninglist_indicators(indicators)
            self.db.set_warninglist_metadata("last_synced_at", str(now), synced_at=now)
            return ModuleStatus.OK

        if sync_failed:
            return ModuleStatus.FALLBACK_NATIVE

        return ModuleStatus.OK
