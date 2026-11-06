import time
from datetime import datetime
from typing import Any, Callable, Optional
import httpx
from ariadns.models.config import AppConfig
from ariadns.models.enums import ModuleStatus
from ariadns.storage.db import DatabaseManager

class RateLimiter:
    def __init__(self, db: DatabaseManager, config: AppConfig):
        self.db = db
        self.config = config
        self._last_call_timestamps: dict[str, float] = {}

    def wait_for_slot(self, provider: str) -> None:
        now = time.time()
        last = self._last_call_timestamps.get(provider, 0.0)
        min_delay = self.config.default_delay_seconds
        if provider == "virustotal":
            min_delay = max(min_delay, 60.0 / self.config.virustotal_rpm)
        elapsed = now - last
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
        self._last_call_timestamps[provider] = time.time()

    def check_and_increment_quota(self, provider: str) -> bool:
        now = time.time()
        dt = datetime.fromtimestamp(now)
        min_key = f"minute:{dt.strftime('%Y%m%d%H%M')}"
        day_key = f"day:{dt.strftime('%Y%m%d')}"

        with self.db.get_connection() as conn:
            if provider == "virustotal":
                row_min = conn.execute(
                    "SELECT call_count FROM api_quota_tracker WHERE provider = ? AND window_key = ?",
                    (provider, min_key)
                ).fetchone()
                if row_min and row_min["call_count"] >= self.config.virustotal_rpm:
                    return False

                row_day = conn.execute(
                    "SELECT call_count FROM api_quota_tracker WHERE provider = ? AND window_key = ?",
                    (provider, day_key)
                ).fetchone()
                if row_day and row_day["call_count"] >= self.config.virustotal_rpd:
                    return False

            conn.execute("""
                INSERT INTO api_quota_tracker (provider, window_key, call_count, last_called_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(provider, window_key) DO UPDATE SET call_count = call_count + 1, last_called_at = excluded.last_called_at
            """, (provider, min_key, now))

            conn.execute("""
                INSERT INTO api_quota_tracker (provider, window_key, call_count, last_called_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(provider, window_key) DO UPDATE SET call_count = call_count + 1, last_called_at = excluded.last_called_at
            """, (provider, day_key, now))
        return True

class HttpClient:
    def __init__(self, rate_limiter: RateLimiter, config: AppConfig):
        self.rate_limiter = rate_limiter
        self.config = config

    def fetch_with_backoff(
        self,
        url: str,
        method: str = "GET",
        provider: str = "generic",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        custom_caller: Callable[[], httpx.Response] | None = None,
    ) -> tuple[Optional[httpx.Response], str]:
        if not self.rate_limiter.check_and_increment_quota(provider):
            return None, ModuleStatus.SKIPPED_QUOTA.value

        self.rate_limiter.wait_for_slot(provider)
        backoffs = [2.0, 4.0, 8.0]
        req_kwargs: dict[str, Any] = {"headers": headers or {}}
        if params:
            req_kwargs["params"] = params

        for attempt in range(len(backoffs) + 1):
            try:
                if custom_caller:
                    resp = custom_caller()
                else:
                    with httpx.Client(timeout=self.config.http_timeout_seconds, follow_redirects=True) as client:
                        resp = client.request(method, url, **req_kwargs)

                if resp.status_code in (429, 504) and attempt < len(backoffs):
                    time.sleep(backoffs[attempt])
                    continue
                return resp, ModuleStatus.OK.value
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt < len(backoffs):
                    time.sleep(backoffs[attempt])
                    continue
                return None, ModuleStatus.TIMEOUT_UNVERIFIED.value
            except Exception:
                return None, ModuleStatus.TIMEOUT_UNVERIFIED.value

        return None, ModuleStatus.TIMEOUT_UNVERIFIED.value
