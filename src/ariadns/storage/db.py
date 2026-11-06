import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional
from ariadns.models.enums import ModuleStatus

class DatabaseManager:
    def __init__(self, db_path: str | Path = "ariadns_state.db"):
        self.db_path = str(db_path)
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_readonly_connection(self) -> sqlite3.Connection:
        db_uri = f"file:{Path(self.db_path).resolve().as_posix()}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        with self.get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS dns_cache (
                    cache_key TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ip_pivot_cache (
                    cache_key TEXT PRIMARY KEY,
                    query_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    result_count INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_quota_tracker (
                    provider TEXT NOT NULL,
                    window_key TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    last_called_at REAL NOT NULL,
                    PRIMARY KEY (provider, window_key)
                );

                CREATE TABLE IF NOT EXISTS investigation_sessions (
                    session_id TEXT PRIMARY KEY,
                    target_domain TEXT NOT NULL,
                    depth INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graph_edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    weight REAL NOT NULL,
                    properties_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (session_id, source_id, target_id, relation_type)
                );
            """)

    def get_dns_cache(self, domain: str, record_type: str) -> Optional[dict[str, Any]]:
        cache_key = f"{domain.lower()}:{record_type.upper()}"
        now = int(time.time())
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT payload_json, expires_at FROM dns_cache WHERE cache_key = ?",
                (cache_key,)
            ).fetchone()
            if row and row["expires_at"] > now:
                return json.loads(row["payload_json"])
        return None

    def set_dns_cache(self, domain: str, record_type: str, payload: Any, ttl_seconds: int = 604800) -> None:
        cache_key = f"{domain.lower()}:{record_type.upper()}"
        now = int(time.time())
        expires_at = now + ttl_seconds
        payload_str = json.dumps(payload)
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO dns_cache (cache_key, domain, record_type, payload_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cache_key, domain.lower(), record_type.upper(), payload_str, now, expires_at))

    def get_pivot_cache(self, provider: str, query_type: str, target: str) -> Optional[dict[str, Any]]:
        cache_key = f"{provider.lower()}:{query_type.lower()}:{target.lower()}"
        now = int(time.time())
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT payload_json, expires_at FROM ip_pivot_cache WHERE cache_key = ?",
                (cache_key,)
            ).fetchone()
            if row and row["expires_at"] > now:
                return json.loads(row["payload_json"])
        return None

    def set_pivot_cache(self, provider: str, query_type: str, target: str, payload: list[Any] | dict[str, Any], ttl_seconds: int = 604800) -> None:
        cache_key = f"{provider.lower()}:{query_type.lower()}:{target.lower()}"
        now = int(time.time())
        expires_at = now + ttl_seconds
        payload_str = json.dumps(payload)
        count = len(payload) if isinstance(payload, list) else 1
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO ip_pivot_cache (cache_key, query_type, target_value, payload_json, result_count, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (cache_key, query_type.lower(), target.lower(), payload_str, count, now, expires_at))

    def execute_readonly_sql(self, sql_query: str, params: tuple = ()) -> list[dict[str, Any]]:
        cleaned = sql_query.strip()
        upper_start = cleaned.upper()
        if not (upper_start.startswith("SELECT") or upper_start.startswith("WITH")):
            raise ValueError("Only SELECT or WITH queries are permitted in read-only mode.")
        if ";" in cleaned.rstrip(";"):
            raise ValueError("Multiple SQL statements are forbidden.")
        
        with self.get_readonly_connection() as conn:
            cursor = conn.execute(cleaned, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
