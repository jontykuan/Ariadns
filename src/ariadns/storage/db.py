import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional
from ariadns.models.entities import PropositionNode, DataCustodian, SessionAuditEntry, WarninglistIndicator

class DatabaseManager:
    def __init__(self, db_path: str = "ariadns_state.db"):
        self.db_path = db_path
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def get_readonly_connection(self) -> sqlite3.Connection:
        uri_path = Path(self.db_path).resolve().as_uri()
        conn = sqlite3.connect(f"{uri_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
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

                CREATE TABLE IF NOT EXISTS evidence_propositions (
                    session_id TEXT NOT NULL,
                    prop_id TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    rank INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    statement TEXT NOT NULL,
                    premises_json TEXT NOT NULL,
                    is_rendered INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (session_id, prop_id)
                );

                CREATE TABLE IF NOT EXISTS evidence_edges (
                    session_id TEXT NOT NULL,
                    premise_id TEXT NOT NULL,
                    conclusion_id TEXT NOT NULL,
                    PRIMARY KEY (session_id, premise_id, conclusion_id)
                );

                CREATE TABLE IF NOT EXISTS evidence_custodians (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    conclusion_id TEXT NOT NULL,
                    custodian_name TEXT NOT NULL,
                    custodian_role TEXT NOT NULL,
                    queryable_node TEXT NOT NULL,
                    queryable_records_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS session_audit_logs (
                    session_id TEXT NOT NULL,
                    step_seq INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    params_json TEXT NOT NULL,
                    added_fact_ids_json TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    PRIMARY KEY (session_id, step_seq)
                );

                CREATE TABLE IF NOT EXISTS warninglist_indicators (
                    list_name TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    synced_at INTEGER NOT NULL,
                    PRIMARY KEY (list_name, indicator_value)
                );

                CREATE TABLE IF NOT EXISTS warninglist_metadata (
                    key TEXT PRIMARY KEY,
                    value_text TEXT NOT NULL,
                    synced_at INTEGER NOT NULL
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

    def save_normalized_evidence(
        self,
        session_id: str,
        propositions: list[PropositionNode],
        edges: list[tuple[str, str]],
        replace: bool = False
    ) -> None:
        with self.get_connection() as conn:
            if replace:
                conn.execute("DELETE FROM evidence_propositions WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM evidence_edges WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM evidence_custodians WHERE session_id = ?", (session_id,))

            for p in propositions:
                conn.execute("""
                    INSERT OR REPLACE INTO evidence_propositions
                    (session_id, prop_id, node_kind, rank, rule_name, target_entity, entity_type, statement, premises_json, is_rendered)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    p.prop_id,
                    p.node_kind,
                    p.rank,
                    p.rule_name,
                    p.target_entity,
                    p.entity_type,
                    p.statement,
                    json.dumps(p.premises),
                    1 if p.is_rendered else 0
                ))

                for c in p.custodians:
                    conn.execute("""
                        INSERT INTO evidence_custodians
                        (session_id, conclusion_id, custodian_name, custodian_role, queryable_node, queryable_records_json)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        session_id,
                        p.prop_id,
                        c.custodian_name,
                        c.custodian_role,
                        c.queryable_node,
                        json.dumps(c.queryable_records)
                    ))

            for premise, conclusion in edges:
                conn.execute("""
                    INSERT OR REPLACE INTO evidence_edges (session_id, premise_id, conclusion_id)
                    VALUES (?, ?, ?)
                """, (session_id, premise, conclusion))

    def get_normalized_propositions(self, session_id: str, rendered_only: bool = True) -> list[PropositionNode]:
        query = "SELECT * FROM evidence_propositions WHERE session_id = ?"
        if rendered_only:
            query += " AND is_rendered = 1"
        query += " ORDER BY rank ASC, prop_id ASC"

        with self.get_connection() as conn:
            rows = conn.execute(query, (session_id,)).fetchall()
            props = []
            for r in rows:
                c_rows = conn.execute(
                    "SELECT * FROM evidence_custodians WHERE session_id = ? AND conclusion_id = ?",
                    (session_id, r["prop_id"])
                ).fetchall()
                custodians = [
                    DataCustodian(
                        custodian_name=c["custodian_name"],
                        custodian_role=c["custodian_role"],
                        queryable_node=c["queryable_node"],
                        queryable_records=json.loads(c["queryable_records_json"]),
                    )
                    for c in c_rows
                ]
                props.append(PropositionNode(
                    prop_id=r["prop_id"],
                    node_kind=r["node_kind"],
                    rank=r["rank"],
                    rule_name=r["rule_name"],
                    target_entity=r["target_entity"],
                    entity_type=r["entity_type"],
                    statement=r["statement"],
                    premises=json.loads(r["premises_json"]),
                    custodians=custodians,
                    is_rendered=bool(r["is_rendered"])
                ))
            return props

    def get_normalized_edges(self, session_id: str) -> list[tuple[str, str]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT premise_id, conclusion_id FROM evidence_edges WHERE session_id = ?",
                (session_id,)
            ).fetchall()
            return [(r["premise_id"], r["conclusion_id"]) for r in rows]

    def get_normalized_custodians(self, session_id: str, conclusion_id: Optional[str] = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM evidence_custodians WHERE session_id = ?"
        params: list[Any] = [session_id]
        if conclusion_id:
            query += " AND conclusion_id = ?"
            params.append(conclusion_id)
        with self.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [
                {
                    "conclusion_id": r["conclusion_id"],
                    "custodian_name": r["custodian_name"],
                    "custodian_role": r["custodian_role"],
                    "queryable_node": r["queryable_node"],
                    "queryable_records": json.loads(r["queryable_records_json"]),
                }
                for r in rows
            ]

    def append_audit_log(self, entry: SessionAuditEntry) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO session_audit_logs
                (session_id, step_seq, timestamp, module_name, target, params_json, added_fact_ids_json, artifact_sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.session_id,
                entry.step_seq,
                entry.timestamp,
                entry.module_name,
                entry.target,
                entry.params_json,
                json.dumps(entry.added_fact_ids),
                entry.artifact_sha256,
            ))

    def get_audit_logs(self, session_id: str) -> list[SessionAuditEntry]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM session_audit_logs WHERE session_id = ? ORDER BY step_seq ASC",
                (session_id,)
            ).fetchall()
            return [
                SessionAuditEntry(
                    session_id=r["session_id"],
                    step_seq=r["step_seq"],
                    timestamp=r["timestamp"],
                    module_name=r["module_name"],
                    target=r["target"],
                    params_json=r["params_json"],
                    added_fact_ids=json.loads(r["added_fact_ids_json"]),
                    artifact_sha256=r["artifact_sha256"],
                )
                for r in rows
            ]

    def set_warninglist_metadata(self, key: str, value_text: str, synced_at: Optional[int] = None) -> None:
        if synced_at is None:
            try:
                now = int(value_text)
            except ValueError:
                now = int(time.time())
        else:
            now = synced_at
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO warninglist_metadata (key, value_text, synced_at)
                VALUES (?, ?, ?)
            """, (key, value_text, now))

    def get_warninglist_last_synced(self) -> Optional[int]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT synced_at FROM warninglist_metadata WHERE key = 'last_synced_at'"
            ).fetchone()
            if row:
                return int(row["synced_at"])
            return None

    def save_warninglist_indicators(self, indicators: list[WarninglistIndicator]) -> None:
        with self.get_connection() as conn:
            for ind in indicators:
                conn.execute("""
                    INSERT OR REPLACE INTO warninglist_indicators
                    (list_name, indicator_type, indicator_value, synced_at)
                    VALUES (?, ?, ?, ?)
                """, (ind.list_name, ind.indicator_type, ind.indicator_value.lower().strip(), ind.synced_at))

    def is_warninglist_match(self, indicator_value: str) -> bool:
        val = indicator_value.lower().strip().rstrip(".")
        with self.get_connection() as conn:
            # Check exact match
            row = conn.execute(
                "SELECT 1 FROM warninglist_indicators WHERE indicator_value = ? LIMIT 1",
                (val,)
            ).fetchone()
            if row:
                return True
            # Check substring match
            rows = conn.execute(
                "SELECT indicator_value FROM warninglist_indicators WHERE indicator_type = 'substring'"
            ).fetchall()
            for r in rows:
                if r["indicator_value"] in val:
                    return True
        return False
