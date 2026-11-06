import json
import time
from typing import Any, Optional
import networkx as nx
from ariadns.models.enums import ConfidenceLevel, EdgeType, NodeType
from ariadns.storage.db import DatabaseManager

EDGE_WEIGHTS = {
    EdgeType.SAME_TOKEN.value: 0.8,
    EdgeType.SAME_ORIGIN_IP.value: 0.7,
    EdgeType.REGISTERED_BY.value: 0.7,
    EdgeType.SAME_MX.value: 0.6,
    EdgeType.SAME_NS.value: 0.4,
}

class PropertyGraphStore:
    def __init__(self, db: DatabaseManager, session_id: str):
        self.db = db
        self.session_id = session_id
        self.graph = nx.DiGraph()
        self.load_from_db()

    def load_from_db(self) -> None:
        self.graph.clear()
        with self.db.get_connection() as conn:
            nodes = conn.execute(
                "SELECT node_id, node_type, label, properties_json FROM graph_nodes WHERE session_id = ?",
                (self.session_id,)
            ).fetchall()
            for n in nodes:
                props = json.loads(n["properties_json"])
                self.graph.add_node(n["node_id"], node_type=n["node_type"], label=n["label"], **props)

            edges = conn.execute(
                "SELECT source_id, target_id, relation_type, weight, properties_json FROM graph_edges WHERE session_id = ?",
                (self.session_id,)
            ).fetchall()
            for e in edges:
                props = json.loads(e["properties_json"])
                self.graph.add_edge(e["source_id"], e["target_id"], relation_type=e["relation_type"], weight=e["weight"], **props)

    def add_node(self, node_type: str, value: str, label: str | None = None, **properties) -> str:
        node_id = f"{node_type}:{value.strip()}"
        lbl = label or value.strip()
        now = int(time.time())
        props_str = json.dumps(properties)
        with self.db.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO graph_nodes (node_id, session_id, node_type, label, properties_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (node_id, self.session_id, node_type, lbl, props_str, now))
        self.graph.add_node(node_id, node_type=node_type, label=lbl, **properties)
        return node_id

    def add_edge(self, source_id: str, target_id: str, relation_type: str, weight: float | None = None, **properties) -> None:
        w = weight if weight is not None else EDGE_WEIGHTS.get(relation_type, 0.5)
        now = int(time.time())
        props_str = json.dumps(properties)
        with self.db.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO graph_edges (source_id, target_id, session_id, relation_type, weight, properties_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (source_id, target_id, self.session_id, relation_type, w, props_str, now))
        self.graph.add_edge(source_id, target_id, relation_type=relation_type, weight=w, **properties)

    def is_shared_hosting_ip(self, ip: str, threshold: int = 100) -> bool:
        node_id = f"{NodeType.IP.value}:{ip}"
        if not self.graph.has_node(node_id):
            return False
        degree = self.graph.in_degree(node_id) + self.graph.out_degree(node_id)
        return degree > threshold

    def score_l2_domain(self, domain_l1: str, candidate_l2: str) -> tuple[float, str]:
        l1_id = f"{NodeType.DOMAIN_L1.value}:{domain_l1}"
        l2_id = f"{NodeType.DOMAIN_L2.value}:{candidate_l2}"
        if not self.graph.has_node(l1_id) or not self.graph.has_node(l2_id):
            return 0.0, ConfidenceLevel.LOW.value

        # Calculate sum of weights for direct or 2-hop edges between L1 and L2
        total_weight = 0.0
        # Direct edges
        if self.graph.has_edge(l1_id, l2_id):
            total_weight += self.graph[l1_id][l2_id].get("weight", 0.0)

        # 2-hop edges via shared hubs (IP, Token, MX, NS, Email)
        l1_neighbors = set(self.graph.successors(l1_id)).union(self.graph.predecessors(l1_id))
        l2_neighbors = set(self.graph.successors(l2_id)).union(self.graph.predecessors(l2_id))
        shared = l1_neighbors.intersection(l2_neighbors)

        for hub in shared:
            # Get edge from hub to L2 or L2 to hub
            w = 0.0
            if self.graph.has_edge(hub, l2_id):
                w = self.graph[hub][l2_id].get("weight", 0.0)
            elif self.graph.has_edge(l2_id, hub):
                w = self.graph[l2_id][hub].get("weight", 0.0)
            total_weight += w

        final_score = min(1.0, total_weight)
        if final_score >= 0.60:
            level = ConfidenceLevel.HIGH.value
        elif final_score >= 0.40:
            level = ConfidenceLevel.MEDIUM.value
        else:
            level = ConfidenceLevel.LOW.value
        return final_score, level

    def export_topology(self) -> dict[str, Any]:
        data = nx.node_link_data(self.graph)
        return {
            "session_id": self.session_id,
            "nodes": [
                {"id": n["id"], "label": n.get("label", n["id"]), "type": n.get("node_type", "UNKNOWN")}
                for n in data.get("nodes", [])
            ],
            "edges": [
                {"source": e["source"], "target": e["target"], "relation": e.get("relation_type", "RELATED"), "weight": e.get("weight", 1.0)}
                for e in data.get("links", [])
            ]
        }
