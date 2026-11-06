from ariadns.models.enums import ConfidenceLevel, EdgeType, NodeType
from ariadns.storage.db import DatabaseManager
from ariadns.storage.graph_store import PropertyGraphStore

def test_graph_store_operations(tmp_path):
    db_file = tmp_path / "test.db"
    db = DatabaseManager(db_file)
    store = PropertyGraphStore(db, session_id="example.com")

    # Add nodes
    l1_id = store.add_node(NodeType.DOMAIN_L1.value, "example.com")
    ip_id = store.add_node(NodeType.IP.value, "198.51.100.24")
    l2_id = store.add_node(NodeType.DOMAIN_L2.value, "portal.net")

    # Add edges
    store.add_edge(l1_id, ip_id, EdgeType.RESOLVES_TO.value, weight=1.0)
    store.add_edge(ip_id, l2_id, EdgeType.SAME_ORIGIN_IP.value, weight=0.7)

    # Score L2 domain
    score, level = store.score_l2_domain("example.com", "portal.net")
    assert score == 0.7
    assert level == ConfidenceLevel.HIGH.value

    # Shared hosting detection
    assert store.is_shared_hosting_ip("198.51.100.24", threshold=100) is False
    for i in range(101):
        d_id = store.add_node(NodeType.DOMAIN_L2.value, f"domain{i}.com")
        store.add_edge(ip_id, d_id, EdgeType.SAME_ORIGIN_IP.value, weight=0.1)

    assert store.is_shared_hosting_ip("198.51.100.24", threshold=100) is True

    # Topology export
    topo = store.export_topology()
    assert topo["session_id"] == "example.com"
    assert len(topo["nodes"]) >= 104
    assert len(topo["edges"]) >= 103

    # Reload from DB persistence check
    store2 = PropertyGraphStore(db, session_id="example.com")
    assert store2.graph.number_of_nodes() == store.graph.number_of_nodes()
