from pathlib import Path

from core_topo_gen.planning.full_preview import build_full_preview


def _base_scenario_dict(path: Path) -> dict:
    return {
        "filepath": str(path),
        "filepath_raw": str(path),
        "exists": True,
    }


def test_base_bridge_cluster_metadata():
    base_path = Path(__file__).parent / "fixtures" / "base_scenario_cluster.xml"
    preview = build_full_preview(
        role_counts={"Workstation": 6},
        routers_planned=3,
        services_plan={"HTTP": 2},
        vulnerabilities_plan={},
        r2r_policy={"mode": "Uniform", "target_degree": 2},
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=[],
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=[],
        seed=4242,
        ip4_prefix="10.30.0.0/24",
        base_scenario=_base_scenario_dict(base_path),
    )

    bridge_info = preview.get("base_bridge_preview") or {}
    assert bridge_info.get("attached")
    cluster = bridge_info.get("target_cluster")
    assert cluster and isinstance(cluster, dict)
    cluster_nodes = cluster.get("nodes") or []
    cluster_edges = cluster.get("edges") or []
    assert len(cluster_nodes) >= 2
    # ensure cluster edges preserved
    edge_set = {tuple(sorted((str(a), str(b)))) for a, b in cluster_edges}
    assert ("101", "102") in edge_set
    assert ("102", "103") in edge_set

def test_base_bridge_cluster_includes_hosts():
    base_path = Path(__file__).parent / "fixtures" / "base_scenario_with_hosts.xml"
    preview = build_full_preview(
        role_counts={"Workstation": 4},
        routers_planned=2,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy={"mode": "Uniform", "target_degree": 2},
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=[],
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=[],
        seed=1357,
        ip4_prefix="10.31.0.0/24",
        base_scenario=_base_scenario_dict(base_path),
    )

    bridge_info = preview.get("base_bridge_preview") or {}
    assert bridge_info.get("attached")
    cluster = bridge_info.get("target_cluster")
    assert cluster and isinstance(cluster, dict)
    cluster_nodes = cluster.get("nodes") or []
    assert len(cluster_nodes) >= 3
    node_types = {str(n.get("type")) for n in cluster_nodes}
    assert "pc" in node_types or "workstation" in node_types
    assert "rj45" in node_types, "cluster should include RJ45 infrastructure nodes"
    assert "wirelesslan" in node_types, "cluster should include wireless infrastructure nodes"
    assert "unknown" in node_types, "cluster should label unrecognized node types as unknown"




def test_base_bridge_marks_existing_router():
    base_path = Path(__file__).parent / "fixtures" / "base_scenario_minimal.xml"
    preview = build_full_preview(
        role_counts={"Workstation": 4},
        routers_planned=2,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=[],
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=[],
        seed=9876,
        ip4_prefix="10.20.0.0/24",
        base_scenario=_base_scenario_dict(base_path),
    )

    bridge_info = preview.get("base_bridge_preview")
    assert bridge_info and bridge_info.get("attached"), "Bridge router should be attached when base scenario is present"
    assert bridge_info.get("target", {}).get("name") == "base-router"
    peer_router_id = bridge_info.get("internal_peer_router_id")

    routers = preview.get("routers") or []
    assert len(routers) == 2, "Existing router count should remain unchanged"
    bridge_nodes = [r for r in routers if r.get("is_base_bridge")]
    assert len(bridge_nodes) == 1
    bridge_node = bridge_nodes[0]
    assert bridge_node.get("node_id") == bridge_info.get("bridge_router_id")
    assert bridge_node.get("node_id") == bridge_info.get("internal_peer_router_id")
    assert bridge_info.get("existing_router_bridge") is True
    targets = bridge_node.get("metadata", {}).get("base_bridge_targets") or []
    assert any(t.get("id") == "201" for t in targets)

    r2r_edges = preview.get("r2r_edges_preview") or []
    router_ids = {r["node_id"] for r in routers}
    for edge in r2r_edges:
        assert set(edge).issubset(router_ids)

    ref = preview.get("base_scenario_reference")
    assert ref and Path(ref.get("filepath")).resolve() == base_path.resolve()


def test_base_bridge_missing_file_reports_reason():
    missing_path = Path(__file__).parent / "fixtures" / "does_not_exist.xml"
    preview = build_full_preview(
        role_counts={"Workstation": 2},
        routers_planned=1,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=[],
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=[],
        seed=123,
        ip4_prefix="10.0.0.0/24",
        base_scenario={
            "filepath": str(missing_path),
            "filepath_raw": str(missing_path),
            "exists": False,
        },
    )

    bridge_info = preview.get("base_bridge_preview")
    assert bridge_info and not bridge_info.get("attached")
    assert bridge_info.get("reason") == "missing-file"
    routers = preview.get("routers") or []
    assert all(not r.get("is_base_bridge") for r in routers)
