import os
import json
from core_topo_gen.types import NodeInfo, SegmentationInfo
from core_topo_gen.utils.segmentation import plan_and_apply_segmentation


def test_segmentation_abs_count_with_zero_density(tmp_path):
    # Prepare minimal nodes: 2 routers, 4 hosts
    routers = [
        NodeInfo(node_id=100, ip4="10.0.0.1/24", role="Router"),
        NodeInfo(node_id=101, ip4="10.0.1.1/24", role="Router"),
    ]
    hosts = [
        NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Workstation"),
        NodeInfo(node_id=2, ip4="10.0.0.11/24", role="Workstation"),
        NodeInfo(node_id=3, ip4="10.0.1.10/24", role="Workstation"),
        NodeInfo(node_id=4, ip4="10.0.1.11/24", role="Workstation"),
    ]

    # Segmentation items with explicit counts (sum = 3)
    items = [
        SegmentationInfo(name="Firewall", factor=1.0, abs_count=2),
        SegmentationInfo(name="NAT", factor=1.0, abs_count=1),
    ]

    out_dir = tmp_path / "segmentation"
    include_hosts = False
    summary = plan_and_apply_segmentation(
        session=None,
        routers=routers,
        hosts=hosts,
        density=0.0,  # zero density should still plan using abs_count
        items=items,
        out_dir=str(out_dir),
        include_hosts=include_hosts,
    )

    rules = summary.get("rules") or []
    requested_slots = sum(int(it.abs_count or 0) for it in items)
    max_available_nodes = len(routers) + (len(hosts) if include_hosts else 0)
    expected_nodes = min(requested_slots, max_available_nodes)

    nodes_with_rules = {r.get("node_id") for r in rules}
    assert len(nodes_with_rules) == expected_nodes, (
        f"expected {expected_nodes} nodes with segmentation rules, got {len(nodes_with_rules)}: {nodes_with_rules}"
    )
    # Each node should have at least one rule recorded
    for nid in nodes_with_rules:
        assert any(r.get("node_id") == nid for r in rules), f"node {nid} missing rule entries"

    # NAT count is 1 -> expect exactly one NAT rule when routers are available
    nat_rules = [r for r in rules if (r.get("rule", {}) or {}).get("type") == "nat"]
    assert len(nat_rules) == 1, f"expected single NAT rule, got {len(nat_rules)}"

    # Ensure total rules is at least the number of nodes (nodes may have multiple rules now)
    assert len(rules) >= expected_nodes

    # Ensure the segmentation_summary.json is written and matches the rule count
    seg_path = out_dir / "segmentation_summary.json"
    assert os.path.exists(seg_path)
    data = json.loads(seg_path.read_text("utf-8"))
    assert isinstance(data.get("rules"), list)
    assert len(data["rules"]) == len(rules)
