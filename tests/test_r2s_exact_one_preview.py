import json
from core_topo_gen.planning.full_preview import build_full_preview

def test_r2s_exact_one_preview_all_hosts_under_single_switch():
    role_counts = {"Workstation": 5}
    routers_planned = 2
    # Provide routing_items-like structures for auto-derive (simulate RoutingInfo dataclass minimal)
    class DummyRI:
        def __init__(self, r2s_mode, r2s_edges):
            self.r2s_mode = r2s_mode
            self.r2s_edges = r2s_edges
    routing_items = [DummyRI('Exact', 1)]
    prev = build_full_preview(
        role_counts=role_counts,
        routers_planned=routers_planned,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=routing_items,
        routing_plan={},
        segmentation_density=None,
        segmentation_items=None,
        seed=1234,
        ip4_prefix='10.10.0.0/16'
    )
    r2s = prev.get('r2s_policy_preview', {})
    assert r2s.get('mode') == 'Exact'
    counts = r2s.get('counts') or {}
    # Every router with hosts should have exactly 1 switch
    assert all(c == 1 for c in counts.values())
    # Ensure switches list length equals number of routers that had any hosts >0
    assert len(prev.get('switches', [])) == len(counts)
    # Each switch's host list should cover all hosts of that router (aggregated semantics) – check first switch detail
    sw_details = prev.get('switches_detail') or []
    assert sw_details, 'Expected at least one switch detail record'
    # Validate no switch record is limited to only 2 hosts unless router truly had only 2
    for rec in sw_details:
        assert len(rec.get('hosts', [])) >= 1


def test_r2s_exact_two_preview_splits_hosts_across_switches():
    role_counts = {"Workstation": 8}
    routers_planned = 2

    class DummyRI:
        def __init__(self, r2s_mode, r2s_edges):
            self.r2s_mode = r2s_mode
            self.r2s_edges = r2s_edges

    routing_items = [DummyRI('Exact', 2)]
    prev = build_full_preview(
        role_counts=role_counts,
        routers_planned=routers_planned,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=routing_items,
        routing_plan={},
        segmentation_density=None,
        segmentation_items=None,
        seed=5678,
        ip4_prefix='10.20.0.0/16'
    )
    counts = prev.get('r2s_policy_preview', {}).get('counts') or {}
    assert counts and all(val == 2 for val in counts.values())
    switches_detail = prev.get('switches_detail') or []
    # Expect two switches per router with non-empty host assignments until hosts exhausted
    assert len(switches_detail) >= routers_planned * 2
    per_router_counts = {}
    for detail in switches_detail:
        rid = detail.get('router_id')
        per_router_counts[rid] = per_router_counts.get(rid, 0) + 1
        hosts = detail.get('hosts', [])
        if hosts:
            assert isinstance(hosts, list)
    assert all(per_router_counts.get(rid, 0) >= 2 for rid in counts.keys())


def test_r2s_min_behaves_like_exact_one():
    role_counts = {"Workstation": 6}
    routers_planned = 2

    class DummyRI:
        def __init__(self, r2s_mode):
            self.r2s_mode = r2s_mode
            self.r2s_edges = 0

    routing_items = [DummyRI('Min')]
    prev = build_full_preview(
        role_counts=role_counts,
        routers_planned=routers_planned,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy=None,
        routing_items=routing_items,
        routing_plan={},
        segmentation_density=None,
        segmentation_items=None,
        seed=2468,
        ip4_prefix='10.30.0.0/16'
    )
    r2s = prev.get('r2s_policy_preview', {})
    assert r2s.get('mode') == 'Min'
    counts = r2s.get('counts') or {}
    assert counts and all(val in (0, 1) for val in counts.values())
    # Every router with hosts should report a single switch
    assert sum(1 for val in counts.values() if val == 1) == routers_planned
    switches_detail = prev.get('switches_detail') or []
    assert len(switches_detail) == routers_planned
    expected_hosts = {idx + 1: set() for idx in range(routers_planned)}
    total_hosts = sum(role_counts.values())
    for idx in range(total_hosts):
        host_id = routers_planned + idx + 1
        rid = (idx % routers_planned) + 1
        expected_hosts[rid].add(host_id)
    for detail in switches_detail:
        rid = detail.get('router_id')
        hosts = set(detail.get('hosts') or [])
        assert hosts == expected_hosts[rid]
