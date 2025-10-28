from core_topo_gen.planning.full_preview import build_full_preview

class DummyRI:
    def __init__(self, r2s_mode, r2s_edges):
        self.r2s_mode = r2s_mode
        self.r2s_edges = r2s_edges


def test_r2s_exact_one_count_only_generates_switches():
    # Simulate 3 routers added purely via count items (abs count routing)
    routers_planned = 3
    # 9 hosts across any roles
    role_counts = {"Workstation": 9}
    routing_items = [DummyRI('Exact', 1)]  # Count-based item with Exact=1 semantics
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
        seed=4321,
        ip4_prefix='10.20.0.0/16'
    )
    r2s = prev.get('r2s_policy_preview', {})
    assert r2s.get('mode') == 'Exact'
    counts = r2s.get('counts') or {}
    # Expect a single aggregated switch per router
    assert counts and all(v == 1 for v in counts.values())
    switches = prev.get('switches_detail') or []
    assert len(switches) == routers_planned
    # Each switch should have 3 hosts (9 total hosts / 3 routers)
    host_total = 0
    for rec in switches:
        host_list = rec.get('hosts', [])
        host_total += len(host_list)
        assert len(host_list) == 3
    assert host_total == 9
