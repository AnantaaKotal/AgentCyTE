from core_topo_gen.planning.full_preview import build_full_preview

class DummyRI:
    def __init__(self, r2s_mode: str = 'Random', r2s_edges: int = 0, r2s_hosts_min: int = 0, r2s_hosts_max: int = 0):
        self.r2s_mode = r2s_mode
        self.r2s_edges = r2s_edges
        self.r2s_hosts_min = r2s_hosts_min
        self.r2s_hosts_max = r2s_hosts_max

def test_preview_host_group_bounds_summary_present():
    role_counts = {"Workstation": 12}
    routers_planned = 3
    routing_items = [DummyRI('Random', 0, 2, 3)]
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
        seed=999,
        ip4_prefix='10.50.0.0/16'
    )
    r2s = prev.get('r2s_policy_preview', {})
    bounds = r2s.get('host_group_bounds')
    assert bounds and bounds.get('effective_min') == 2 and bounds.get('effective_max') == 3

def test_preview_exact_one_respects_single_switch():
    role_counts = {"Workstation": 9}
    routers_planned = 3
    routing_items = [DummyRI('Exact', 1, 2, 4)]
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
        seed=321,
        ip4_prefix='10.60.0.0/16'
    )
    r2s = prev.get('r2s_policy_preview', {})
    counts = r2s.get('counts') or {}
    assert counts and all(v == 1 for v in counts.values())
    # Ensure switches_detail lists each router's hosts aggregated (3 each)
    details = prev.get('switches_detail') or []
    assert len(details) == 3
    sizes = sorted(len(d.get('hosts', [])) for d in details)
    assert sizes == [3,3,3]
