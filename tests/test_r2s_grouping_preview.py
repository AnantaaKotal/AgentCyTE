from core_topo_gen.planning.full_preview import build_full_preview

class DummyRI:
    def __init__(self, protocol: str, mode: str, hmin: int, hmax: int):
        self.protocol = protocol
        self.r2s_mode = mode
        self.r2s_edges = 0
        self.r2s_hosts_min = hmin
        self.r2s_hosts_max = hmax
        self.abs_count = 0

def test_grouping_preview_per_router_bounds_and_groups():
    role_counts = {"Workstation": 16}
    routers_planned = 4
    # Provide four routing items with different bounds; last repeats first to ensure assignment fills
    routing_items = [
        DummyRI('OSPF','Random',2,3),
        DummyRI('BGP','Random',3,5),
        DummyRI('RIP','Random',1,2),
        DummyRI('EIGRP','Random',4,4),
    ]
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
        seed=777,
        ip4_prefix='10.70.0.0/16'
    )
    gp = prev.get('r2s_grouping_preview')
    assert gp and len(gp) == routers_planned
    # Ensure per-router bounds echoed
    rid_to_bounds = {rec['router_id']: rec['bounds'] for rec in gp}
    assert rid_to_bounds[1]['min'] == 2 and rid_to_bounds[1]['max'] == 3
    assert rid_to_bounds[2]['min'] == 3 and rid_to_bounds[2]['max'] == 5
    assert rid_to_bounds[3]['min'] == 1 and rid_to_bounds[3]['max'] == 2
    assert rid_to_bounds[4]['min'] == 4 and rid_to_bounds[4]['max'] == 4
    # Check group sizes respect bounds
    for rec in gp:
        bmin = rec['bounds']['min'] or 1
        bmax = rec['bounds']['max'] or 10**6
        for sz in rec['group_sizes']:
            assert bmin <= sz <= bmax


def test_nonuniform_switch_counts_are_unique():
    role_counts = {"Workstation": 18}
    routers_planned = 3
    routing_items = [DummyRI('OSPF', 'NonUniform', 0, 8)]
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
        seed=4242,
        ip4_prefix='10.80.0.0/16'
    )
    counts = prev.get('r2s_policy_preview', {}).get('counts') or {}
    assert len(counts) == routers_planned
    non_zero_counts = [val for val in counts.values() if val > 0]
    assert non_zero_counts and len(non_zero_counts) == routers_planned
    assert len(set(non_zero_counts)) == len(non_zero_counts)
    assert sorted(non_zero_counts) == [1, 2, 3]
    switches_detail = prev.get('switches_detail') or []
    per_router_counts = {}
    for detail in switches_detail:
        rid = detail.get('router_id')
        per_router_counts[rid] = per_router_counts.get(rid, 0) + 1
    assert sorted(per_router_counts.values()) == [1, 2, 3]
