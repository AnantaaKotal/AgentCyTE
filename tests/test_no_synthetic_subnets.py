from core_topo_gen.planning.router_host_plan import plan_r2s_grouping, plan_host_router_mapping

class DummyRoutingItem:
    def __init__(self, r2s_mode='Exact', r2s_edges=1):
        self.r2s_mode = r2s_mode
        self.r2s_edges = r2s_edges
        self.abs_count = 0
        self.factor = 0.0

class DummyHost:
    def __init__(self, node_id):
        self.node_id = node_id


def test_grouping_no_legacy_synthetic_subnets():
    routers = 2
    role_counts = {'Host':4}
    host_router_map = {i+1: (i % routers)+1 for i in range(4)}
    hosts = [DummyHost(i+1) for i in range(4)]
    out = plan_r2s_grouping(routers, host_router_map, hosts, routing_items=[DummyRoutingItem()], r2s_policy={'mode':'Exact','target_per_router':1}, seed=1234)
    for subnet in out['router_switch_subnets'] + out['lan_subnets']:
        assert not subnet.startswith('10.254.'), f"Found legacy synthetic subnet {subnet}"
        assert not subnet.startswith('10.253.'), f"Found legacy synthetic subnet {subnet}"


def test_preview_host_roles_not_random():
    # Build a minimal preview directly via build_full_preview to ensure roles sanitized
    from core_topo_gen.planning.full_preview import build_full_preview
    role_counts = {'Random': 3}
    prev = build_full_preview(role_counts=role_counts, routers_planned=1, services_plan={}, vulnerabilities_plan={}, r2r_policy=None, r2s_policy={'mode':'Exact','target_per_router':1}, routing_items=None, routing_plan={}, segmentation_density=0.0, segmentation_items=[], traffic_plan=None, seed=99, ip4_prefix='10.1.0.0/16')
    # In full_preview we currently raise if 'Random' is unresolved in services/vulns/etc., but role label 'Random' is allowed earlier.
    # Ensure that resulting hosts either do not contain 'Random' or are all labeled generically.
    assert all(h['role'].lower() != 'random' for h in prev['hosts']), f"Unexpected Random role leakage: {prev['hosts']}"
