from core_topo_gen.planning.router_host_plan import plan_router_counts


def test_plan_router_counts_density_only():
    rc = {'Server': 10, 'PC': 5}
    # One weight-based item (factor>0, abs_count=0) to activate density
    class R: pass
    r = R(); r.abs_count = 0; r.factor = 0.5
    stats = plan_router_counts(rc, routing_density=0.2, routing_items=[r], base_host_pool=15)
    # 0.2 * 15 = 3 (floor) routers expected
    assert stats['router_count'] == 3
    assert stats['density_router_count'] == 3


def test_plan_router_counts_count_only():
    rc = {'Server': 8}
    class R: pass
    r1 = R(); r1.abs_count = 2; r1.factor = 0.0
    r2 = R(); r2.abs_count = 1; r2.factor = 0.0
    stats = plan_router_counts(rc, routing_density=0.9, routing_items=[r1, r2], base_host_pool=8)
    # No weight-based items -> density ignored -> 3 routers (count sum)
    assert stats['router_count'] == 3
    assert stats['density_router_count'] == 0


def test_plan_router_counts_preview_override_removed():
    rc = {'Server': 5}
    class R: pass
    r1 = R(); r1.abs_count = 1; r1.factor = 0.0
    stats = plan_router_counts(rc, routing_density=0.5, routing_items=[r1], base_host_pool=5)
    # With approval removed, router count should remain the declared count (1)
    assert stats['router_count'] == 1
    # preview_router_override field removed; ensure no unexpected fields appear
    assert 'preview_router_override' not in stats


def test_plan_router_counts_zero_hosts():
    rc = {}
    class R: pass
    r = R(); r.abs_count = 3; r.factor = 0.0
    stats = plan_router_counts(rc, routing_density=0.5, routing_items=[r], base_host_pool=0)
    # Cannot exceed total_hosts=0
    assert stats['router_count'] == 0