from core_topo_gen.planning.router_plan import compute_router_plan
from core_topo_gen.types import RoutingInfo


def test_density_suppressed_when_only_count_based():
    # Provide a high density that should be ignored because only abs_count items exist.
    routing_density = 0.95
    total_hosts = 100
    base_host_pool = 80
    # Only count-based routing items (factor should be zero, abs_count > 0)
    items = [
        RoutingInfo(protocol="OSPF", factor=0.0, abs_count=3),
        RoutingInfo(protocol="BGP", factor=0.0, abs_count=2),
    ]
    router_count, breakdown = compute_router_plan(
        total_hosts=total_hosts,
        base_host_pool=base_host_pool,
        routing_density=routing_density,
        routing_items=items,
    )
    assert router_count == 5, "Density should not add routers when only count-based items are present"
    assert breakdown["density_component"] == 0, "Density component must be zero for count-only routing"
    assert breakdown["count_based_component"] == 5
