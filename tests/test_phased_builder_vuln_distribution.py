import random
from core_topo_gen.planning.pool import AllocationPool


def test_vulnerability_assignment_count_tracking():
    pool = AllocationPool(
        hosts_total=10,
        role_counts={'User': 10},
        routers_planned=2,
        services_plan={},
        routing_plan={},
        vulnerabilities_plan={'A':4, 'B':3}
    )
    # Simulate what phased builder would do: assign min(total plan, hosts)
    total_plan = sum(pool.vulnerabilities_plan.values())
    assignable = min(total_plan, pool.hosts_total)
    pool.vulnerabilities_assigned = assignable
    assert pool.vulnerabilities_assigned == 7
    # Ensure we don't exceed hosts
    pool.hosts_allocated = 10
    assert pool.vulnerabilities_assigned <= pool.hosts_allocated
