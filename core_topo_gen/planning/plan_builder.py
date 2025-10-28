from __future__ import annotations
from typing import Dict, List
from .pool import AllocationPool

def build_initial_pool(role_counts: Dict[str, int], router_count: int, service_plan: Dict[str, int], routing_plan: Dict[str, int], router_breakdown: Dict | None = None, r2r_policy: Dict[str, int] | None = None, vulnerabilities_plan: Dict[str, int] | None = None) -> AllocationPool:
    total_hosts = sum(role_counts.values())
    pool = AllocationPool(
        hosts_total=total_hosts,
        role_counts=role_counts,
        routers_planned=router_count,
        services_plan=service_plan,
        routing_plan=routing_plan,
        r2r_policy=r2r_policy,
        vulnerabilities_plan=vulnerabilities_plan,
    )
    if router_breakdown:
        pool.notes.append(f"router_plan: {router_breakdown}")
    return pool
