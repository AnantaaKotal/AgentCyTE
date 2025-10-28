from __future__ import annotations
from typing import List, Dict

class ServiceSpec:
    def __init__(self, name: str, density: float = 0.0, abs_count: int = 0):
        self.name = name
        self.density = density
        self.abs_count = abs_count

def compute_service_plan(services: List[ServiceSpec], base_host_pool: int) -> tuple[Dict[str,int], dict]:
    """Compute service activation counts with Random placeholder expansion.

    Enhancements:
    - Service name 'Random' splits its density or abs_count evenly across DEFAULT_RANDOM_SERVICES.
    - Multiple Random entries aggregate before splitting.
    - Preserves original semantics for non-Random services.
    """
    import math as _math
    # Web UI enumeration (excluding 'Random'): ["SSH", "HTTP", "DHCPClient", "Random"]
    DEFAULT_RANDOM_SERVICES = ["SSH", "HTTP", "DHCPClient"]

    # Aggregate Random placeholders
    aggregated_density = 0.0
    aggregated_abs = 0
    normalized: List[ServiceSpec] = []
    for s in services:
        if s.name.strip().lower() == 'random':
            if s.abs_count and s.abs_count > 0:
                aggregated_abs += int(s.abs_count)
            else:
                aggregated_density += float(s.density or 0.0)
        else:
            normalized.append(s)
    if aggregated_density > 0 or aggregated_abs > 0:
        # Translate aggregated density into per-default density (same fraction); derived will scale by base_host_pool.
        # If both abs and density present, both are applied proportionally across defaults.
        per_density = aggregated_density
        # We keep density same for each default to mimic original semantics: one Random line with density d
        # becomes N lines each with density d / N? Decide: use equal split to keep total bounded.
        # To conserve total, we split: total effect must remain d * base_host_pool. So per item density = aggregated_density / len(defaults)
        if aggregated_density > 0:
            per_density = aggregated_density / len(DEFAULT_RANDOM_SERVICES)
        base_abs_each = aggregated_abs // len(DEFAULT_RANDOM_SERVICES) if aggregated_abs > 0 else 0
        residual_abs = aggregated_abs - base_abs_each * len(DEFAULT_RANDOM_SERVICES)
        for idx, name in enumerate(DEFAULT_RANDOM_SERVICES):
            abs_for = base_abs_each + (1 if idx < residual_abs else 0)
            normalized.append(ServiceSpec(name=name, density=per_density, abs_count=abs_for))

    plan: Dict[str,int] = {}
    meta: Dict[str,dict] = {}
    for s in normalized:
        if s.abs_count and s.abs_count > 0:
            plan[s.name] = plan.get(s.name, 0) + int(s.abs_count)
            meta[s.name] = {'mode': 'abs', 'value': int(s.abs_count)}
        else:
            d = max(0.0, min(1.0, float(s.density or 0.0)))
            derived = int(_math.floor(d * (base_host_pool or 0) + 1e-9))
            if derived > 0:
                plan[s.name] = plan.get(s.name, 0) + derived
            meta[s.name] = {'mode': 'density', 'density': d, 'derived': derived}
    breakdown = {
        'base_host_pool': base_host_pool,
        'services_total': sum(plan.values()),
        'services': meta,
        'random_defaults': DEFAULT_RANDOM_SERVICES,
        'random_density_aggregated': aggregated_density,
        'random_abs_aggregated': aggregated_abs,
    }
    return plan, breakdown
