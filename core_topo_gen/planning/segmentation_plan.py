from __future__ import annotations
from typing import List, Dict

class SegmentationItem:
    def __init__(self, name: str, factor: float):
        self.name = name
        self.factor = factor

def compute_segmentation_plan(seg_density: float, seg_items: List[SegmentationItem], base_host_pool: int) -> tuple[Dict[str,int], dict]:
    """Compute segmentation service slot plan using proportional distribution.

    Enhancements:
    - Resolves placeholder items whose name is 'Random' (case-insensitive) into concrete
      segmentation kinds (Firewall, NAT, CUSTOM) by splitting the factor proportionally.
    - Keeps original items list for backward compatibility while exposing an expanded list.

    Density fraction applies to base_host_pool; result floored; residual distributed deterministically
    via largest fractional remainder allocation (same pattern used in other planners).
    """
    import math as _math

    # Preserve original specification for downstream consumers/tests
    original_items_repr = [{'name': it.name, 'factor': it.factor} for it in seg_items]

    # Expand any 'Random' placeholders into concrete kinds
    expanded: List[SegmentationItem] = []
    default_kinds = ['Firewall', 'NAT', 'CUSTOM']
    for it in seg_items:
        if (it.name or '').strip().lower() == 'random':
            # Split factor evenly across defaults (previous preview semantics)
            if it.factor > 0 and default_kinds:
                share = it.factor / len(default_kinds)
            else:
                # Factor 0 means no weight contribution (retain zeros for transparency)
                share = 0.0
            for k in default_kinds:
                expanded.append(SegmentationItem(k, share))
        else:
            expanded.append(it)

    d = max(0.0, min(1.0, float(seg_density or 0.0)))
    has_weight_items = any((getattr(it, 'factor', 0.0) or 0.0) > 0 and (getattr(it, 'abs_count', 0) or 0) <= 0 for it in seg_items)
    raw_slots = d * (base_host_pool or 0) if has_weight_items else 0.0
    total_slots = int(_math.floor(raw_slots + 1e-9)) if has_weight_items else 0
    factors_sum = sum(it.factor for it in expanded) or 0.0
    plan: Dict[str,int] = {}
    if total_slots > 0 and factors_sum > 0 and has_weight_items:
        provisional = []
        residual = total_slots
        for it in expanded:
            share = (it.factor / factors_sum) * total_slots if factors_sum > 0 else 0
            alloc = int(_math.floor(share + 1e-9))
            provisional.append((it.name, share, alloc))
            residual -= alloc
        if residual > 0 and provisional:
            frac_sorted = sorted(provisional, key=lambda x: (x[1]-x[2]), reverse=True)
            for i in range(residual):
                n, sshare, a = frac_sorted[i % len(frac_sorted)]
                frac_sorted[i % len(frac_sorted)] = (n, sshare, a+1)  # type: ignore
            provisional = frac_sorted
        for n, _, a in provisional:
            if a > 0:
                plan[n] = plan.get(n, 0) + a
    breakdown = {
        'density': d,
        'raw_slots': raw_slots,
        'slots': total_slots,
        'weight_items_present': has_weight_items,
        # Backward-compatible original items list
        'items': original_items_repr,
        # New expanded representation actually used for allocation
        'expanded_items': [{'name': it.name, 'factor': it.factor} for it in expanded],
        'expanded_random_defaults': default_kinds,
    }
    return plan, breakdown
