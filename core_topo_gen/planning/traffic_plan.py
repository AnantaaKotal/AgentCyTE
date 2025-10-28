from __future__ import annotations
from typing import List, Dict

class TrafficItem:
    def __init__(self, pattern: str = 'continuous', rate_kbps: int | None = None, factor: float = 1.0, content: str | None = None, kind: str | None = None, abs_count: int = 0):
        self.pattern = pattern
        self.rate_kbps = rate_kbps
        self.factor = factor
        self.content = content or 'text'
        self.kind = kind or 'Random'
        self.abs_count = abs_count or 0

def compute_traffic_plan(items: List[TrafficItem], default_rate_kbps: int = 128) -> tuple[list[dict], dict]:
    """Normalize and expand traffic items.

    Enhancements:
    - Resolves 'Random' kind into UI enumerated kinds: ["TCP", "UDP", "CUSTOM"].
      Aggregates factors and abs_counts before splitting evenly (largest remainder for counts).
    - Ensures each expanded item has concrete rate_kbps and content value.
    """
    DEFAULT_RANDOM_KINDS = ["TCP", "UDP", "CUSTOM"]
    agg_factor = 0.0
    agg_abs = 0
    passthrough: List[TrafficItem] = []
    for it in items:
        k = (getattr(it, 'kind', 'Random') or 'Random').strip().lower()
        if k == 'random':
            if getattr(it, 'abs_count', 0) > 0:
                agg_abs += int(getattr(it, 'abs_count'))
            else:
                agg_factor += float(getattr(it, 'factor', 0.0) or 0.0)
        else:
            passthrough.append(it)
    # Expand aggregated Random placeholders
    expanded: List[TrafficItem] = list(passthrough)
    if agg_factor > 0 or agg_abs > 0:
        per_factor = agg_factor / len(DEFAULT_RANDOM_KINDS) if agg_factor > 0 else 0.0
        base_abs_each = agg_abs // len(DEFAULT_RANDOM_KINDS) if agg_abs > 0 else 0
        residual_abs = agg_abs - base_abs_each * len(DEFAULT_RANDOM_KINDS)
        for idx, k in enumerate(DEFAULT_RANDOM_KINDS):
            abs_c = base_abs_each + (1 if idx < residual_abs else 0)
            expanded.append(TrafficItem(
                pattern='continuous',  # default pattern (UI sets individually post-expansion if needed)
                rate_kbps=None,
                factor=per_factor,
                content='text',
                kind=k,
                abs_count=abs_c,
            ))

    norm: list[dict] = []
    for it in expanded:
        rate = it.rate_kbps if (it.rate_kbps and it.rate_kbps > 0) else default_rate_kbps
        norm.append({
            'kind': it.kind,
            'pattern': it.pattern,
            'rate_kbps': rate,
            'factor': it.factor,
            'content': it.content,
            'abs_count': it.abs_count,
        })
    breakdown: Dict[str, object] = {
        'count': len(norm),
        'default_rate_kbps': default_rate_kbps,
        'random_factor_aggregated': agg_factor,
        'random_abs_aggregated': agg_abs,
        'random_defaults': DEFAULT_RANDOM_KINDS,
    }
    return norm, breakdown
