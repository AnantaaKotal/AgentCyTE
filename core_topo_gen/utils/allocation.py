from __future__ import annotations
import math
from typing import Dict, List, Tuple


def compute_role_counts(total: int, role_factors: List[Tuple[str, float]]) -> Dict[str, int]:
    non_random = [(r, f) for r, f in role_factors if r.lower() != "random"]
    if not non_random:
        return {"Workstation": total}
    exacts = [(r, f * total) for r, f in non_random]
    counts = {r: math.floor(x) for r, x in exacts}
    remaining = total - sum(counts.values())
    remainders = sorted(((r, x - math.floor(x)) for r, x in exacts), key=lambda t: t[1], reverse=True)
    i = 0
    while remaining > 0 and i < len(remainders):
        r, _ = remainders[i]
        counts[r] += 1
        remaining -= 1
        i += 1
    remaining = total - sum(counts.values())
    if remaining > 0:
        labels = [r for r, _ in non_random]
        for j in range(remaining):
            counts[labels[j % len(labels)]] += 1
    return counts


def compute_counts_by_factor(total: int, items: List[Tuple[str, float]]) -> Dict[str, int]:
    if total <= 0 or not items:
        return {}
    exacts = [(name, f * total) for name, f in items]
    counts = {name: math.floor(x) for name, x in exacts}
    remaining = total - sum(counts.values())
    remainders = sorted(((name, x - math.floor(x)) for name, x in exacts), key=lambda t: t[1], reverse=True)
    i = 0
    while remaining > 0 and i < len(remainders):
        name, _ = remainders[i]
        counts[name] += 1
        remaining -= 1
        i += 1
    return counts
