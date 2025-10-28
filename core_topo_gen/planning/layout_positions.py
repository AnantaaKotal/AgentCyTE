from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Tuple

MAX_DIM_DEFAULT = 2000
_MIN_MARGIN = 60
_SWITCH_RING_STEP = 90
_HOST_RING_STEP = 60
_DIRECT_HOST_STEP = 70


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _clamp(value: float, max_dim: int) -> int:
    return max(_MIN_MARGIN, min(max_dim - _MIN_MARGIN, int(round(value))))


def _sorted_node_ids(nodes: Iterable[Dict[str, Any]]) -> List[int]:
    ids: List[int] = []
    for node in nodes or []:
        nid = _coerce_int(node.get("node_id")) if isinstance(node, dict) else None
        if not nid:
            try:
                nid = _coerce_int(getattr(node, "node_id", None))
            except Exception:
                nid = None
        if nid is not None and nid not in ids:
            ids.append(nid)
    return sorted(ids)


def _fan_offsets(count: int, base_radius: float, step: float) -> List[Tuple[float, float]]:
    if count <= 0:
        return []
    positions: List[Tuple[float, float]] = []
    remaining = count
    ring = 0
    placed = 0
    while remaining > 0:
        radius = max(10.0, base_radius + ring * step)
        ring_capacity = max(4, int(round(2 * math.pi * radius / 160)))
        ring_capacity = max(4, ring_capacity)
        items_this_ring = min(remaining, ring_capacity)
        for idx in range(items_this_ring):
            angle = (2 * math.pi * idx) / items_this_ring
            positions.append((radius * math.cos(angle), radius * math.sin(angle)))
        placed += items_this_ring
        remaining -= items_this_ring
        ring += 1
    return positions[:count]


def compute_clustered_layout(preview_plan: Dict[str, Any], max_dim: int = MAX_DIM_DEFAULT) -> Dict[str, Dict[str, Dict[str, int]]]:
    """Compute clustered layout positions for preview graphs and CORE placement.

    The layout groups subnetworks (routers, switches, hosts) together and caps
    all coordinates to fit inside a ``max_dim`` square (default 2000x2000).

    Returns a nested mapping keyed by node type (routers, switches, hosts) with
    stringified node IDs mapped to ``{"x": int, "y": int}`` coordinate dicts.
    """

    max_dim = max(400, int(max_dim) if max_dim else MAX_DIM_DEFAULT)

    routers = preview_plan.get("routers") or []
    hosts = preview_plan.get("hosts") or []
    switches_detail = preview_plan.get("switches_detail") or []
    host_router_map = preview_plan.get("host_router_map") or {}

    router_ids = _sorted_node_ids(routers)
    host_ids = _sorted_node_ids(hosts)

    host_router: Dict[int, int] = {}
    for key, val in (host_router_map or {}).items():
        hid = _coerce_int(key)
        rid = _coerce_int(val)
        if hid:
            host_router[hid] = rid

    switch_hosts: Dict[int, List[int]] = {}
    router_switches: Dict[int, List[int]] = {}
    for detail in switches_detail:
        sid = _coerce_int(detail.get("switch_id"))
        rid = _coerce_int(detail.get("router_id"))
        if not sid:
            continue
        router_switches.setdefault(rid, []).append(sid)
        hosts_raw = detail.get("hosts") or []
        host_list: List[int] = []
        for h in hosts_raw:
            hid = _coerce_int(h)
            if hid:
                host_list.append(hid)
        if host_list:
            switch_hosts[sid] = host_list

    # Grid placement for router centers
    router_positions: Dict[int, Tuple[int, int]] = {}
    switch_positions: Dict[int, Tuple[int, int]] = {}
    host_positions: Dict[int, Tuple[int, int]] = {}

    if router_ids:
        cols = max(1, int(math.ceil(math.sqrt(len(router_ids)))))
        rows = int(math.ceil(len(router_ids) / cols))
        cell_w = max_dim / cols
        cell_h = max_dim / rows
        half_w = cell_w / 2.0
        half_h = cell_h / 2.0
        max_cluster_radius = max(80.0, min(half_w, half_h) - _MIN_MARGIN)
        switch_base_radius = min(max_cluster_radius, max(110.0, max_cluster_radius * 0.7))
        host_base_radius = max(50.0, switch_base_radius * 0.55)
        direct_host_base_radius = min(max_cluster_radius, max(70.0, max_cluster_radius * 0.65))

        for idx, rid in enumerate(router_ids):
            row = idx // cols
            col = idx % cols
            base_x = (col * cell_w) + half_w
            base_y = (row * cell_h) + half_h
            clamped_base = (_clamp(base_x, max_dim), _clamp(base_y, max_dim))
            router_positions[rid] = clamped_base

            switches_for_router = router_switches.get(rid, [])
            if switches_for_router:
                switch_offsets = _fan_offsets(len(switches_for_router), switch_base_radius, _SWITCH_RING_STEP)
                for sid, offset in zip(switches_for_router, switch_offsets):
                    sx = _clamp(base_x + offset[0], max_dim)
                    sy = _clamp(base_y + offset[1], max_dim)
                    switch_positions[sid] = (sx, sy)
                    host_list = switch_hosts.get(sid, [])
                    if host_list:
                        host_offsets = _fan_offsets(len(host_list), host_base_radius, _HOST_RING_STEP)
                        for hid, hoffset in zip(host_list, host_offsets):
                            hx = _clamp(sx + hoffset[0], max_dim)
                            hy = _clamp(sy + hoffset[1], max_dim)
                            host_positions[hid] = (hx, hy)

            # Direct hosts (not assigned via switches)
            direct_hosts = [hid for hid in host_ids if host_router.get(hid) == rid and hid not in host_positions]
            if direct_hosts:
                direct_offsets = _fan_offsets(len(direct_hosts), direct_host_base_radius, _DIRECT_HOST_STEP)
                for hid, doffset in zip(direct_hosts, direct_offsets):
                    hx = _clamp(base_x + doffset[0], max_dim)
                    hy = _clamp(base_y + doffset[1], max_dim)
                    host_positions[hid] = (hx, hy)

    # Hosts that remain unplaced (e.g., due to missing router) – place on fallback grid
    if host_ids:
        fallback_idx = 0
        fallback_cols = max(1, int(math.ceil(math.sqrt(len(host_ids)))))
        spacing = max(140, int(max_dim / (fallback_cols + 1)))
        for hid in host_ids:
            if hid in host_positions:
                continue
            row = fallback_idx // fallback_cols
            col = fallback_idx % fallback_cols
            hx = _clamp((col + 1) * spacing, max_dim)
            hy = _clamp((row + 1) * spacing, max_dim)
            host_positions[hid] = (hx, hy)
            fallback_idx += 1

    result = {
        'routers': {str(rid): {'x': x, 'y': y} for rid, (x, y) in router_positions.items()},
        'switches': {str(sid): {'x': x, 'y': y} for sid, (x, y) in switch_positions.items()},
        'hosts': {str(hid): {'x': x, 'y': y} for hid, (x, y) in host_positions.items()},
    }
    return result


__all__ = [
    'compute_clustered_layout',
]
