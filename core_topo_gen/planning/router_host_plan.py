from __future__ import annotations
"""Pure planning helpers for router count derivation (preview + builder reuse).

This module extracts the deterministic parts of router planning logic from
`builders.topology.build_segmented_topology` so that preview generation and
runtime builders share a single source of truth for how many routers to create.

The builder previously embedded this logic inline. We now expose:
  plan_router_counts(...): returns a dictionary of router planning stats.

Notes:
    - `base_host_pool` should be the density base (i.e., hosts eligible for density-based
        router derivation). When not known, callers may pass total hosts; results will still
        be consistent with current heuristic.
"""
from typing import Dict, Any, List, Optional
import random
import ipaddress
import math
from ..utils.allocators import make_subnet_allocator

def _expand_roles(role_counts: Dict[str, int]) -> List[str]:
    out: List[str] = []
    for r, c in role_counts.items():
        out.extend([r] * int(c))
    return out

def plan_host_router_mapping(role_counts: Dict[str,int], routers_planned: int) -> Dict[int,int]:
    """Deterministically assign each host (by sequential index) to a router (round-robin)."""
    host_router_map: Dict[int,int] = {}
    expanded = _expand_roles(role_counts)
    for idx,_role in enumerate(expanded):
        host_id = routers_planned + idx + 1
        if routers_planned > 0:
            rid = (idx % routers_planned) + 1
        else:
            rid = 0
        host_router_map[host_id] = rid
    return host_router_map

def _distribute_exact_groups(
    host_ids: List[int],
    groups_desired: int,
    min_hosts: Optional[int],
    max_hosts: Optional[int],
) -> List[List[int]]:
    """Split host_ids into exactly groups_desired buckets.

    The distribution attempts to respect provided bounds when feasible. When
    bounds cannot be satisfied (insufficient hosts, inconsistent min/max), the
    method relaxes toward evenly sized groups while still returning the exact
    number of buckets. Remaining hosts are allocated round-robin. Empty buckets
    are allowed when there are fewer hosts than requested groups."""

    groups_desired = max(1, int(groups_desired))
    groups: List[List[int]] = [[] for _ in range(groups_desired)]
    if not host_ids:
        return groups

    host_queue = list(host_ids)
    eff_min = min_hosts if (isinstance(min_hosts, int) and min_hosts > 0) else 1
    eff_max = max_hosts if (isinstance(max_hosts, int) and max_hosts > 0) else None
    if eff_max is not None and eff_max < eff_min:
        eff_max = eff_min

    total_hosts = len(host_queue)
    if total_hosts < groups_desired * eff_min:
        # Relax minimum bound while keeping at least one host per bucket when possible
        if total_hosts >= groups_desired:
            eff_min = 1
        else:
            eff_min = 0

    # Seed each group with the relaxed minimum requirement
    for idx in range(groups_desired):
        if not host_queue:
            break
        take = min(eff_min, len(host_queue)) if eff_min > 0 else 0
        if take > 0:
            groups[idx].extend(host_queue[:take])
            del host_queue[:take]

    # Evenly distribute remaining hosts while honoring max bounds where possible
    if host_queue:
        g_idx = 0
        safety = 0
        while host_queue and safety < groups_desired * 8:
            group = groups[g_idx % groups_desired]
            if eff_max is not None and len(group) >= eff_max:
                g_idx += 1
                safety += 1
                continue
            group.append(host_queue.pop(0))
            g_idx += 1
            safety += 1
        # If hosts remain because every bucket is saturated by max bounds, append remainder to last bucket
        if host_queue:
            groups[-1].extend(host_queue)

    return groups


def plan_r2s_grouping(
    routers_planned: int,
    host_router_map: Dict[int,int],
    host_nodes: List[Any],  # objects with node_id
    routing_items: Optional[List[Any]],
    r2s_policy: Optional[Dict[str, Any]],
    seed: int,
    ip4_prefix: str | None = None,
    ip_mode: str | None = None,
    ip_region: str | None = None,
) -> Dict[str, Any]:
    """Replica of grouping logic from full_preview, returned as a structured dict.

    Returned keys: grouping_preview, computed_r2s_policy, switch_nodes, switches_detail,
    ptp_subnets, router_switch_subnets, lan_subnets
    """
    router_nodes = [{'node_id': i+1} for i in range(routers_planned)]
    total_hosts = len(host_nodes)
    # Host list by router
    hosts_by_router: Dict[int, List[int]] = {r['node_id']: [] for r in router_nodes}
    for hid, rid in host_router_map.items():
        if rid in hosts_by_router:
            hosts_by_router[rid].append(hid)
    # Adopt policy
    target_per_router = (r2s_policy or {}).get('target_per_router') if r2s_policy else None
    mode_rs = (r2s_policy or {}).get('mode') if r2s_policy else None
    mode_rs = mode_rs if mode_rs else 'ratio'
    mode_lower = str(mode_rs).strip().lower()
    effective_mode = mode_lower
    derived_effective_target: Optional[int] = None
    if effective_mode == 'min':
        target_per_router = 1
        derived_effective_target = 1
        effective_mode = 'exact'
    # Assign routing items to routers (simple round-robin with abs_count expansions)
    def _assign_items(items: Optional[List[Any]], count: int):
        if not items or count<=0:
            return [None]*count
        expanded: List[Any] = []
        for it in items:
            try:
                ac = int(getattr(it,'abs_count',0) or 0)
            except Exception:
                ac = 0
            if ac>0:
                expanded.extend([it]*ac)
        if len(expanded) < count:
            idx=0
            while len(expanded) < count:
                expanded.append(items[idx % len(items)])
                idx+=1
        return expanded[:count]
    item_assignment = _assign_items(routing_items, routers_planned)
    grouping_preview: List[Dict[str, Any]] = []
    r2s_counts: Dict[int,int] = {r['node_id']: 0 for r in router_nodes}
    r2s_host_pairs_possible: Dict[int,int] = {}
    r2s_host_pairs_used: Dict[int,int] = {}
    r2s_unmet: Dict[int,int] = {}
    per_router_bounds: Dict[int, Dict[str, Optional[int]]] = {}
    switch_nodes: List[Dict[str,Any]] = []
    switches_detail: List[Dict[str,Any]] = []
    router_switch_subnets: List[str] = []  # /30 subnets for each router<->switch link
    lan_subnets: List[str] = []
    ptp_subnets: List[str] = []
    r2r_subnets: List[str] = []  # /30 subnets for router<->router links (preview purpose)
    next_switch_id = routers_planned + total_hosts + 1
    # Derive target if Exact but unspecified
    if effective_mode == 'exact' and (target_per_router is None):
        for it in (routing_items or []):
            try:
                ev = int(getattr(it,'r2s_edges',0) or 0)
            except Exception:
                ev = 0
            if ev>0:
                target_per_router = ev
                derived_effective_target = ev
                break
        if target_per_router is None:
            target_per_router = 1
            derived_effective_target = 1
    # Prepare allocator for realistic subnet assignment (optional)
    subnet_alloc = None
    try:
        # Provide a deterministic default pool if caller omitted prefix (tests often do)
        eff_prefix = ip4_prefix or '10.200.0.0/15'
        subnet_alloc = make_subnet_allocator(ip_mode or 'private', eff_prefix, ip_region or 'all')
    except Exception:
        subnet_alloc = None

    def _lan_prefix_for_hosts(host_count: int, reserve: int = 2, max_prefix: int = 24) -> int:
        """Return the smallest prefix length that can fit host_count plus reserve with 25% headroom.

        headroom factor: we inflate required hosts by 1.25 (ceil) so that modest future growth
        or service IPs can be added without immediate reallocation.

        We cap expansion at /24 (prefixlen <= 24). We never go beyond /24 to keep address blocks
        reasonably sized and routing table compact.
        """
        if host_count <= 0:
            return 30  # degenerate tiny case
        needed = int((host_count + reserve) * 1.25 + 0.9999)  # ceil((hosts+reserve)*1.25)
        # Iterate candidate prefix lengths from /30 (4 addresses) up to max_prefix (/24 default: 256 addresses)
        for p in range(30, max_prefix + 1):
            size = 1 << (32 - p)
            usable = size - 2  # network + broadcast removed
            if usable >= needed:
                return p
        return max_prefix

    def _next_group_subnets(router_id: int, group_idx: int, host_count: int = 0) -> tuple[str,str]:
        """Allocate subnets for router/group using the real allocator only with dynamic LAN sizing.

        Layout inside parent /24 (allocator enforced):
          - First /30 for router-switch link
          - LAN starts at +64 offset (as before) but prefix chosen dynamically.
        """
        if subnet_alloc is None:
            raise RuntimeError("Subnet allocator unavailable; cannot synthesize legacy subnets (removed).")
        try:
            parent = subnet_alloc.next_subnet(24)  # parent slice (/24)
            base_int = int(parent.network_address)
            rsw_net = ipaddress.ip_network((ipaddress.IPv4Address(base_int), 30), strict=False)
            lan_base = ipaddress.IPv4Address(base_int + 64)
            lan_prefix = _lan_prefix_for_hosts(host_count)
            # Ensure LAN fits within the same /24 parent; if prefix is too small (too many addresses), fallback to /24 aligned at lan_base's /24
            try:
                lan_net = ipaddress.ip_network((lan_base, lan_prefix), strict=False)
                # If LAN would overflow parent, fallback to parent-aligned /24
                if not (int(lan_net.network_address) >= base_int and int(lan_net.broadcast_address) <= int(parent.broadcast_address)):
                    lan_net = ipaddress.ip_network((ipaddress.IPv4Address(base_int), 24), strict=False)
            except Exception:
                lan_net = ipaddress.ip_network((ipaddress.IPv4Address(base_int), 24), strict=False)
            return str(rsw_net), str(lan_net)
        except Exception as e:
            raise RuntimeError(f"Failed to allocate R2S group subnets for router {router_id}: {e}")

    router_meta: Dict[int, Dict[str, Any]] = {}
    for rid in sorted(hosts_by_router.keys()):
        host_list_sorted = sorted(hosts_by_router[rid])
        r2s_host_pairs_possible[rid] = len(host_list_sorted) // 2
        bounds_item = None
        if item_assignment and 0 <= (rid - 1) < len(item_assignment):
            bounds_item = item_assignment[rid - 1]
        hmin_r = None
        hmax_r = None
        proto_name = None
        if bounds_item is not None:
            try:
                hmin_r = int(getattr(bounds_item, 'r2s_hosts_min', 0)) or None
                hmax_r = int(getattr(bounds_item, 'r2s_hosts_max', 0)) or None
                proto_name = getattr(bounds_item, 'protocol', None)
            except Exception:
                pass
        per_router_bounds[rid] = {'min': hmin_r, 'max': hmax_r}
        router_meta[rid] = {
            'host_ids': host_list_sorted,
            'hmin': hmin_r,
            'hmax': hmax_r,
            'proto': proto_name,
        }

    def _assign_nonuniform_targets(meta: Dict[int, Dict[str, Any]]) -> Dict[int, int]:
        assignments: Dict[int, int] = {}
        candidates: List[Dict[str, Any]] = []
        for rid, info in meta.items():
            host_ids = info.get('host_ids') or []
            host_count = len(host_ids)
            if host_count < 2:
                continue
            hmin_raw = info.get('hmin')
            eff_min = hmin_raw if (isinstance(hmin_raw, int) and hmin_raw > 0) else 2
            if eff_min <= 0:
                eff_min = 1
            hmax_raw = info.get('hmax')
            eff_max = hmax_raw if (isinstance(hmax_raw, int) and hmax_raw > 0) else None
            if eff_max is not None and eff_max < eff_min:
                eff_max = eff_min
            min_groups = 1
            if eff_max is not None and eff_max > 0:
                min_groups = max(1, math.ceil(host_count / eff_max))
            if eff_min > host_count:
                max_groups = 1
            else:
                max_groups = host_count if eff_min <= 1 else max(1, host_count // eff_min)
            if max_groups < 1:
                max_groups = 1
            if max_groups < min_groups:
                max_groups = min_groups
            range_values = list(range(min_groups, max_groups + 1))
            if not range_values:
                continue
            candidates.append({
                'rid': rid,
                'range': range_values,
                'flex': len(range_values),
                'host_count': host_count,
            })
        candidates.sort(key=lambda entry: (entry['flex'], -entry['host_count'], entry['rid']))
        used: set[int] = set()
        for entry in candidates:
            choice = next((val for val in entry['range'] if val not in used), None)
            if choice is None:
                choice = entry['range'][0]
            assignments[entry['rid']] = choice
            used.add(choice)
        return assignments

    nonuniform_targets: Dict[int, int] = {}
    if effective_mode == 'nonuniform':
        nonuniform_targets = _assign_nonuniform_targets(router_meta)

    for rid in sorted(hosts_by_router.keys()):
        meta = router_meta.get(rid, {})
        host_list_sorted = meta.get('host_ids', [])
        hmin_r = meta.get('hmin')
        hmax_r = meta.get('hmax')
        proto_name = meta.get('proto')
        bounds_info = per_router_bounds.get(rid, {'min': hmin_r, 'max': hmax_r})
        if effective_mode == 'exact':
            desired_targets = max(1, int(float(target_per_router or 0)))
            if desired_targets == 1:
                if not host_list_sorted:
                    r2s_host_pairs_used[rid] = 0
                    r2s_unmet[rid] = 0
                    grouping_preview.append({'router_id': rid, 'protocol': proto_name, 'bounds': bounds_info, 'host_ids': host_list_sorted, 'groups': [], 'group_sizes': []})
                    continue
                rsw_subnet, lan_subnet = _next_group_subnets(rid, 0, host_count=len(host_list_sorted))
                router_switch_subnets.append(rsw_subnet)
                lan_subnets.append(lan_subnet)
                switch_nodes.append({'node_id': next_switch_id, 'name': f"rsw-{rid}-1"})
                host_if_ips: Dict[int, str] = {}
                try:
                    lan_net = ipaddress.ip_network(lan_subnet, strict=False)
                    lan_hosts = list(lan_net.hosts())
                except Exception:
                    lan_hosts = []
                for idx_h, h_id in enumerate(host_list_sorted):
                    if lan_hosts and idx_h + 2 < len(lan_hosts):
                        host_if_ips[h_id] = str(lan_hosts[idx_h + 2]) + f"/{lan_net.prefixlen if lan_hosts else 28}"
                router_ip = None
                switch_ip = None
                try:
                    rsw_net = ipaddress.ip_network(rsw_subnet, strict=False)
                    rsw_hosts = list(rsw_net.hosts())
                    if len(rsw_hosts) >= 2:
                        router_ip = f"{rsw_hosts[0]}/{rsw_net.prefixlen}"
                        switch_ip = f"{rsw_hosts[1]}/{rsw_net.prefixlen}"
                except Exception:
                    pass
                switches_detail.append({'switch_id': next_switch_id, 'router_id': rid, 'hosts': host_list_sorted, 'rsw_subnet': rsw_subnet, 'lan_subnet': lan_subnet, 'router_ip': router_ip, 'switch_ip': switch_ip, 'host_if_ips': host_if_ips})
                next_switch_id += 1
                r2s_counts[rid] = 1
                r2s_host_pairs_used[rid] = len(host_list_sorted) // 2
                r2s_unmet[rid] = max(0, int(float(target_per_router)) - 1)
                grouping_preview.append({'router_id': rid, 'protocol': proto_name, 'bounds': bounds_info, 'host_ids': host_list_sorted, 'groups': [host_list_sorted], 'group_sizes': [len(host_list_sorted)]})
                continue

            groups = _distribute_exact_groups(host_list_sorted, desired_targets, hmin_r, hmax_r)
            for gi, group in enumerate(groups):
                rsw_subnet, lan_subnet = _next_group_subnets(rid, gi, host_count=len(group))
                router_switch_subnets.append(rsw_subnet)
                lan_subnets.append(lan_subnet)
                router_ip = None
                switch_ip = None
                try:
                    rsw_net = ipaddress.ip_network(rsw_subnet, strict=False)
                    rsw_hosts = list(rsw_net.hosts())
                    if len(rsw_hosts) >= 2:
                        router_ip = f"{rsw_hosts[0]}/{rsw_net.prefixlen}"
                        switch_ip = f"{rsw_hosts[1]}/{rsw_net.prefixlen}"
                except Exception:
                    pass
                switches_detail.append({'switch_id': next_switch_id, 'router_id': rid, 'hosts': list(group), 'rsw_subnet': rsw_subnet, 'lan_subnet': lan_subnet, 'router_ip': router_ip, 'switch_ip': switch_ip, 'host_if_ips': {}})
                switch_nodes.append({'node_id': next_switch_id, 'name': f"rsw-{rid}-{gi+1}"})
                next_switch_id += 1
            r2s_counts[rid] = len(groups)
            r2s_host_pairs_used[rid] = sum(len(g) // 2 for g in groups)
            grouping_preview.append({'router_id': rid, 'protocol': proto_name, 'bounds': bounds_info, 'host_ids': host_list_sorted, 'groups': groups, 'group_sizes': [len(g) for g in groups]})
            if len(groups) < desired_targets:
                r2s_unmet[rid] = desired_targets - len(groups)
            continue

        if len(host_list_sorted) < 2:
            r2s_host_pairs_used[rid] = 0
            grouping_preview.append({'router_id': rid, 'protocol': proto_name, 'bounds': bounds_info, 'host_ids': host_list_sorted, 'groups': [], 'group_sizes': []})
            continue
        target_groups = nonuniform_targets.get(rid) if effective_mode == 'nonuniform' else None
        if target_groups is not None:
            groups = _distribute_exact_groups(host_list_sorted, target_groups, hmin_r, hmax_r)
        else:
            rnd_local = random.Random(seed + 7000 + rid)
            lo = hmin_r if (hmin_r and hmin_r > 0) else 2
            hi = hmax_r if (hmax_r and hmax_r > 0 and (not hmin_r or hmax_r >= hmin_r)) else 4
            if lo > hi:
                lo = hi
            remaining = list(host_list_sorted)
            groups = []
            while remaining:
                if len(remaining) <= hi and len(remaining) >= lo:
                    groups.append(list(remaining))
                    remaining.clear()
                    break
                if len(remaining) < lo:
                    if groups:
                        groups[-1].extend(remaining)
                    else:
                        groups.append(list(remaining))
                    remaining.clear()
                    break
                sizes = list(range(lo, min(hi, len(remaining)) + 1))
                weights = [1.0 / (s ** 1.15) for s in sizes]
                tot = sum(weights)
                pick = rnd_local.random() * tot
                acc = 0.0
                chosen = sizes[0]
                for s, w in zip(sizes, weights):
                    acc += w
                    if pick <= acc:
                        chosen = s
                        break
                if chosen > len(remaining):
                    chosen = len(remaining)
                groups.append(remaining[:chosen])
                remaining = remaining[chosen:]
        for gi, group in enumerate(groups):
            rsw_subnet, lan_subnet = _next_group_subnets(rid, gi, host_count=len(group))
            router_switch_subnets.append(rsw_subnet)
            lan_subnets.append(lan_subnet)
            router_ip = None
            switch_ip = None
            try:
                rsw_net = ipaddress.ip_network(rsw_subnet, strict=False)
                rsw_hosts = list(rsw_net.hosts())
                if len(rsw_hosts) >= 2:
                    router_ip = f"{rsw_hosts[0]}/{rsw_net.prefixlen}"
                    switch_ip = f"{rsw_hosts[1]}/{rsw_net.prefixlen}"
            except Exception:
                pass
            switches_detail.append({'switch_id': next_switch_id, 'router_id': rid, 'hosts': list(group), 'rsw_subnet': rsw_subnet, 'lan_subnet': lan_subnet, 'router_ip': router_ip, 'switch_ip': switch_ip, 'host_if_ips': {}})
            switch_nodes.append({'node_id': next_switch_id, 'name': f"rsw-{rid}-{gi+1}"})
            next_switch_id += 1
        r2s_counts[rid] = len(groups)
        r2s_host_pairs_used[rid] = sum(len(g) // 2 for g in groups)
        grouping_preview.append({'router_id': rid, 'protocol': proto_name, 'bounds': bounds_info, 'host_ids': host_list_sorted, 'groups': groups, 'group_sizes': [len(g) for g in groups]})
    # Build policy summary
    if effective_mode=='exact':
        policy_mode_label = 'Exact' if mode_lower == 'exact' else mode_rs
        computed_r2s_policy = {'mode': policy_mode_label,'target_per_router': target_per_router or 1,'counts': r2s_counts}
        if derived_effective_target is not None:
            computed_r2s_policy['target_per_router_effective'] = derived_effective_target
    else:
        computed_r2s_policy = {'mode': mode_rs,'target_per_router': target_per_router or 0,'counts': r2s_counts}
    # Saturation stats
    total_pairs_possible = sum(r2s_host_pairs_possible.values()) or 0
    total_pairs_used = sum(r2s_host_pairs_used.values()) or 0
    sat = 0.0
    if total_pairs_possible>0:
        sat = round(total_pairs_used/total_pairs_possible,3)
    computed_r2s_policy.update({
        'host_pairs_possible_total': total_pairs_possible,
        'host_pairs_used_total': total_pairs_used,
        'host_pair_saturation': sat,
        'host_pairs_possible': r2s_host_pairs_possible,
        'host_pairs_used': r2s_host_pairs_used,
        'per_router_bounds': per_router_bounds,
    })
    if r2s_unmet:
        computed_r2s_policy['unmet_switch_targets'] = r2s_unmet
    return {
        'grouping_preview': grouping_preview,
        'computed_r2s_policy': computed_r2s_policy,
        'switch_nodes': switch_nodes,
        'switches_detail': switches_detail,
        'ptp_subnets': ptp_subnets,
        'router_switch_subnets': router_switch_subnets,
        'lan_subnets': lan_subnets,
        'r2r_subnets': r2r_subnets,
    }

def plan_router_counts(
    role_counts: Dict[str, int],
    routing_density: float,
    routing_items: List[Any],
    base_host_pool: Optional[int],
) -> Dict[str, Any]:
    total_hosts = sum(int(c) for c in role_counts.values())
    effective_base = max(0, int(base_host_pool or 0))
    # Count-based routers (abs_count >0)
    try:
        count_router_count = sum(int(getattr(ri, 'abs_count', 0) or 0) for ri in (routing_items or []))
    except Exception:
        count_router_count = 0
    # Detect weight-based items (factor>0 & abs_count==0)
    has_weight_based = False
    try:
        has_weight_based = any(
            (int(getattr(ri, 'abs_count', 0) or 0) == 0) and (float(getattr(ri, 'factor', 0) or 0.0) > 0.0)
            for ri in (routing_items or [])
        )
    except Exception:
        has_weight_based = False
    try:
        rd_raw = float(routing_density or 0.0)
    except Exception:
        rd_raw = 0.0
    rd_clamped = max(0.0, min(1.0, rd_raw)) if has_weight_based else 0.0
    # Weight-based routers
    import math as _math
    weight_based = int(_math.floor(effective_base * rd_clamped + 1e-9)) if (rd_clamped > 0 and effective_base > 0) else 0
    router_count = min(total_hosts, count_router_count + weight_based)
    return {
        'router_count': router_count,
        'count_router_count': count_router_count,
        'density_router_count': weight_based,  # legacy naming compatibility
        'weight_based': weight_based,
        'rd_clamped': rd_clamped,
        'rd_raw': rd_raw,
        'has_weight_based': has_weight_based,
        'effective_base': effective_base,
        'total_hosts': total_hosts,
    }
