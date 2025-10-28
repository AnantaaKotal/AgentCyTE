from __future__ import annotations
"""Full topology planning preview (reconstructed after corruption).

This module provides a deterministic forecast of the planned topology including:
 - Routers / Hosts / (preview) Switches
 - Simple IP allocation preview
 - R2R policy & edge approximation
 - R2S policy (with Exact=1 aggregated semantics) + counts
 - Service & Vulnerability assignment previews
 - Segmentation density sampling

The implementation is intentionally simpler than the builder logic but keeps
the same public return contract relied upon by the web UI, CLI and tests.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any, Optional, Set
import ipaddress
import random
import os
import tempfile
import xml.etree.ElementTree as ET
import math

from .layout_positions import compute_clustered_layout
from ..utils.allocators import UniqueAllocator, make_subnet_allocator  # runtime-like allocators
from .router_host_plan import plan_router_counts, plan_r2s_grouping  # reuse builder's router count & grouping logic
from .node_plan import _normalize_role_name  # internal normalization helper


@dataclass
class PreviewNode:
    node_id: int
    name: str
    role: str
    kind: str  # router | host | switch
    ip4: str | None = None
    r2r_interfaces: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    is_base_bridge: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


def _stable_shuffle(seq: List[Any], seed: int) -> List[Any]:
    rnd = random.Random(seed)
    out = list(seq)
    rnd.shuffle(out)
    return out


def _expand_roles(role_counts: Dict[str, int]) -> List[str]:
    out: List[str] = []
    for r, c in role_counts.items():
        out.extend([r] * int(c))
    return out


BASE_TARGET_TYPES = {
    'router', 'prouter', 'mdr', 'switch', 'lanswitch'
}

BASE_HOST_TYPES = {
    'host', 'pc', 'server', 'workstation', 'client', 'desktop', 'lxc', 'xterm',
    'generic', 'terminal', 'laptop'
}

BASE_INFRA_TYPES = {
    'network', 'lan', 'wan', 'wireless', 'wirelesslan', 'wireless-lan', 'wlan',
    'hub', 'rj45', 'ethernet', 'tap', 'bridge', 'link', 'wifi', 'wirelessap',
    'radio', 'rf', 'pointtopoint', 'p2p'
}

BASE_CLUSTER_ALLOWED_TYPES = BASE_TARGET_TYPES.union(BASE_HOST_TYPES).union(BASE_INFRA_TYPES)


def _parse_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _position_from_element(element: Optional[ET.Element]) -> Optional[Dict[str, float]]:
    if element is None:
        return None
    x = _parse_float(element.get('x'))
    y = _parse_float(element.get('y'))
    if x is None or y is None:
        return None
    return {'x': x, 'y': y}


def _extract_base_graph(root: ET.Element) -> Tuple[Dict[str, Dict[str, Any]], List[Tuple[str, str]]]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Tuple[str, str]] = []

    def _register_node(node_id: Any, name: Any, node_type: Any, position: Optional[Dict[str, float]]):
        if node_id is None:
            return
        node_id_str = str(node_id).strip()
        if not node_id_str:
            return
        node_type_norm = (str(node_type).strip().lower()) if node_type is not None else ''
        name_str = str(name).strip() if name is not None else ''
        existing = nodes.get(node_id_str)
        if existing:
            if name_str and not existing.get('name'):
                existing['name'] = name_str
            if node_type_norm and not existing.get('type'):
                existing['type'] = node_type_norm
            if position and not existing.get('position'):
                existing['position'] = position
            return
        nodes[node_id_str] = {
            'id': node_id_str,
            'name': name_str or node_id_str,
            'type': node_type_norm or 'unknown',
            'position': position,
        }

    def _register_edge(a: Any, b: Any):
        if a is None or b is None:
            return
        a_str = str(a).strip()
        b_str = str(b).strip()
        if not a_str or not b_str or a_str == b_str:
            return
        edges.append((a_str, b_str))

    for node in root.findall('.//node'):
        node_id = node.get('id') or node.findtext('id')
        node_type = node.get('type') or node.get('model')
        name = node.get('name') or node.findtext('name')
        pos = _position_from_element(node.find('position'))
        _register_node(node_id, name, node_type, pos)

    for device in root.findall('.//device'):
        node_id = device.get('id')
        node_type = device.get('type')
        name = device.get('name')
        pos = _position_from_element(device.find('position'))
        _register_node(node_id, name, node_type, pos)

    for network in root.findall('.//network'):
        node_id = network.get('id')
        node_type = network.get('type') or 'network'
        name = network.get('name')
        pos = _position_from_element(network.find('position'))
        _register_node(node_id, name, node_type, pos)

    for link in root.findall('.//link'):
        node1 = link.get('node1') or link.get('node1_id') or link.get('src')
        node2 = link.get('node2') or link.get('node2_id') or link.get('dst')
        _register_edge(node1, node2)

    return nodes, edges


def _parse_base_candidates(base_path: str) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    if not base_path or not os.path.exists(base_path):
        return candidates
    try:
        tree = ET.parse(base_path)
        root = tree.getroot()
    except Exception:
        return candidates
    nodes_map, edges = _extract_base_graph(root)
    if not nodes_map:
        return candidates

    adjacency: Dict[str, Set[str]] = {}
    for node_id in nodes_map:
        adjacency[node_id] = set()
    for a, b in edges:
        if a in nodes_map and b in nodes_map:
            adjacency.setdefault(a, set()).add(b)
            adjacency.setdefault(b, set()).add(a)

    for node_id, node in nodes_map.items():
        node_type = (node.get('type') or '').strip().lower()
        if node_type not in BASE_TARGET_TYPES:
            continue
        candidate = dict(node)
        visited: Set[str] = set()
        queue: List[str] = []
        if node_id:
            visited.add(node_id)
            queue.append(node_id)
        while queue:
            current = queue.pop(0)
            for neighbor in adjacency.get(current, set()):
                if neighbor in visited:
                    continue
                neighbor_type = (nodes_map.get(neighbor, {}).get('type') or '').strip().lower()
                if neighbor_type and neighbor_type not in BASE_CLUSTER_ALLOWED_TYPES:
                    nodes_map.setdefault(neighbor, {})['type'] = 'unknown'
                elif not neighbor_type:
                    nodes_map.setdefault(neighbor, {})['type'] = 'unknown'
                visited.add(neighbor)
                queue.append(neighbor)
        if visited:
            cluster_nodes = [dict(nodes_map[n]) for n in visited if n in nodes_map]
            cluster_edges_set: Set[Tuple[str, str]] = set()
            for edge_a, edge_b in edges:
                if edge_a in visited and edge_b in visited:
                    ordered = tuple(sorted((edge_a, edge_b)))
                    cluster_edges_set.add(ordered)
            candidate['cluster'] = {
                'root_id': node_id,
                'nodes': cluster_nodes,
                'edges': [list(edge) for edge in sorted(cluster_edges_set)],
            }
        candidates.append(candidate)
    return candidates


def _attach_base_bridge(
    base_scenario: Optional[Dict[str, Any]],
    router_nodes: List[PreviewNode],
    r2r_edges: List[Tuple[int, int]],
    seed: int,
) -> Optional[Dict[str, Any]]:
    if not isinstance(base_scenario, dict):
        return None
    resolved_path = (base_scenario.get('filepath') or '').strip()
    if not resolved_path:
        # fall back to raw path if provided
        resolved_path = (base_scenario.get('filepath_raw') or '').strip()
    if not resolved_path:
        return None
    info: Dict[str, Any] = {
        'filepath': resolved_path,
        'filepath_raw': base_scenario.get('filepath_raw', resolved_path),
    }
    exists = os.path.exists(resolved_path)
    info['exists'] = exists
    if not exists:
        info['attached'] = False
        info['reason'] = 'missing-file'
        return info
    candidates = _parse_base_candidates(resolved_path)
    info['candidate_count'] = len(candidates)
    if not candidates:
        info['attached'] = False
        info['reason'] = 'no-target'
        return info
    rng = random.Random(seed + 811)
    target = rng.choice(candidates)
    peer_candidates = [r.node_id for r in router_nodes]
    if not peer_candidates:
        info['attached'] = False
        info['reason'] = 'no-router-available'
        return info
    peer_router_id = rng.choice(peer_candidates)
    peer_router = None
    for node in router_nodes:
        if node.node_id == peer_router_id:
            peer_router = node
            break
    if peer_router is None:
        info['attached'] = False
        info['reason'] = 'peer-router-missing'
        return info

    info['attached'] = True
    target_copy = dict(target)
    info['target'] = target_copy
    if target.get('cluster'):
        info['target_cluster'] = target['cluster']
        target_copy['cluster'] = target['cluster']
    if target.get('position'):
        info['target_position'] = target['position']

    peer_router.is_base_bridge = True
    peer_router.metadata['base_target'] = dict(target)
    peer_router.metadata.setdefault('base_bridge_targets', [])
    peer_router.metadata['base_bridge_targets'].append(dict(target))
    peer_router.metadata['base_filepath'] = resolved_path
    if target.get('cluster'):
        peer_router.metadata['base_target_cluster'] = target['cluster']

    info['bridge_router_id'] = peer_router.node_id
    info['bridge_router_name'] = peer_router.name
    info['internal_peer_router_id'] = peer_router.node_id
    info['internal_peer_router_name'] = peer_router.name
    info['existing_router_bridge'] = True
    info['bridge_router_ip4'] = peer_router.ip4
    return info

def _preview_services(service_plan: Dict[str, int], host_ids: List[int], seed: int) -> Dict[int, List[str]]:
    if not service_plan:
        return {}
    ordered = _stable_shuffle(list(host_ids), seed + 17)
    if not ordered:
        return {}
    assignments: Dict[int, List[str]] = {h: [] for h in ordered}
    idx = 0
    for svc, count in service_plan.items():
        for _ in range(int(count)):
            hid = ordered[idx % len(ordered)]
            assignments[hid].append(svc)
            idx += 1
    return {k: v for k, v in assignments.items() if v}


def _derive_r2s_policy_from_items(routing_items: Optional[List[Any]]) -> Optional[Dict[str, Any]]:
    if not routing_items:
        return None
    for it in routing_items:
        try:
            mode_val = getattr(it, 'r2s_mode', None)
        except Exception:
            mode_val = None
        if not mode_val and isinstance(it, dict):
            mode_val = it.get('r2s_mode') or it.get('r2sMode')
        if not mode_val:
            continue
        edges_val = 0
        try:
            edges_val = int(getattr(it, 'r2s_edges', 0))
        except Exception:
            if isinstance(it, dict):
                try:
                    edges_val = int(it.get('r2s_edges') or it.get('r2sEdges') or 0)
                except Exception:
                    edges_val = 0
        m = str(mode_val).strip()
        if not m:
            continue
        if m.lower() == 'exact' and edges_val > 0:
            return {'mode': 'Exact', 'target_per_router': edges_val}
        return {'mode': m}
    return None


def build_full_preview(
    role_counts: Dict[str, int],
    routers_planned: int,
    services_plan: Dict[str, int],
    vulnerabilities_plan: Dict[str, int],
    r2r_policy: Optional[Dict[str, Any]],
    r2s_policy: Optional[Dict[str, Any]],
    routing_items: Optional[List[Any]],
    routing_plan: Dict[str, Any],
    segmentation_density: Optional[float],
    segmentation_items: Optional[List[Dict[str, Any]]],
    traffic_plan: Optional[List[Dict[str, Any]]] = None,
    seed: Optional[int] = None,
    ip4_prefix: str = '10.0.0.0/16',
    ip_mode: str | None = None,
    ip_region: str | None = None,
    r2s_hosts_min_list: Optional[List[int]] = None,
    r2s_hosts_max_list: Optional[List[int]] = None,
    base_scenario: Optional[Dict[str, Any]] = None,
):
    """Return a topology preview dictionary.

    Parameters mirror previous implementation (extra args accepted & ignored
    if not used for forward compatibility).
    """
    seed_generated = False
    if seed is None:
        seed = random.randint(1, 2**31 - 1)
        seed_generated = True
    rnd_seed = seed

    # ---- Validation: any remaining 'Random' placeholders indicate upstream resolution failed ----
    def _has_random_label() -> List[str]:
        offenders: List[str] = []
        # services
        if services_plan and any(k.strip().lower() == 'random' for k in services_plan.keys()):
            offenders.append('services_plan')
        # vulnerabilities
        if vulnerabilities_plan and any(k.strip().lower() == 'random' for k in vulnerabilities_plan.keys()):
            offenders.append('vulnerabilities_plan')
        # segmentation items
        if segmentation_items and any(((it.get('name') or it.get('selected') or '').strip().lower() == 'random') for it in segmentation_items):
            offenders.append('segmentation_items')
        # traffic
        if traffic_plan and any(((it.get('kind') or it.get('selected') or '').strip().lower() == 'random') for it in traffic_plan):
            offenders.append('traffic_plan')
        # routing items
        if routing_items and any(getattr(it, 'protocol', '').strip().lower() == 'random' for it in routing_items):
            offenders.append('routing_items')
        return offenders
    # Pre-resolve 'Random' segmentation placeholders into concrete kinds BEFORE validation
    # Segmentation random expansion: split total factor of all Random rows evenly across defaults
    default_seg_kinds = ['Firewall', 'NAT', 'CUSTOM']
    if segmentation_items:
        total_random_factor = 0.0
        concrete_items: List[Dict[str, Any]] = []
        for it in segmentation_items:
            name_l = str((it.get('name') or it.get('selected') or '')).strip().lower()
            try:
                fval = float(it.get('factor') or 0.0)
            except Exception:
                fval = 0.0
            if name_l == 'random':
                total_random_factor += fval
            else:
                concrete_items.append(it)
        if total_random_factor > 0 and default_seg_kinds:
            share = total_random_factor / len(default_seg_kinds)
            for k in default_seg_kinds:
                concrete_items.append({'selected': k, 'factor': share})
        segmentation_items = concrete_items

    random_offenders = _has_random_label()
    # After expansion, any remaining Random is an error (other sections must already resolve Random upstream)
    if random_offenders:
        raise ValueError(f"Unresolved 'Random' placeholders present in: {', '.join(random_offenders)}. They must be expanded before preview.")

    # ---- Routers (recomputed via shared planner if discrepancy) ----
    try:
        # Attempt to recompute router count for parity; fall back silently if inputs incomplete
        recompute_stats = plan_router_counts(role_counts, (r2r_policy or {}).get('density', 0.0) if False else 0.0, routing_items or [], sum(role_counts.values()), None)
        recomputed = recompute_stats.get('router_count')
        if isinstance(recomputed, int) and recomputed > 0 and recomputed != routers_planned:
            routers_planned = recomputed
            router_plan_stats = recompute_stats
        else:
            router_plan_stats = {'router_count_input': routers_planned}
    except Exception:
        router_plan_stats = {'router_count_input': routers_planned}
    router_nodes: List[PreviewNode] = []
    for i in range(routers_planned):
        router_nodes.append(PreviewNode(node_id=i + 1, name=f"r{i+1}", role="Router", kind="router"))

    # ---- Hosts ----
    total_hosts = sum(int(c) for c in role_counts.values())
    # Normalize role_counts in case caller bypassed compute_node_plan
    normalized_counts = {}
    for r, c in role_counts.items():
        nr = _normalize_role_name(r)
        normalized_counts[nr] = normalized_counts.get(nr, 0) + int(c)
    role_counts = normalized_counts
    role_expanded = _expand_roles(role_counts)
    host_nodes: List[PreviewNode] = []
    host_router_map: Dict[int, int] = {}
    if total_hosts:
        # Deterministic distribution: round-robin, stable order (roles already normalized by node_plan)
        for idx, role in enumerate(role_expanded):
            host_id = routers_planned + idx + 1  # host IDs start after routers
            if routers_planned > 0:
                rid = (idx % routers_planned) + 1
            else:
                rid = 0
            host_router_map[host_id] = rid
            host_nodes.append(PreviewNode(node_id=host_id, name=f"h{idx+1}", role=role, kind="host"))
    host_map: Dict[int, PreviewNode] = {h.node_id: h for h in host_nodes}

    # ---- Runtime-like IP assignment (using allocators similar to topology.py) ----
    # We mimic the builder behavior more closely by using UniqueAllocator which rolls to the next
    # contiguous block when exhausted. Subnet allocation (make_subnet_allocator) is reserved for
    # switch / LAN preview later; here we focus on per-node primary IPs.
    ip_alloc_mode = 'runtime_like'
    assigned_ips: Set[str] = set()
    try:
        uniq_alloc = UniqueAllocator(ip4_prefix)
    except Exception:
        uniq_alloc = None
    fallback_ip_iter = None
    fallback_prefixlen = None

    def _alloc_ip_from_pool() -> Optional[str]:
        nonlocal uniq_alloc, fallback_ip_iter, fallback_prefixlen
        while True:
            if uniq_alloc is not None:
                try:
                    ip, mask = uniq_alloc.next_ip()
                    if ip not in assigned_ips:
                        assigned_ips.add(ip)
                        return f"{ip}/{mask}"
                except Exception:
                    uniq_alloc = None
            if fallback_ip_iter is None:
                try:
                    base_net = ipaddress.ip_network(ip4_prefix or '10.0.0.0/24', strict=False)
                except Exception:
                    base_net = ipaddress.ip_network('10.0.0.0/24', strict=False)
                fallback_ip_iter = iter(base_net.hosts())
                fallback_prefixlen = base_net.prefixlen
            try:
                addr = next(fallback_ip_iter)
            except StopIteration:
                return None
            raw = str(addr)
            if raw in assigned_ips:
                continue
            assigned_ips.add(raw)
            return f"{raw}/{fallback_prefixlen}"

    for rn in router_nodes:
        alloc_ip = _alloc_ip_from_pool()
        if not alloc_ip:
            break
        rn.ip4 = alloc_ip

    # ---- R2R Policy Preview ----
    if r2r_policy:
        r2r_preview = dict(r2r_policy)
    else:
        if routers_planned <= 1:
            r2r_preview = {"mode": "None", "target_degree": 0}
        elif routers_planned <= 2:
            r2r_preview = {"mode": "Min", "target_degree": 1}
        elif routers_planned <= 4:
            r2r_preview = {"mode": "Uniform", "target_degree": 2}
        else:
            r2r_preview = {"mode": "NonUniform", "target_degree": min(routers_planned - 1, 4)}

    rng_edges = random.Random(rnd_seed + 103)

    def _chain_edges(node_ids: List[int]) -> List[Tuple[int, int]]:
        return [(node_ids[i], node_ids[i + 1]) for i in range(len(node_ids) - 1)]

    def _edges_from_degree_sequence(node_ids: List[int], degrees: List[int]) -> Optional[List[Tuple[int, int]]]:
        if len(node_ids) != len(degrees):
            return None
        if any(d < 0 or d > len(node_ids) - 1 for d in degrees):
            return None
        if sum(degrees) % 2 != 0:
            return None
        work = list(zip(node_ids, degrees))
        edges: set[Tuple[int, int]] = set()
        while work:
            rng_edges.shuffle(work)
            work.sort(key=lambda x: x[1], reverse=True)
            node, deg = work[0]
            if deg == 0:
                break
            work = work[1:]
            if deg > len(work):
                return None
            for idx in range(deg):
                target_node, target_deg = work[idx]
                if target_node == node:
                    return None
                edge = tuple(sorted((node, target_node)))
                edges.add(edge)
                work[idx] = (target_node, target_deg - 1)
                if work[idx][1] < 0:
                    return None
        if any(rem_deg > 0 for _, rem_deg in work):
            return None
        return sorted(edges)

    def _degree_counts(node_ids: List[int], edges: List[Tuple[int, int]]) -> Dict[int, int]:
        counts: Dict[int, int] = {nid: 0 for nid in node_ids}
        for a, b in edges:
            counts[a] = counts.get(a, 0) + 1
            counts[b] = counts.get(b, 0) + 1
        return counts

    def _assign_r2r_link_interfaces(
        router_nodes: List[PreviewNode],
        edges: List[Tuple[int, int]],
        ip4_prefix: str | None,
        ip_mode: str | None,
        ip_region: str | None,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        if not edges or not router_nodes:
            return [], []
        router_map: Dict[int, PreviewNode] = {r.node_id: r for r in router_nodes}
        try:
            allocator = make_subnet_allocator(ip_mode or 'private', ip4_prefix or '10.224.0.0/11', ip_region or 'all')
        except Exception:
            allocator = None
        fallback_base = int(ipaddress.IPv4Address('10.240.0.0'))
        fallback_idx = 0
        link_details: List[Dict[str, Any]] = []
        subnets: List[str] = []
        for edge_idx, (a, b) in enumerate(edges, start=1):
            subnet_obj = None
            if allocator is not None:
                try:
                    subnet_obj = allocator.next_subnet(30)
                except Exception:
                    subnet_obj = None
            if subnet_obj is None:
                try:
                    base_addr = ipaddress.IPv4Address(fallback_base + (fallback_idx * 4))
                    subnet_obj = ipaddress.ip_network((base_addr, 30), strict=False)
                    fallback_idx += 1
                except Exception:
                    subnet_obj = ipaddress.ip_network('10.254.0.0/30', strict=False)
            hosts = list(subnet_obj.hosts())
            ip_a = f"{hosts[0]}/{subnet_obj.prefixlen}" if len(hosts) >= 1 else None
            ip_b = f"{hosts[1]}/{subnet_obj.prefixlen}" if len(hosts) >= 2 else None
            ra = router_map.get(a)
            rb = router_map.get(b)
            if ra is not None:
                if ip_a:
                    ra.r2r_interfaces[str(b)] = ip_a
            if rb is not None:
                if ip_b:
                    rb.r2r_interfaces[str(a)] = ip_b
            detail = {
                'edge_id': edge_idx,
                'routers': [
                    {'id': a, 'ip': ip_a},
                    {'id': b, 'ip': ip_b},
                ],
                'subnet': str(subnet_obj),
            }
            link_details.append(detail)
            subnets.append(str(subnet_obj))
        return link_details, subnets

    # Build R2R edges according to mode semantics
    r2r_edges: List[Tuple[int, int]] = []
    r2r_links_detail: List[Dict[str, Any]] = []
    r2r_subnets: List[str] = []
    if routers_planned > 1:
        node_ids = [r.node_id for r in router_nodes]
        mode_rr = (r2r_preview.get('mode') or '').strip().lower()
        if mode_rr == 'min':
            r2r_edges = _chain_edges(node_ids)
        elif mode_rr == 'uniform':
            allowed_degrees = [d for d in range(1, len(node_ids)) if (len(node_ids) * d) % 2 == 0]
            if allowed_degrees:
                chosen_degree = rng_edges.choice(allowed_degrees)
                candidate = _edges_from_degree_sequence(node_ids, [chosen_degree] * len(node_ids))
                if candidate is not None:
                    r2r_edges = candidate
                    r2r_preview['target_degree'] = chosen_degree
                else:
                    r2r_edges = _chain_edges(node_ids)
            else:
                r2r_edges = _chain_edges(node_ids)
        elif mode_rr == 'exact':
            requested = int(r2r_preview.get('target_degree') or r2r_preview.get('target_per_router') or 0)
            target_degree = max(0, min(requested, len(node_ids) - 1))
            r2r_preview['target_degree'] = target_degree

            def _ensure_even(seq: List[int]) -> None:
                if sum(seq) % 2 != 0:
                    for idx in range(len(seq) - 1, -1, -1):
                        if seq[idx] > 0:
                            seq[idx] -= 1
                            break

            def _attempt_degree_sequence(base_target: int) -> Tuple[Optional[List[Tuple[int, int]]], List[int]]:
                if base_target <= 0:
                    return [], [0] * len(node_ids)
                base_seq = [base_target] * len(node_ids)
                _ensure_even(base_seq)
                candidate_edges = _edges_from_degree_sequence(node_ids, base_seq)
                if candidate_edges is not None:
                    return candidate_edges, base_seq
                for reduce_count in range(1, len(node_ids) + 1):
                    seq_try = [base_target] * len(node_ids)
                    for offset in range(reduce_count):
                        idx = len(seq_try) - 1 - offset
                        if idx < 0:
                            break
                        if seq_try[idx] > 0:
                            seq_try[idx] -= 1
                    _ensure_even(seq_try)
                    candidate_edges = _edges_from_degree_sequence(node_ids, seq_try)
                    if candidate_edges is not None:
                        return candidate_edges, seq_try
                return None, base_seq

            edges_exact, _ = _attempt_degree_sequence(target_degree)
            if edges_exact is not None:
                r2r_edges = edges_exact
                realized = _degree_counts(node_ids, r2r_edges)
                r2r_preview['degree_sequence'] = {str(nid): realized.get(nid, 0) for nid in node_ids}
            else:
                r2r_edges = _chain_edges(node_ids)
        elif mode_rr == 'nonuniform':
            edges_set: Set[Tuple[int, int]] = set()
            degrees = {nid: 0 for nid in node_ids}
            order_ids = list(node_ids)
            rng_edges.shuffle(order_ids)

            def _try_add_edge(a_id: int, b_id: int) -> bool:
                if a_id == b_id:
                    return False
                key = tuple(sorted((a_id, b_id)))
                if key in edges_set:
                    return False
                edges_set.add(key)
                r2r_edges.append(key)
                degrees[a_id] += 1
                degrees[b_id] += 1
                return True

            in_tree = {order_ids[0]}
            remaining = set(order_ids[1:])
            while remaining:
                a_id = rng_edges.choice(list(in_tree))
                b_id = rng_edges.choice(list(remaining))
                if _try_add_edge(a_id, b_id):
                    in_tree.add(b_id)
                    remaining.remove(b_id)

            hub_pool = list(node_ids)
            if len(hub_pool) > 1:
                max_hubs = int(round(max(2.0, math.sqrt(len(node_ids)))))
                max_hubs = max(2, max_hubs)
                hub_count = min(max_hubs, len(node_ids) - 1)
                if hub_count <= 0:
                    hub_count = 1
                rng_edges.shuffle(hub_pool)
                hub_ids = hub_pool[:hub_count]
                if not hub_ids:
                    hub_ids = [hub_pool[0]]
                primary_hub = hub_ids[0]
                secondary_hubs = hub_ids[1:]
                periphery_ids = [rid for rid in node_ids if rid not in hub_ids]
                nonhub_cap = 2 if len(node_ids) >= 5 else max(2, len(node_ids) // 2)

                def _eligible_target(hub_id: int, cand_id: int) -> bool:
                    if hub_id == cand_id:
                        return False
                    key = tuple(sorted((hub_id, cand_id)))
                    if key in edges_set:
                        return False
                    if cand_id in hub_ids:
                        return True
                    if hub_id == primary_hub:
                        return degrees[cand_id] < (nonhub_cap + 1)
                    return degrees[cand_id] < nonhub_cap

                for idx, a_id in enumerate(hub_ids):
                    for b_id in hub_ids[idx + 1:]:
                        _try_add_edge(a_id, b_id)

                for per_id in periphery_ids:
                    if _eligible_target(primary_hub, per_id):
                        _try_add_edge(primary_hub, per_id)
                    if secondary_hubs and rng_edges.random() < 0.2:
                        hub_choice = rng_edges.choice(secondary_hubs)
                        if _eligible_target(hub_choice, per_id):
                            _try_add_edge(hub_choice, per_id)

                def _degree_span() -> int:
                    vals = list(degrees.values())
                    if not vals:
                        return 0
                    return max(vals) - min(vals)

                def _gini(values: List[int]) -> float:
                    vals = [int(v) for v in values if v >= 0]
                    n = len(vals)
                    if n <= 1:
                        return 0.0
                    total = sum(vals)
                    if total <= 0:
                        return 0.0
                    sorted_vals = sorted(vals)
                    cum = 0
                    for idx, val in enumerate(sorted_vals, start=1):
                        cum += idx * val
                    return (2 * cum) / (n * total) - (n + 1) / n

                variance_target = 2 if len(node_ids) >= 5 else 1
                current_span = _degree_span()
                current_gini = _gini(list(degrees.values()))

                if secondary_hubs and (current_span < variance_target or (len(node_ids) >= 5 and current_gini < 0.15)):
                    for hub_id in secondary_hubs:
                        if rng_edges.random() < 0.5 and _eligible_target(primary_hub, hub_id):
                            _try_add_edge(primary_hub, hub_id)
                    current_span = _degree_span()
                    current_gini = _gini(list(degrees.values()))

                if degrees:
                    r2r_preview['degree_sequence'] = {str(k): degrees.get(k, 0) for k in node_ids}
        elif mode_rr == 'none':
            r2r_edges = []
        else:
            r2r_edges = _chain_edges(node_ids)
    r2r_links_detail: List[Dict[str, Any]] = []
    r2r_subnets: List[str] = []
    r2r_degree: Dict[int, int] = {}
    r2r_stats: Dict[str, Any] = {}

    # ---- Helper: assign routing items to routers to derive per-router bounds ----
    def _assign_items_to_routers(items: Optional[List[Any]], count: int) -> List[Optional[Any]]:
        if not items or count <= 0:
            return [None] * count
        expanded: List[Any] = []
        # First expand items with abs_count if present
        for it in items:
            abs_c = int(getattr(it, 'abs_count', 0) or (it.get('abs_count') if isinstance(it, dict) else 0) or 0)
            if abs_c > 0:
                expanded.extend([it] * abs_c)
        # If still short, append remaining items (weight / factor based) round-robin
        if len(expanded) < count:
            idx = 0
            while len(expanded) < count:
                expanded.append(items[idx % len(items)])
                idx += 1
        return expanded[:count]

    item_assignment = _assign_items_to_routers(routing_items, routers_planned)

    # ---- R2S Policy (focus on Exact=1 semantics used in tests, extended with grouping preview) ----
    if not r2s_policy:
        r2s_policy = _derive_r2s_policy_from_items(routing_items)
    mode_rs = (r2s_policy or {}).get('mode') if r2s_policy else None
    target_per_router = (r2s_policy or {}).get('target_per_router') if r2s_policy else None
    if not mode_rs:
        mode_rs = 'ratio'
    switch_nodes: List[PreviewNode] = []
    switches_detail: List[Dict[str, Any]] = []
    router_switch_subnets: List[str] = []
    lan_subnets: List[str] = []
    ptp_subnets: List[str] = []  # keep key for backward compatibility

    base_bridge_info: Optional[Dict[str, Any]] = None
    if base_scenario:
        base_bridge_info = _attach_base_bridge(
            base_scenario,
            router_nodes,
            r2r_edges,
            rnd_seed,
        )
    # recompute router stats + interfaces post bridge
    router_ids_for_stats = [r.node_id for r in router_nodes]
    if r2r_edges:
        for router in router_nodes:
            router.r2r_interfaces.clear()
        r2r_links_detail, r2r_subnets = _assign_r2r_link_interfaces(router_nodes, r2r_edges, ip4_prefix, ip_mode, ip_region)
    if router_nodes:
        r2r_degree = _degree_counts(router_ids_for_stats, r2r_edges)
        if r2r_edges or any(v > 0 for v in r2r_degree.values()):
            r2r_preview['degree_sequence'] = {str(k): r2r_degree.get(k, 0) for k in router_ids_for_stats}
        if any(r2r_degree.values()):
            vals = list(r2r_degree.values())
            r2r_stats = {'min': min(vals), 'max': max(vals), 'avg': round(sum(vals) / len(vals), 2)}

    # Host grouping per router (deterministic): collect hosts by rid
    hosts_by_router: Dict[int, List[int]] = {r.node_id: [] for r in router_nodes}
    for hid, rid in host_router_map.items():
        if rid in hosts_by_router:
            hosts_by_router[rid].append(hid)

    next_switch_id = routers_planned + total_hosts + 1
    derived_effective_target = None
    if str(mode_rs).lower() == 'exact':
        try:
            if target_per_router is None:
                raise ValueError
            _ = float(target_per_router)
        except Exception:
            # attempt derive edges from first routing item
            for it in (routing_items or []):
                ev = getattr(it, 'r2s_edges', None) if not isinstance(it, dict) else it.get('r2s_edges') or it.get('r2sEdges')
                try:
                    ev_int = int(ev)
                except Exception:
                    ev_int = 0
                if ev_int > 0:
                    target_per_router = ev_int
                    derived_effective_target = ev_int
                    break
            if target_per_router is None:
                target_per_router = 1
                derived_effective_target = 1

    grouping_out = plan_r2s_grouping(routers_planned, host_router_map, host_nodes, routing_items, r2s_policy, rnd_seed, ip4_prefix=ip4_prefix, ip_mode=ip_mode, ip_region=ip_region)
    grouping_preview = grouping_out['grouping_preview']
    computed_r2s_policy = grouping_out['computed_r2s_policy']
    # adopt switch + subnet previews
    switches_detail = grouping_out['switches_detail']
    router_switch_subnets = grouping_out['router_switch_subnets']
    lan_subnets = grouping_out['lan_subnets']
    ptp_subnets = grouping_out['ptp_subnets']
    grouping_r2r_subnets = grouping_out.get('r2r_subnets', []) or []
    if grouping_r2r_subnets:
        if r2r_subnets:
            r2r_subnets.extend([s for s in grouping_r2r_subnets if s not in r2r_subnets])
        else:
            r2r_subnets = list(grouping_r2r_subnets)
    # convert generic switch nodes to PreviewNodes
    switch_nodes = [PreviewNode(node_id=sn['node_id'], name=sn.get('name', f"sw-{sn['node_id']}"), role="Switch", kind="switch") for sn in grouping_out['switch_nodes']]

    # Override host IPs using LAN subnets for realistic per-LAN addressing
    try:
        router_map = {r.node_id: r for r in router_nodes}
        for swd in switches_detail:
            lan_sub = swd.get('lan_subnet')
            host_ids_raw = swd.get('hosts') or []
            if not lan_sub or not host_ids_raw:
                continue
            try:
                lan_net = ipaddress.ip_network(lan_sub, strict=False)
                lan_hosts = list(lan_net.hosts())
            except Exception:
                continue
            sorted_host_ids = sorted(int(h) for h in host_ids_raw)
            existing_host_ips_raw = swd.get('host_if_ips') or {}
            normalized_host_ips: Dict[int, str] = {}
            for hid_key, cidr in existing_host_ips_raw.items():
                try:
                    hid_int = int(hid_key)
                except Exception:
                    continue
                if not cidr:
                    continue
                normalized_host_ips[hid_int] = cidr
                ip_only = str(cidr).split('/')
                if ip_only:
                    assigned_ips.add(ip_only[0])
                host_obj = host_map.get(hid_int)
                if host_obj:
                    if host_obj.ip4:
                        prev_ip = host_obj.ip4.split('/')
                        if prev_ip:
                            assigned_ips.discard(prev_ip[0])
                    host_obj.ip4 = cidr
            swd['host_if_ips'] = normalized_host_ips
            reserve_for_infra = 2
            while reserve_for_infra > 0 and (len(lan_hosts) - reserve_for_infra) < len(sorted_host_ids):
                reserve_for_infra -= 1
            for idx_h, hid in enumerate(sorted_host_ids):
                host_obj = host_map.get(hid)
                if hid in normalized_host_ips and normalized_host_ips[hid]:
                    continue
                ip_slot_index = reserve_for_infra + idx_h if reserve_for_infra >= 0 else idx_h
                cidr_val: Optional[str] = None
                if 0 <= ip_slot_index < len(lan_hosts):
                    ip_addr = lan_hosts[ip_slot_index]
                    cidr_val = f"{ip_addr}/{lan_net.prefixlen}"
                else:
                    cidr_val = _alloc_ip_from_pool()
                if not cidr_val:
                    continue
                if host_obj:
                    if host_obj.ip4:
                        prev_ip = host_obj.ip4.split('/')
                        if prev_ip:
                            assigned_ips.discard(prev_ip[0])
                    host_obj.ip4 = cidr_val
                normalized_host_ips[hid] = cidr_val
                ip_only = cidr_val.split('/')
                if ip_only:
                    assigned_ips.add(ip_only[0])
            # Apply router/switch link IPs if provided
            r_ip = swd.get('router_ip')
            try:
                if r_ip:
                    rid = int(swd.get('router_id'))
                    rnode = router_map.get(rid)
                    if rnode:
                        if rnode.ip4:
                            prev_ip = rnode.ip4.split('/')
                            if prev_ip:
                                assigned_ips.discard(prev_ip[0])
                        rnode.ip4 = r_ip
                        ip_only = r_ip.split('/')
                        if ip_only:
                            assigned_ips.add(ip_only[0])
            except Exception:
                pass
        ip_alloc_mode = 'lan_subnet'
    except Exception:
        pass

    for host in host_nodes:
        if host.ip4:
            continue
        fallback_ip = _alloc_ip_from_pool()
        if fallback_ip:
            host.ip4 = fallback_ip

    # Host group bounds summary from routing_items
    try:
        mins: List[int] = []
        maxs: List[int] = []
        for it in (routing_items or []):
            mi = getattr(it, 'r2s_hosts_min', None) if not isinstance(it, dict) else it.get('r2s_hosts_min')
            ma = getattr(it, 'r2s_hosts_max', None) if not isinstance(it, dict) else it.get('r2s_hosts_max')
            if isinstance(mi, int) and mi > 0:
                mins.append(mi)
            if isinstance(ma, int) and ma > 0:
                maxs.append(ma)
        if mins or maxs:
            computed_r2s_policy['host_group_bounds'] = {
                'effective_min': min(mins) if mins else None,
                'effective_max': max(maxs) if maxs else None,
            }
    except Exception:
        pass

    # Add saturation stats similar to previous contract
    # (All pairs statistics already embedded by helper)

    # ---- Services & Vulnerabilities ----
    service_assignments = _preview_services(services_plan, [h.node_id for h in host_nodes], rnd_seed)
    vuln_assignments: Dict[int, List[str]] = {}
    if vulnerabilities_plan:
        ordered = _stable_shuffle([h.node_id for h in host_nodes], rnd_seed + 101)
        flat: List[str] = []
        for name, count in vulnerabilities_plan.items():
            for _ in range(int(count)):
                flat.append(name)
        for idx, vname in enumerate(flat):
            if not ordered:
                break
            hid = ordered[idx % len(ordered)]
            vuln_assignments.setdefault(hid, []).append(vname)
    for h in host_nodes:
        node_vulns = vuln_assignments.get(h.node_id) or []
        h.vulnerabilities = list(node_vulns)

    # ---- Traffic Materialization (resolve abstract items to concrete flows) ----
    traffic_summary: Dict[str, Any] = {}
    if traffic_plan:
        try:
            rnd = random.Random(rnd_seed + 703)
            host_ids = [h.node_id for h in host_nodes]
            flows: List[Dict[str, Any]] = []
            if host_ids:
                for item in traffic_plan:
                    factor = float(item.get('factor', 0) or 0)
                    abs_count = int(item.get('abs_count') or 0)
                    pattern = item.get('pattern') or 'continuous'
                    rate = item.get('rate_kbps') or item.get('rate') or 0
                    # derive target flows
                    if abs_count > 0:
                        flows_needed = abs_count
                    else:
                        flows_needed = int(round(factor * len(host_ids))) if factor > 0 else 0
                        if factor > 0 and flows_needed == 0:
                            flows_needed = 1
                    flows_needed = min(flows_needed, max(1, len(host_ids) * 2))
                    for _ in range(flows_needed):
                        if len(host_ids) == 1:
                            src = dst = host_ids[0]
                        else:
                            src = rnd.choice(host_ids)
                            dst = rnd.choice(host_ids)
                            if src == dst and len(host_ids) > 1:
                                for _attempt in range(3):
                                    dst = rnd.choice(host_ids)
                                    if dst != src:
                                        break
                        flows.append({'src_id': src, 'dst_id': dst, 'pattern': pattern, 'rate_kbps': rate})
            traffic_summary = {'flows': flows, 'count': len(flows)}
        except Exception as _e:
            traffic_summary = {'error': str(_e)}

    # ---- Segmentation Preview (lightweight) ----
    seg_preview: Dict[str, Any] = {"density": segmentation_density or 0.0, "planned": [], "rules": [], 'source': 'runtime_planner'}
    segmentation_rules_preview: List[Dict[str, Any]] = []
    deep_segmentation_error: Optional[str] = None
    if segmentation_density and segmentation_density > 0 and segmentation_items:
        try:
            # Convert raw segmentation items into SegmentationInfo objects (they should already be Random-resolved upstream)
            from ..types import SegmentationInfo, NodeInfo as _NI  # type: ignore
            seg_objs: List[SegmentationInfo] = []
            for it in segmentation_items:
                name = (it.get('name') or it.get('selected') or '').strip()
                factor = float(it.get('factor') or 0.0)
                abs_c = int(it.get('abs_count') or 0)
                if name:
                    seg_objs.append(SegmentationInfo(name=name, factor=factor, abs_count=abs_c))

            # Build stub session & nodes compatible with segmentation planner
            class _StubServices:
                def __init__(self):
                    self._map: Dict[int, List[str]] = {}
                def add(self, node_id, service_name):
                    self._map.setdefault(getattr(node_id, 'id', node_id), []).append(service_name)
                def get(self, node_id):
                    nid = getattr(node_id, 'id', node_id)
                    return list(self._map.get(nid, []))

            class _StubNode:
                def __init__(self, node_id: int, name: str, ip4: str, role: str):
                    self.id = node_id
                    self.name = name
                    self.ip4 = ip4
                    self.role = role
                    self.services: List[str] = []
            class _StubSession:
                def __init__(self):
                    self.services = _StubServices()
                    self.nodes: Dict[int, _StubNode] = {}
                def get_node(self, nid):
                    return self.nodes.get(nid)
            stub_session = _StubSession()
            # Populate stub nodes (routers + hosts)
            for r in router_nodes:
                stub_session.nodes[r.node_id] = _StubNode(r.node_id, r.name, r.ip4 or '', r.role)
            for h in host_nodes:
                stub_session.nodes[h.node_id] = _StubNode(h.node_id, h.name, h.ip4 or '', h.role)

            # Prepare NodeInfo lists for planner
            router_infos = [_NI(node_id=r.node_id, ip4=r.ip4 or '', role=r.role) for r in router_nodes]
            host_infos = [_NI(node_id=h.node_id, ip4=h.ip4 or '', role=h.role) for h in host_nodes]

            # Invoke real segmentation planner (dry-run style) writing into temp dir
            from ..utils.segmentation import plan_and_apply_segmentation  # type: ignore
            seg_tmp = os.path.join(tempfile.gettempdir(), f"core-topo-preview-seg-{seed}")
            summary = plan_and_apply_segmentation(
                stub_session,
                routers=router_infos,
                hosts=host_infos,
                density=float(segmentation_density or 0.0),
                items=seg_objs,
                nat_mode='SNAT',
                out_dir=seg_tmp,
                include_hosts=False,
            )
            # Extract rules
            for rr in summary.get('rules', []):
                try:
                    segmentation_rules_preview.append({
                        'node_id': rr.get('node_id'),
                        'rule': rr.get('rule'),
                        'script': rr.get('script'),
                    })
                except Exception:
                    continue
            # For preview display, synthesize 'planned' list by type of each rule
            seg_preview['planned'] = [ (r.get('rule') or {}).get('type','') for r in summary.get('rules', []) ]
            seg_preview['rules'] = segmentation_rules_preview
            seg_preview['out_dir'] = seg_tmp
            seg_preview['planned_slots'] = len(segmentation_rules_preview)
            seg_preview['note'] = 'Segmentation preview produced by runtime planner logic.'
            # Collect artifact file metadata for preview (without moving to /tmp/segmentation runtime dir)
            artifacts: List[Dict[str, Any]] = []
            try:
                for fname in sorted(os.listdir(seg_tmp)):
                    fpath = os.path.join(seg_tmp, fname)
                    if not os.path.isfile(fpath):
                        continue
                    size = 0
                    try:
                        size = os.path.getsize(fpath)
                    except Exception:
                        pass
                    snippet = ''
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                            snippet = ''.join(fh.readlines()[:5])
                    except Exception:
                        pass
                    artifacts.append({'file': fname, 'size': size, 'snippet': snippet})
            except Exception:
                pass
            seg_preview['artifacts'] = artifacts
        except Exception as _se:
            deep_segmentation_error = str(_se)
            seg_preview['source'] = 'lightweight_fallback'
            seg_preview['error'] = deep_segmentation_error
            # If runtime planner fails, leave rules list empty (no fallback lightweight recreation to avoid drift)

    # ---- Traffic Script Early Generation ----
    traffic_scripts_preview: Dict[str, Any] = {}
    if traffic_plan and host_nodes:
        try:
            from ..types import TrafficInfo, NodeInfo  # type: ignore
            from ..utils.traffic import generate_traffic_scripts  # type: ignore
            from ..utils.segmentation import plan_preview_allow_rules  # type: ignore
            # Heuristic density: average of factors capped at 1.0
            factors = [float(it.get('factor') or 0.0) for it in traffic_plan]
            density_est = 0.0
            if factors:
                density_est = min(1.0, max(0.0, sum(factors) / max(1.0, len(factors))))
            # Build TrafficInfo list
            t_items: List[TrafficInfo] = []
            for it in traffic_plan:
                t_items.append(TrafficInfo(kind=(it.get('kind') or 'TCP'), factor=float(it.get('factor') or 0.0), pattern=it.get('pattern') or 'continuous', rate_kbps=float(it.get('rate_kbps') or 0.0), abs_count=int(it.get('abs_count') or 0)))
            ninfos: List[NodeInfo] = []
            for h in host_nodes:
                if h.ip4:
                    ninfos.append(NodeInfo(node_id=h.node_id, ip4=h.ip4, role=h.role))
            # Use deterministic per-seed preview temp dir; don't pollute final /tmp/traffic until execution.
            preview_dir = os.path.join(tempfile.gettempdir(), f"core-topo-preview-traffic-{seed}")
            os.makedirs(preview_dir, exist_ok=True)
            script_map = generate_traffic_scripts(ninfos, density_est, t_items, out_dir=preview_dir) or {}
            # Summarize
            summary_nodes = {}
            for nid, paths in script_map.items():
                summary_nodes[str(nid)] = {'count': len(paths), 'paths': paths[:5]}  # cap list for payload size
            traffic_scripts_preview = {
                'nodes': summary_nodes,
                'density_est': density_est,
                'preview_dir': preview_dir,
                'final_dir_hint': '/tmp/traffic',
                'note': 'Preview scripts will be copied to runtime dir for reuse (unified preview/runtime).'
            }
            try:
                import json as _json
                summary_path = os.path.join(preview_dir, 'traffic_summary.json')
                with open(summary_path, 'r', encoding='utf-8') as _tf:
                    _preview_summary = _json.load(_tf) or {}
                flows_with_scripts = _preview_summary.get('flows') or []
                if flows_with_scripts:
                    traffic_scripts_preview['preview_flows'] = flows_with_scripts[:250]
                    traffic_summary = {
                        'flows': flows_with_scripts,
                        'count': len(flows_with_scripts)
                    }
            except Exception:
                pass
            # Predicted allow rules (dry-run) for preview purposes
            host_ip_map = {h.node_id: h.ip4.split('/')[0] for h in host_nodes if h.ip4}
            try:
                predicted = plan_preview_allow_rules(seg_preview or {}, traffic_plan, host_ip_map, seed=seed)
                traffic_scripts_preview['predicted_allow_rules'] = predicted.get('predicted_allow_rules')
            except Exception as _pae:
                traffic_scripts_preview['predicted_allow_rules_error'] = str(_pae)
        except Exception as _te:
            traffic_scripts_preview = {'error': str(_te)}

    # ---- Unify Preview -> Runtime Scripts + Hashing (Segmentation & Traffic) ----
    try:
        import hashlib, shutil
        # Segmentation scripts
        seg_prev_dir = seg_preview.get('out_dir') if isinstance(seg_preview, dict) else None
        if seg_prev_dir and os.path.isdir(seg_prev_dir):
            runtime_seg_dir = '/tmp/segmentation'
            os.makedirs(runtime_seg_dir, exist_ok=True)
            # clean runtime dir
            for _n in os.listdir(runtime_seg_dir):
                _p = os.path.join(runtime_seg_dir, _n)
                try:
                    if os.path.isfile(_p) or os.path.islink(_p): os.unlink(_p)
                    elif os.path.isdir(_p): shutil.rmtree(_p)
                except Exception: pass
            copied = []
            for _n in sorted(os.listdir(seg_prev_dir)):
                _src = os.path.join(seg_prev_dir, _n)
                if os.path.isfile(_src):
                    try:
                        shutil.copy(_src, os.path.join(runtime_seg_dir, _n))
                        copied.append(_n)
                    except Exception: pass
            seg_preview['runtime_copied'] = True
            seg_preview['runtime_dir'] = runtime_seg_dir
            seg_preview['copied_files'] = copied
            # hash
            h = hashlib.sha256()
            for _n in sorted(copied):
                if not _n.endswith('.py'): continue
                try:
                    with open(os.path.join(runtime_seg_dir,_n),'rb') as _fh: h.update(_fh.read())
                except Exception: pass
            seg_preview['scripts_hash_sha256'] = h.hexdigest()
            # load segmentation_summary.json
            summary_fp = os.path.join(runtime_seg_dir,'segmentation_summary.json')
            if os.path.exists(summary_fp):
                try:
                    import json as _json
                    with open(summary_fp,'r',encoding='utf-8') as _sf: _sum = _json.load(_sf) or {}
                    if isinstance(_sum.get('rules'), list) and len(_sum['rules'])>75:
                        _sum['_rules_truncated'] = True
                        _sum['rules'] = _sum['rules'][:75]
                    seg_preview['runtime_summary'] = _sum
                except Exception: pass
        # Traffic scripts
        tr_prev_dir = traffic_scripts_preview.get('preview_dir') if isinstance(traffic_scripts_preview, dict) else None
        if tr_prev_dir and os.path.isdir(tr_prev_dir):
            runtime_tr_dir = '/tmp/traffic'
            os.makedirs(runtime_tr_dir, exist_ok=True)
            for _n in os.listdir(runtime_tr_dir):
                _p = os.path.join(runtime_tr_dir, _n)
                try:
                    if os.path.isfile(_p) or os.path.islink(_p): os.unlink(_p)
                    elif os.path.isdir(_p): shutil.rmtree(_p)
                except Exception: pass
            copied_t = []
            for _n in sorted(os.listdir(tr_prev_dir)):
                _src = os.path.join(tr_prev_dir, _n)
                if os.path.isfile(_src):
                    try:
                        shutil.copy(_src, os.path.join(runtime_tr_dir, _n))
                        copied_t.append(_n)
                    except Exception: pass
            traffic_scripts_preview['runtime_copied'] = True
            traffic_scripts_preview['runtime_dir'] = runtime_tr_dir
            traffic_scripts_preview['copied_files'] = copied_t
            th = hashlib.sha256()
            for _n in sorted(copied_t):
                if not _n.endswith('.py'): continue
                try:
                    with open(os.path.join(runtime_tr_dir,_n),'rb') as _fh: th.update(_fh.read())
                except Exception: pass
            traffic_scripts_preview['scripts_hash_sha256'] = th.hexdigest()
    except Exception:
        pass

    # ---- Housekeeping: cleanup stale previous preview directories (best-effort) ----
    try:
        from ..utils.cleanup import clean_stale_preview_dirs  # type: ignore
        protect_dirs = []
        try:
            if isinstance(seg_preview, dict) and seg_preview.get('out_dir'):
                protect_dirs.append(seg_preview.get('out_dir'))
        except Exception:
            pass
        try:
            if isinstance(traffic_scripts_preview, dict) and traffic_scripts_preview.get('preview_dir'):
                protect_dirs.append(traffic_scripts_preview.get('preview_dir'))
        except Exception:
            pass
        clean_stale_preview_dirs(protect=protect_dirs)
    except Exception:
        pass

    routers_payload = [r.__dict__ for r in router_nodes]
    hosts_payload = [h.__dict__ for h in host_nodes]
    switches_payload = [s.__dict__ for s in switch_nodes]

    preview = {
        'routers': routers_payload,
        'hosts': hosts_payload,
        'switches': switches_payload,
        'switches_detail': switches_detail,
        'host_router_map': host_router_map,
        'services_preview': service_assignments,
        'vulnerabilities_preview': vuln_assignments,
        'vulnerabilities_by_node': {str(n.node_id): n.vulnerabilities for n in host_nodes if n.vulnerabilities},
        'r2r_policy_preview': r2r_preview,
        'r2r_edges_preview': r2r_edges,
        'r2r_links_preview': r2r_links_detail,
        'r2r_degree_preview': r2r_degree,
        'r2r_stats_preview': r2r_stats,
        'r2s_policy_preview': computed_r2s_policy,
        'segmentation_preview': seg_preview,
        'segmentation_rules_preview': segmentation_rules_preview,
        'segmentation_items_resolved': segmentation_items or [],
        'traffic_plan': traffic_plan,
        'traffic_summary': traffic_summary,
        'traffic_scripts_preview': traffic_scripts_preview,
        'ptp_subnets': ptp_subnets,
        'router_switch_subnets': router_switch_subnets,
        'lan_subnets': lan_subnets,
        'r2r_subnets': r2r_subnets,
        'routing_plan': routing_plan,
        'services_plan': services_plan,
        'vulnerabilities_plan': vulnerabilities_plan,
    'base_scenario_reference': base_scenario,
    'base_bridge_preview': base_bridge_info,
        'role_counts': dict(role_counts),
        'seed': seed,
        'seed_generated': seed_generated,
        'r2s_hosts_min_list': r2s_hosts_min_list or [],
        'r2s_hosts_max_list': r2s_hosts_max_list or [],
        'r2s_grouping_preview': grouping_preview,
        'ip_allocation_mode': ip_alloc_mode,
        'router_plan_stats': router_plan_stats,
    }

    layout_input = {
        'routers': routers_payload,
        'hosts': hosts_payload,
        'switches': switches_payload,
        'switches_detail': switches_detail,
        'host_router_map': host_router_map,
    }
    try:
        preview['layout_positions'] = compute_clustered_layout(layout_input, max_dim=2000)
    except Exception as layout_err:
        preview['layout_positions'] = {'error': str(layout_err)}

    return preview
