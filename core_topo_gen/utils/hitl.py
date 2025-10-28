from __future__ import annotations
import logging
import hashlib
import ipaddress
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..types import NodeInfo

try:  # pragma: no cover - exercised with real CORE installs
    from core.api.grpc.wrappers import NodeType, Position, Interface  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback used in tests/offline
    # Reuse the fallback definitions from the topology builder to ensure identical behaviour.
    from ..builders.topology import NodeType, Position, Interface  # type: ignore  # noqa: F401

logger = logging.getLogger(__name__)

_ATTACHMENT_ALLOWED = {
    "existing_router",
    "existing_switch",
    "new_router",
    "new_switch",
}
_DEFAULT_ATTACHMENT = "existing_router"
_LEGACY_ASSIGNMENT = {
    "existing_router": "peer",
    "existing_switch": "switch",
    "new_switch": "network",
    "new_router": "router",
}


def _normalize_attachment(value: Any) -> str:
    if value is None:
        return _DEFAULT_ATTACHMENT
    try:
        normalized = str(value).strip().lower().replace('-', '_').replace(' ', '_')
    except Exception:
        return _DEFAULT_ATTACHMENT
    if normalized in _ATTACHMENT_ALLOWED:
        return normalized
    return _DEFAULT_ATTACHMENT


def _attachment_attempt_order(preference: str) -> List[str]:
    pref = _normalize_attachment(preference)
    if pref == "existing_router":
        return ["existing_router", "existing_switch", "new_switch", "new_router"]
    if pref == "existing_switch":
        return ["existing_switch", "existing_router", "new_switch", "new_router"]
    if pref == "new_router":
        return ["new_router", "existing_router", "existing_switch", "new_switch"]
    # new_switch or default
    return ["new_switch", "existing_switch", "existing_router", "new_router"]


def _enable_rj45_option(session: Any) -> bool:
    """Best-effort attempt to enable RJ45 in session options."""
    if session is None:
        return False
    value = "1"
    # Direct setters (common on recent CORE gRPC wrappers)
    for attr in ("set_session_option", "set_option"):
        setter = getattr(session, attr, None)
        if callable(setter):
            try:
                setter("enablerj45", value)
                logger.debug("HITL: enabled enablerj45 via %s", attr)
                return True
            except Exception as exc:  # pragma: no cover - depends on runtime wrapper
                logger.debug("HITL: %s failed enabling enablerj45: %s", attr, exc)
    # Session options container (dict-like)
    session_opts = getattr(session, "session_options", None)
    if session_opts is not None:
        for attr in ("set", "update", "append", "set_value"):
            setter = getattr(session_opts, attr, None)
            if callable(setter):
                try:
                    setter("enablerj45", value)
                    logger.debug("HITL: enabled enablerj45 via session_options.%s", attr)
                    return True
                except Exception as exc:  # pragma: no cover - depends on runtime wrapper
                    logger.debug("HITL: session_options.%s failed: %s", attr, exc)
        try:
            session_opts["enablerj45"] = value
            logger.debug("HITL: set enablerj45 directly on session_options mapping")
            return True
        except Exception as exc:  # pragma: no cover
            logger.debug("HITL: direct session_options assignment failed: %s", exc)
    return False


def _node_type_rj45() -> Any:
    candidates = ("RJ45", "PHYSICAL", "ETHERNET")
    for name in candidates:
        if hasattr(NodeType, name):
            return getattr(NodeType, name)
    return getattr(NodeType, "DEFAULT", None)


def _switch_node_type() -> Any:
    for name in ("SWITCH", "HUB", "LAN"):
        if hasattr(NodeType, name):
            return getattr(NodeType, name)
    return getattr(NodeType, "DEFAULT", None)


def _router_node_type() -> Any:
    for name in ("ROUTER", "MDR", "PRJ45", "CORE_ROUTER"):
        if hasattr(NodeType, name):
            return getattr(NodeType, name)
    return getattr(NodeType, "DEFAULT", None)


def _safe_get_node(session: Any, node_id: int) -> Any:
    getter = getattr(session, "get_node", None)
    if callable(getter):
        try:
            return getter(node_id)
        except Exception as exc:  # pragma: no cover - wrapper specific
            logger.debug("HITL: get_node(%s) failed: %s", node_id, exc)
    nodes = getattr(session, "nodes", None)
    if isinstance(nodes, dict):
        return nodes.get(node_id)
    if isinstance(nodes, Iterable):
        for node in nodes:
            try:
                if getattr(node, "id", None) == node_id:
                    return node
            except Exception:
                continue
    return None


def _extract_node_id(node: Any, fallback: int) -> int:
    try:
        value = getattr(node, "id", None)
        if value is None:
            value = getattr(node, "node_id", None)
        if value is None:
            return fallback
        return int(value)
    except Exception:
        return fallback


def _determine_existing_ids(session: Any, routers: List[NodeInfo], hosts: List[NodeInfo]) -> List[int]:
    ids = {ni.node_id for ni in routers} | {ni.node_id for ni in hosts}
    nodes = getattr(session, "nodes", None)
    if isinstance(nodes, dict):
        ids |= { _extract_node_id(node, 0) for node in nodes.values() }
    elif isinstance(nodes, Iterable):
        for node in nodes:
            ids.add(_extract_node_id(node, 0))
    return sorted(i for i in ids if i is not None)


def _allocate_node_id(existing: List[int]) -> int:
    base = max(existing) + 1 if existing else 1000
    while base in existing:
        base += 1
    existing.append(base)
    return base


def _next_iface_id(node: Any, cache: Dict[int, int]) -> int:
    node_id = _extract_node_id(node, 0)
    if node_id not in cache:
        max_existing = -1
        try:
            ifaces = getattr(node, "ifaces", None) or getattr(node, "interfaces", None)
        except Exception:
            ifaces = None
        if ifaces:
            for iface in ifaces:
                try:
                    max_existing = max(max_existing, int(getattr(iface, "id", -1)))
                except Exception:
                    continue
        cache[node_id] = max_existing + 1
    next_id = cache[node_id]
    cache[node_id] = next_id + 1
    return next_id


def _make_position_near(peer: Any, index: int) -> Optional[Position]:
    if Position is None:
        return None
    try:
        pos = getattr(peer, "position", None)
        if pos is None:
            return Position(x=100 + index * 40, y=100 + index * 30)
        base_x = getattr(pos, "x", None)
        base_y = getattr(pos, "y", None)
        if base_x is None or base_y is None:
            return Position(x=100 + index * 40, y=100 + index * 30)
        offset = 80 + (index * 20)
        return Position(x=int(base_x) + offset, y=int(base_y) + offset)
    except Exception:
        return Position(x=100 + index * 40, y=100 + index * 30)


def _normalize_iface_name(raw_name: str, counter: int) -> str:
    clean = raw_name.strip().replace(" ", "-")
    clean = "".join(ch for ch in clean if ch.isalnum() or ch in {"-", "_"})
    clean = clean[:48]
    if not clean:
        clean = f"iface-{counter}"
    return clean.lower()


def _make_deterministic_rng(seed: str):
    base = hashlib.sha256(seed.encode("utf-8", "replace")).digest()
    counter = 0

    def _next() -> float:
        nonlocal counter
        counter_bytes = counter.to_bytes(8, "little", signed=False)
        digest = hashlib.sha256(base + counter_bytes).digest()
        counter += 1
        return int.from_bytes(digest[:8], "big") / float(1 << 64)

    return _next


def _compute_hitl_link_ips(
    scenario_key: str,
    iface_name: str,
    ordinal: int,
    *,
    prefix_len: int = 29,
) -> Optional[Dict[str, Any]]:
    """Deterministically derive IPv4 assignments for a HITL uplink.

    Produces a stable /29 (6 usable addresses) inside 10.254.0.0/16 to avoid
    overlap with the default 10.0.0.0/24 preview allocations. Returns None if
    the prefix cannot be derived for any reason.
    """

    try:
        key = f"{scenario_key or '__default__'}|{iface_name or ordinal}|{ordinal}"
        digest = hashlib.sha256(key.encode("utf-8", "replace")).digest()
        index = int.from_bytes(digest[:4], "big")
        base_network = ipaddress.IPv4Network("10.254.0.0/16")
        host_block = 1 << max(0, 32 - prefix_len)
        subnet_span = max(0, prefix_len - base_network.prefixlen)
        total_subnets = max(1, 1 << subnet_span)
        subnet_index = index % total_subnets
        network_address_int = int(base_network.network_address) + (subnet_index * host_block)
        max_address_int = int(base_network.broadcast_address)
        if network_address_int > max_address_int:
            network_address_int = int(base_network.network_address) + (network_address_int % (base_network.num_addresses))
        network = ipaddress.IPv4Network((network_address_int, prefix_len))
        hosts = list(network.hosts())
        if len(hosts) < 3:
            return None
        rng = _make_deterministic_rng(f"{scenario_key or '__default__'}|{iface_name or ordinal}|{ordinal}|ips")
        available = hosts[:]
        selected_hosts: List[ipaddress.IPv4Address] = []
        for _ in range(3):
            if not available:
                break
            try:
                choice_idx = int(rng() * len(available)) % len(available)
            except Exception:
                choice_idx = 0
            selected_hosts.append(available.pop(choice_idx))
        if len(selected_hosts) < 3:
            return None
        return {
            "network": str(network.network_address),
            "network_cidr": f"{network.network_address}/{prefix_len}",
            "prefix_len": prefix_len,
            "netmask": str(network.netmask),
            "broadcast_ip4": str(network.broadcast_address),
            "existing_router_ip4": str(selected_hosts[0]),
            "new_router_ip4": str(selected_hosts[1]),
            "rj45_ip4": str(selected_hosts[2]),
        }
    except Exception:
        return None


def _apply_iface_ip(iface: Any, ip: Optional[str], prefix_len: Optional[int]) -> None:
    if iface is None or not ip or prefix_len is None:
        return
    try:
        setattr(iface, "ip4", ip)
    except Exception:
        pass
    try:
        setattr(iface, "ip4_mask", int(prefix_len))
    except Exception:
        pass


def _is_switch_like(node: Any) -> bool:
    if node is None:
        return False
    node_type = getattr(node, "type", None)
    try:
        if hasattr(NodeType, "SWITCH") and node_type == getattr(NodeType, "SWITCH"):
            return True
    except Exception:
        pass
    try:
        if hasattr(NodeType, "HUB") and node_type == getattr(NodeType, "HUB"):
            return True
    except Exception:
        pass
    if isinstance(node_type, str) and node_type.lower() in {"switch", "hub", "lan"}:
        return True
    model = getattr(node, "model", None)
    if isinstance(model, str) and model.lower() in {"switch", "lan", "hub"}:
        return True
    name = getattr(node, "name", None)
    if isinstance(name, str) and name.lower().startswith("switch"):
        return True
    return False


def _gather_switch_nodes(session: Any) -> List[Any]:
    nodes_attr = getattr(session, "nodes", None)
    if isinstance(nodes_attr, dict):
        candidates = list(nodes_attr.values())
    elif isinstance(nodes_attr, Iterable):
        candidates = list(nodes_attr)
    else:
        candidates = []
    switch_nodes = [node for node in candidates if _is_switch_like(node)]
    switch_nodes.sort(key=lambda n: _extract_node_id(n, 0))
    return switch_nodes


def _link_nodes(session: Any, node_a: Any, node_b: Any, iface_a: Optional[Interface], iface_b: Optional[Interface]) -> bool:
    attempts: List[Tuple[str, Tuple[Any, ...], Dict[str, Any]]] = [
        ("kw-obj", tuple(), {"node1": node_a, "node2": node_b, "iface1": iface_a, "iface2": iface_b}),
        ("kw-id", tuple(), {"node1_id": _extract_node_id(node_a, 0), "node2_id": _extract_node_id(node_b, 0), "iface1": iface_a, "iface2": iface_b}),
        ("pos-obj", (node_a, node_b), {"iface1": iface_a, "iface2": iface_b}),
        ("pos-id", (_extract_node_id(node_a, 0), _extract_node_id(node_b, 0)), {"iface1": iface_a, "iface2": iface_b}),
        ("simple-kw", tuple(), {"node1": node_a, "node2": node_b}),
        ("simple-id", tuple(), {"node1_id": _extract_node_id(node_a, 0), "node2_id": _extract_node_id(node_b, 0)}),
        ("simple-pos", (node_a, node_b), {}),
    ]
    add_link = getattr(session, "add_link", None)
    if not callable(add_link):
        logger.warning("HITL: session has no add_link; cannot connect RJ45 node")
        return False
    for label, pos_args, kw_args in attempts:
        try:
            add_link(*pos_args, **kw_args)
            logger.debug("HITL: add_link succeeded via %s", label)
            return True
        except Exception as exc:
            logger.debug("HITL: add_link attempt %s failed: %s", label, exc)
            continue
    logger.warning("HITL: failed to link RJ45 node to peer after all attempts")
    return False


def _link_node_to_router(
    session: Any,
    new_node: Any,
    router_candidates: List[Any],
    iface_id_cache: Dict[int, int],
    rng,
    name_seed: str,
) -> Tuple[bool, Optional[int], Optional[Any], Optional[Any]]:
    if not router_candidates:
        return False, None, None, None
    try:
        choice_idx = int(rng() * len(router_candidates)) % len(router_candidates)
    except Exception:
        choice_idx = 0
    try:
        router_node = router_candidates[choice_idx]
    except Exception:
        router_node = router_candidates[0]
    router_id = _extract_node_id(router_node, 0)
    if router_id is None:
        return False, None, None, None
    router_iface_id = _next_iface_id(router_node, iface_id_cache)
    new_iface_id = _next_iface_id(new_node, iface_id_cache)
    router_iface_name = f"{getattr(router_node, 'name', 'router')}-{name_seed}".lower()
    new_iface_name = f"{name_seed}".lower()
    try:
        router_iface = Interface(id=router_iface_id, name=router_iface_name)
    except Exception:
        router_iface = None
    try:
        new_iface = Interface(id=new_iface_id, name=new_iface_name)
    except Exception:
        new_iface = None
    linked = _link_nodes(session, new_node, router_node, new_iface, router_iface)
    return linked, router_id, new_iface, router_iface


def _prepare_rj45_options(node: Any, iface_name: str) -> None:
    try:
        setattr(node, "model", "RJ45")
    except Exception:
        pass
    try:
        setattr(node, "interface", iface_name)
    except Exception:
        pass
    options_obj = getattr(node, "options", None)
    if options_obj is None:
        options_obj = SimpleNamespace()
        try:
            setattr(node, "options", options_obj)
        except Exception:
            pass
    for key in ("type", "model", "interface", "device"):
        try:
            setattr(options_obj, key, "RJ45" if key in {"type", "model"} else iface_name)
        except Exception:
            continue
    return


def _push_rj45_edit(session: Any, node: Any) -> None:
    editor = getattr(session, "edit_node", None)
    if not callable(editor):
        return
    try:
        options_obj = getattr(node, "options", None)
        editor(getattr(node, "id"), options=options_obj)
    except Exception as exc:  # pragma: no cover - depends on runtime wrapper
        logger.debug("HITL: edit_node failed for RJ45 node %s: %s", getattr(node, "id", None), exc)


def attach_hitl_rj45_nodes(
    session: Any,
    routers: List[NodeInfo],
    hosts: List[NodeInfo],
    hitl_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Create RJ45 nodes bound to host interfaces and link them into the session."""
    summary: Dict[str, Any] = {
        "enabled": bool(hitl_config.get("enabled")),
        "interfaces": [],
        "session_option_enabled": False,
        "created_nodes": [],
        "created_network_nodes": [],
        "created_router_nodes": [],
    }
    if not summary["enabled"]:
        return summary
    interfaces = hitl_config.get("interfaces")
    if not interfaces:
        logger.info("HITL: enabled but no interfaces provided; skipping RJ45 attachment")
        return summary
    if session is None:
        logger.warning("HITL: no active CORE session; cannot attach RJ45 nodes")
        return summary
    node_type = _node_type_rj45()
    if node_type is None:
        logger.warning("HITL: RJ45 node type unavailable; skipping attachment")
        return summary
    # Determine peers
    router_nodes: List[Any] = []
    for info in routers:
        node = _safe_get_node(session, info.node_id)
        if node:
            router_nodes.append(node)
    host_nodes: List[Any] = []
    for info in hosts:
        node = _safe_get_node(session, info.node_id)
        if node:
            host_nodes.append(node)
    peer_nodes: List[Any] = router_nodes if router_nodes else host_nodes
    if not router_nodes and not host_nodes:
        logger.warning("HITL: no eligible router/host peers detected; RJ45 nodes may attach to standalone networks only")
    switch_nodes = _gather_switch_nodes(session)
    existing_ids = _determine_existing_ids(session, routers, hosts)
    iface_id_cache: Dict[int, int] = {}
    summary["session_option_enabled"] = _enable_rj45_option(session)
    created_nodes: List[int] = []
    created_network_nodes: List[int] = []
    created_router_nodes: List[int] = []
    scenario_key = str(hitl_config.get("scenario_key") or hitl_config.get("scenario_name") or "")
    preference_values: List[str] = []
    for iface_entry in interfaces:
        if isinstance(iface_entry, dict):
            preference_values.append(_normalize_attachment(iface_entry.get("attachment")))
        else:
            preference_values.append(_DEFAULT_ATTACHMENT)
    for idx, iface_entry in enumerate(interfaces):
        if isinstance(iface_entry, str):
            iface_entry = {"name": iface_entry, "attachment": _DEFAULT_ATTACHMENT}
        if not isinstance(iface_entry, dict):
            continue
        raw_name = str(iface_entry.get("name") or f"iface-{idx}")
        clean_name = _normalize_iface_name(raw_name, idx)
        node_name = f"hitl-{clean_name}"
        node_id = _allocate_node_id(existing_ids)
        preference = preference_values[idx] if idx < len(preference_values) else _DEFAULT_ATTACHMENT
        attempt_order = _attachment_attempt_order(preference)
        anchor = None
        target_node: Any = None
        assignment_kind = "peer"
        uplink_router_id: Optional[int] = None
        uplink_linked: bool = False
        router_link_ips: Optional[Dict[str, Any]] = None
        rng_seed = f"{scenario_key}|{raw_name}|{idx}|{len(interfaces)}"
        rng = _make_deterministic_rng(rng_seed)
        for attempt in attempt_order:
            if attempt == "existing_router" and router_nodes:
                anchor = router_nodes[int(rng() * len(router_nodes)) % len(router_nodes)]
                target_node = anchor
                assignment_kind = "peer"
                break
            if attempt == "existing_switch" and switch_nodes:
                anchor = switch_nodes[int(rng() * len(switch_nodes)) % len(switch_nodes)]
                target_node = anchor
                assignment_kind = "switch"
                break
            if attempt == "new_router":
                router_type = _router_node_type()
                router_name = f"hitl-router-{clean_name}"
                router_id = _allocate_node_id(existing_ids)
                router_position = _make_position_near(router_nodes[0] if router_nodes else None, idx + 10)
                router_candidates = list(router_nodes)
                try:
                    target_node = session.add_node(router_id, _type=router_type, position=router_position, name=router_name)
                    created_nodes.append(router_id)
                    created_router_nodes.append(router_id)
                    assignment_kind = "router"
                    anchor = target_node
                    if router_candidates:
                        link_ips_candidate = _compute_hitl_link_ips(scenario_key, raw_name, idx)
                        uplink_linked, uplink_router_id, new_router_iface_obj, peer_router_iface_obj = _link_node_to_router(
                            session,
                            target_node,
                            router_candidates,
                            iface_id_cache,
                            rng,
                            f"{clean_name}-uplink",
                        )
                        if link_ips_candidate:
                            router_link_ips = link_ips_candidate
                            _apply_iface_ip(new_router_iface_obj, link_ips_candidate.get("new_router_ip4"), link_ips_candidate.get("prefix_len"))
                            _apply_iface_ip(peer_router_iface_obj, link_ips_candidate.get("existing_router_ip4"), link_ips_candidate.get("prefix_len"))
                    router_nodes.append(target_node)
                    break
                except Exception as exc:
                    logger.error("HITL: failed to create router %s: %s", router_name, exc)
                    target_node = None
                    if router_id in existing_ids:
                        try:
                            existing_ids.remove(router_id)
                        except Exception:
                            pass
                    continue
            if attempt == "new_switch":
                network_id = _allocate_node_id(existing_ids)
                network_type = _switch_node_type()
                network_name = f"hitl-net-{clean_name}"
                network_position = _make_position_near(None, idx + 1)
                try:
                    network_node = session.add_node(network_id, _type=network_type, position=network_position, name=network_name)
                    try:
                        setattr(network_node, "model", "switch")
                    except Exception:
                        pass
                    created_nodes.append(network_id)
                    created_network_nodes.append(network_id)
                    switch_nodes.append(network_node)
                    target_node = network_node
                    assignment_kind = "network"
                    anchor = network_node
                    if router_nodes:
                        uplink_linked, uplink_router_id, _, _ = _link_node_to_router(
                            session,
                            network_node,
                            router_nodes,
                            iface_id_cache,
                            rng,
                            f"{clean_name}-uplink",
                        )
                    break
                except Exception as exc:
                    logger.error("HITL: failed to create network node %s: %s", network_name, exc)
                    target_node = None
                    if network_id in existing_ids:
                        try:
                            existing_ids.remove(network_id)
                        except Exception:
                            pass
                    continue
        if target_node is None:
            if peer_nodes:
                anchor = peer_nodes[idx % len(peer_nodes)]
                target_node = anchor
                assignment_kind = "peer"
            elif switch_nodes:
                anchor = switch_nodes[idx % len(switch_nodes)]
                target_node = anchor
                assignment_kind = "switch"
        position = _make_position_near(anchor, idx)
        try:
            logger.info("HITL: adding RJ45 node %s (id=%s) targeting interface %s", node_name, node_id, raw_name)
        except Exception:
            pass
        try:
            rj45_node = session.add_node(node_id, _type=node_type, position=position, name=node_name)
        except Exception as exc:
            logger.error("HITL: failed to add RJ45 node %s: %s", node_name, exc)
            summary["interfaces"].append({"name": raw_name, "created": False, "reason": str(exc)})
            continue
        try:
            setattr(rj45_node, "name", node_name)
        except Exception:
            pass
        _prepare_rj45_options(rj45_node, raw_name)
        _push_rj45_edit(session, rj45_node)
        network_node = None
        if assignment_kind == "network" and target_node is not None and getattr(target_node, "id", None) in created_network_nodes:
            network_node = target_node
        if assignment_kind == "router" and target_node is not None:
            try:
                options_obj = getattr(target_node, "options", None)
                if options_obj is None:
                    options_obj = SimpleNamespace()
                    setattr(target_node, "options", options_obj)
                setattr(target_node, "type", getattr(NodeType, "ROUTER", getattr(NodeType, "DEFAULT", None)))
            except Exception:
                pass
        if target_node is None:
            summary["interfaces"].append({
                "name": raw_name,
                "normalized_name": clean_name,
                "created": False,
                "reason": "no-target",
            })
            continue
        iface_peer_id = _next_iface_id(target_node, iface_id_cache)
        peer_iface_name = f"{getattr(target_node, 'name', 'peer')}-hitl{idx}".lower()
        try:
            peer_iface = Interface(id=iface_peer_id, name=peer_iface_name)
        except Exception:
            peer_iface = None
        try:
            rj_iface = Interface(id=0, name=f"{clean_name}-uplink")
        except Exception:
            rj_iface = None
        if assignment_kind == "router" and router_link_ips:
            _apply_iface_ip(rj_iface, router_link_ips.get("rj45_ip4"), router_link_ips.get("prefix_len"))
        linked = _link_nodes(session, rj45_node, target_node, rj_iface, peer_iface)
        created_nodes.append(node_id)
        summary_entry = {
            "name": raw_name,
            "normalized_name": clean_name,
            "rj45_node_id": _extract_node_id(rj45_node, node_id),
            "target_node_id": _extract_node_id(target_node, 0),
            "assignment": assignment_kind,
            "linked": linked,
            "attachment": preference,
        }
        summary_entry["peer_node_id"] = summary_entry["target_node_id"]
        if linked and peer_iface is not None:
            summary_entry["peer_iface_id"] = getattr(peer_iface, "id", iface_peer_id)
        if network_node is not None:
            summary_entry["network_node_id"] = _extract_node_id(network_node, 0)
        if assignment_kind == "router":
            summary_entry["router_node_id"] = summary_entry["target_node_id"]
        if router_link_ips:
            summary_entry["link_network_cidr"] = router_link_ips.get("network_cidr") or router_link_ips.get("network")
            summary_entry["existing_router_ip4"] = router_link_ips.get("existing_router_ip4")
            summary_entry["new_router_ip4"] = router_link_ips.get("new_router_ip4")
            summary_entry["rj45_ip4"] = router_link_ips.get("rj45_ip4")
            summary_entry["prefix_len"] = router_link_ips.get("prefix_len")
            summary_entry["netmask"] = router_link_ips.get("netmask")
        if uplink_router_id is not None:
            summary_entry["uplink_router_node_id"] = uplink_router_id
            summary_entry["uplink_linked"] = uplink_linked
        summary["interfaces"].append(summary_entry)
    summary["created_nodes"] = created_nodes
    if created_network_nodes:
        summary["created_network_nodes"] = created_network_nodes
    if created_router_nodes:
        summary["created_router_nodes"] = created_router_nodes
    return summary


def predict_hitl_link_ips(scenario_key: str, interface_name: str, ordinal: int) -> Optional[Dict[str, Any]]:
    """Public helper for callers needing deterministic HITL uplink IP allocations."""

    name = interface_name if isinstance(interface_name, str) else str(interface_name or ordinal)
    return _compute_hitl_link_ips(scenario_key, name, ordinal)
