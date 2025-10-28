from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Set, Any
from types import SimpleNamespace
from collections import defaultdict
import math
import random
import logging
import ipaddress

try:  # pragma: no cover - offline mode exercised via CLI tests
    from core.api.grpc import client  # type: ignore
    from core.api.grpc.wrappers import NodeType, Position, Interface  # type: ignore
    CORE_GRPC_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover
    CORE_GRPC_AVAILABLE = False

    class _DummyCoreClient:
        def __init__(self, *_, **__):  # noqa: D401 - minimal placeholder
            raise RuntimeError("core.api.grpc is not installed; CORE operations are unavailable")

    import types as _types
    client = _types.SimpleNamespace(CoreGrpcClient=_DummyCoreClient)  # type: ignore[attr-defined]

    class _NodeTypeValue:
        def __init__(self, name: str):
            self.name = name

        def __repr__(self) -> str:  # pragma: no cover - debug aid
            return self.name

    class NodeType:  # type: ignore
        DEFAULT = _NodeTypeValue("DEFAULT")
        SWITCH = _NodeTypeValue("SWITCH")
        ROUTER = _NodeTypeValue("ROUTER")
        DOCKER = _NodeTypeValue("DOCKER")
        RJ45 = _NodeTypeValue("RJ45")

    class Position:  # type: ignore
        def __init__(self, x: int = 0, y: int = 0, z: int = 0):
            self.x = x
            self.y = y
            self.z = z

    class Interface:  # type: ignore
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

from ..types import NodeInfo, ServiceInfo, RoutingInfo
from ..utils.allocators import UniqueAllocator, SubnetAllocator, make_subnet_allocator
from ..planning.router_host_plan import plan_router_counts  # new pure-planning helper
from ..utils.grpc_helpers import safe_create_session
from ..utils.services import (
    map_role_to_node_type,
    distribute_services,
    mark_node_as_router,
    set_node_services,
    ensure_service,
    remove_service,
    has_service,
    ROUTING_STACK_SERVICES,
)
from ..utils.allocation import compute_counts_by_factor

logger = logging.getLogger(__name__)
import os

# Enable verbose gRPC call trace if env var set (default off unless user requests)
def _env_flag(name: str, default_on: bool = True) -> bool:
    val = os.getenv(name)
    if val is None:
        return default_on  # default to ON for web GUI unless explicitly disabled
    return val not in ("0", "false", "False", "")

# By default (no env override) enable diagnostics and gRPC tracing so web GUI users get visibility automatically.
# Users can explicitly disable by setting the env var to 0/false.
GRPC_TRACE = _env_flag("CORETG_GRPC_TRACE", default_on=True)
GRPC_FORCE_SIMPLE = _env_flag("CORETG_GRPC_FORCE_SIMPLE", default_on=False)  # keep simple fallback OFF by default
DIAG_ENABLED = _env_flag("CORETG_DIAG", default_on=True)

# Optional global seed for deterministic topology aspects (can be overridden externally)
GLOBAL_RANDOM_SEED: Optional[int] = None

def set_global_random_seed(seed: Optional[int]) -> None:
    """Set a global random seed for deterministic router placement / protocol assignment.

    Passing None leaves randomness untouched. This does not guarantee full determinism if
    other modules use randomness separately, but it stabilizes this module's primary flows.
    """
    global GLOBAL_RANDOM_SEED
    GLOBAL_RANDOM_SEED = seed
    if seed is not None:
        try:
            random.seed(seed)
            logger.info("Applied global random seed %s for topology generation", seed)
        except Exception:
            logger.debug("Failed applying random seed %s", seed)

# --- Helper utilities (restored) ---

def _type_desc(t: NodeType) -> str:
    try:
        return getattr(t, 'name', str(t))
    except Exception:
        return str(t)

def _make_safe_link_tracker():
    existing: Set[Tuple[int, int]] = set()
    link_failures: int = 0
    counters = { 'attempts': 0, 'success': 0, 'fail_total': 0 }
    def _compat_add_link(sess, a_obj, b_obj, iface1=None, iface2=None):
        """Attempt to add a link using multiple possible CORE API signatures.

        Strategy:
        1. Detect callable signature parameter names (via inspect) to decide whether positional args are allowed.
        2. Prefer keyword-based calls (node1/node2) when available to avoid positional mismatch TypeErrors.
        3. Only attempt positional fallbacks if the signature length suggests it still supports them.
        4. Log (debug) each failed variant once per distinct error class to aid troubleshooting without spamming.
        """
        a_id = getattr(a_obj, 'id', a_obj)
        b_id = getattr(b_obj, 'id', b_obj)
        import inspect
        add_link = getattr(sess, 'add_link', None)
        if add_link is None:
            raise RuntimeError('Session has no add_link method')
        try:
            sig = inspect.signature(add_link)
            params = list(sig.parameters.values())
        except Exception:
            sig = None
            params = []
        # Determine capabilities
        kw_names = {p.name for p in params}
        has_var_pos = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        # Default allow positional
        accepts_positional = True
        # Only disable positional if we have a very small fixed signature AND no varargs/kwargs AND no known kw names
        if (len(params) <= 2) and not has_var_pos and not has_var_kw and not (kw_names & {'node1','node2','node1_id','node2_id'}):
            accepts_positional = False
        # Prepare attempt call patterns
        attempt_order = []
        # Keyword object form
        if {'node1', 'node2'} & kw_names:
            attempt_order.append(('kw-obj-ifaces', lambda: add_link(node1=a_obj, node2=b_obj, iface1=iface1, iface2=iface2)))
            attempt_order.append(('kw-obj-noif', lambda: add_link(node1=a_obj, node2=b_obj)))
        # Keyword id form (some variants use node1_id/node2_id)
        if {'node1_id', 'node2_id'} & kw_names:
            attempt_order.append(('kw-id-ifaces', lambda: add_link(node1_id=a_id, node2_id=b_id, iface1=iface1, iface2=iface2)))
            attempt_order.append(('kw-id-noif', lambda: add_link(node1_id=a_id, node2_id=b_id)))
            # QoS keyword variant if user wants delay/bandwidth
            try:
                _d = int(os.getenv('CORETG_LINK_DELAY', '0') or 0)
                _bw = int(os.getenv('CORETG_LINK_BW', '0') or 0)
            except Exception:
                _d = 0; _bw = 0
            if _d or _bw:
                def _kw_id_if_qos():
                    kwargs = {'node1_id': a_id, 'node2_id': b_id, 'iface1': iface1, 'iface2': iface2}
                    if _d: kwargs['delay'] = _d
                    if _bw: kwargs['bandwidth'] = _bw
                    return add_link(**kwargs)
                attempt_order.insert(0, ('kw-id-ifaces-qos', _kw_id_if_qos))
        # Positional object or id fallback only if accepted
        if accepts_positional:
            # with ifaces
            attempt_order.append(('pos-obj-ifaces', lambda: add_link(a_obj, b_obj, iface1=iface1, iface2=iface2)))
            attempt_order.append(('pos-id-ifaces', lambda: add_link(a_id, b_id, iface1=iface1, iface2=iface2)))
            # no ifaces
            attempt_order.append(('pos-obj-noif', lambda: add_link(a_obj, b_obj)))
            attempt_order.append(('pos-id-noif', lambda: add_link(a_id, b_id)))
            # Add positional QoS variant (sample provided by user)
            try:
                _d2 = int(os.getenv('CORETG_LINK_DELAY', '0') or 0)
                _bw2 = int(os.getenv('CORETG_LINK_BW', '0') or 0)
            except Exception:
                _d2 = 0; _bw2 = 0
            if _d2 or _bw2:
                def _pos_id_ifaces_qos():
                    return add_link(a_id, b_id, iface1=iface1, iface2=iface2, **({k:v for k,v in {'delay':_d2,'bandwidth':_bw2}.items() if v}))
                # Put before plain positional iface variant to prefer QoS if requested
                attempt_order.insert( (0 if not {'node1','node2'} & kw_names else 2), ('pos-id-ifaces-qos', _pos_id_ifaces_qos) )
        # Heuristic: if we only have *args/**kwargs (generic signature) and no explicit kw variants were added, still try likely keyword patterns.
        if has_var_kw and not any(lbl.startswith('kw-') for lbl, _ in attempt_order):
            # Prefer object keyword forms first; id-based forms later (some CORE builds reject *_id kwargs)
            attempt_order.insert(0, ('kw-guess-obj-ifaces', lambda: add_link(node1=a_obj, node2=b_obj, iface1=iface1, iface2=iface2)))
            attempt_order.insert(1, ('kw-guess-obj-noif', lambda: add_link(node1=a_obj, node2=b_obj)))
            attempt_order.insert(2, ('kw-guess-id-ifaces', lambda: add_link(node1_id=a_id, node2_id=b_id, iface1=iface1, iface2=iface2)))
            attempt_order.insert(3, ('kw-guess-id-noif', lambda: add_link(node1_id=a_id, node2_id=b_id)))
        if not attempt_order:
            # Generic fallback for opaque signatures (e.g., def add_link(*args, **kwargs))
            attempt_order = [
                ('gen-obj-ifaces', lambda: add_link(a_obj, b_obj, iface1=iface1, iface2=iface2)),
                ('gen-id-ifaces', lambda: add_link(a_id, b_id, iface1=iface1, iface2=iface2)),
                ('gen-obj-noif', lambda: add_link(a_obj, b_obj)),
                ('gen-id-noif', lambda: add_link(a_id, b_id)),
            ]
            if GRPC_TRACE or DIAG_ENABLED:
                try:
                    logger.warning("[grpc.sig.fallback] using generic variants; params=%s", [p.name for p in params])
                except Exception:
                    pass
        last_exc = None
        def _iface_repr(ifc):
            if not ifc: return '-'
            try:
                return f"{getattr(ifc,'name','')}({getattr(ifc,'id','')}) {getattr(ifc,'ip4','')}/{getattr(ifc,'ip4_mask','')}"
            except Exception:
                return '-'
        skip_positional = False
        skip_id_kwargs = False
        for label, fn in attempt_order:
            if skip_id_kwargs and ('-id-' in label or label.startswith('kw-id') or label.startswith('kw-guess-id') or label.startswith('kw-id')):
                continue
            if skip_positional and label.startswith('pos-'):
                continue
            if GRPC_TRACE:
                logger.info("[grpc.try] variant=%s a=%s b=%s iface1=%s iface2=%s", label, a_id, b_id, _iface_repr(iface1), _iface_repr(iface2))
            try:
                fn()
                if GRPC_TRACE:
                    logger.info("[grpc.try.ok] variant=%s a=%s b=%s", label, a_id, b_id)
                return label
            except Exception as e:
                last_exc = e
                # If this is a positional-variant failure complaining about positional args, stop trying further positional variants.
                try:
                    msg = str(e)
                    if label.startswith('pos-') and 'takes 1 positional argument' in msg:
                        skip_positional = True
                    if ('unexpected keyword argument' in msg) and ("node1_id" in msg or "node2_id" in msg):
                        skip_id_kwargs = True
                        if GRPC_TRACE or DIAG_ENABLED:
                            logger.info("[grpc.try.prune] pruning remaining id-based variants after %s failure", label)
                except Exception:
                    pass
                if GRPC_TRACE:
                    logger.info("[grpc.try.fail] variant=%s a=%s b=%s err=%s", label, a_id, b_id, e)
                else:
                    logger.debug("add_link fallback '%s' failed: %s", label, e)
                continue
        if last_exc:
            raise last_exc

    def safe_add(session_obj, a_obj, b_obj, iface1=None, iface2=None):
        try:
            a_id = getattr(a_obj, 'id', a_obj)
            b_id = getattr(b_obj, 'id', b_obj)
        except Exception:
            a_id, b_id = a_obj, b_obj
        key = (min(a_id, b_id), max(a_id, b_id))
        if DIAG_ENABLED:
            try:
                logger.info("[diag.link.call] attempting link a=%s b=%s dup=%s iface1=%s iface2=%s", a_id, b_id, key in existing, getattr(iface1,'name',None), getattr(iface2,'name',None))
            except Exception:
                pass
        if key in existing:
            return False
        try:
            counters['attempts'] += 1
            label = _compat_add_link(session_obj, a_obj, b_obj, iface1=iface1, iface2=iface2)
            if label is None:
                raise RuntimeError('add_link: internal inconsistency, label None after success')
            if GRPC_TRACE:
                try:
                    def _iface_repr(ifc):
                        if not ifc: return '-'
                        return f"{getattr(ifc,'name', '')}({getattr(ifc,'id', '')}) {getattr(ifc,'ip4','')}/{getattr(ifc,'ip4_mask','')}"
                    logger.info("[grpc] add_link a=%s b=%s via=%s iface1=%s iface2=%s", a_id, b_id, label, _iface_repr(iface1), _iface_repr(iface2))
                except Exception:
                    pass
            existing.add(key)
            counters['success'] += 1
            return True
        except Exception as e:
            nonlocal link_failures
            link_failures += 1
            counters['attempts'] += 1
            counters['fail_total'] += 1
            if GRPC_TRACE:
                logger.error("[grpc.fail] add_link all variants failed a=%s b=%s err=%s", a_id, b_id, e)
            # Optional simple fallback if enabled
            if GRPC_FORCE_SIMPLE:
                try:
                    if hasattr(session_obj, 'add_link'):
                        try:
                            session_obj.add_link(node1_id=a_id, node2_id=b_id)
                        except TypeError:
                            session_obj.add_link(a_id, b_id)  # type: ignore
                        existing.add(key)
                        if GRPC_TRACE:
                            logger.info("[grpc.force-simple] add_link (no ifaces) a=%s b=%s", a_id, b_id)
                        return True
                except Exception as e2:
                    if GRPC_TRACE:
                        logger.error("[grpc.force-simple.fail] a=%s b=%s err=%s", a_id, b_id, e2)
            return False
    return existing, safe_add, counters


def _log_add_node_result(session_obj, node_obj, requested_id, node_type, name, position=None):
    if not logger.isEnabledFor(logging.INFO):
        return
    try:
        session_type = type(session_obj).__name__
    except Exception:
        session_type = str(type(session_obj))
    try:
        actual_id = getattr(node_obj, 'id', None)
    except Exception:
        actual_id = None
    pos_desc = None
    if position is not None:
        try:
            pos_desc = (getattr(position, 'x', None), getattr(position, 'y', None))
        except Exception:
            try:
                pos_desc = (position[0], position[1]) if isinstance(position, (tuple, list)) else position
            except Exception:
                pos_desc = None
    try:
        attr_type = getattr(node_obj, "type", None)
    except Exception:
        attr_type = None
    try:
        attr_image = getattr(node_obj, "image", None)
    except Exception:
        attr_image = None
    try:
        attr_compose = getattr(node_obj, "compose", None)
    except Exception:
        attr_compose = None
    try:
        attr_compose_name = getattr(node_obj, "compose_name", None)
    except Exception:
        attr_compose_name = None
    try:
        logger.info(
            "[grpc.call] session.add_node name=%s requested_id=%s actual_id=%s type=%s session_type=%s position=%s attr_type=%s attr_image=%s compose=%s compose_name=%s",
            name,
            requested_id,
            actual_id,
            _type_desc(node_type) if node_type is not None else None,
            session_type,
            pos_desc,
            attr_type,
            attr_image,
            attr_compose,
            attr_compose_name,
        )
    except Exception:
        pass

def _apply_docker_compose_meta(node, rec, session=None):
    """Attach docker compose metadata if available (best-effort, non-fatal)."""
    try:
        if not node:
            return
        n = getattr(node, 'name', None)
        if not n:
            return
        compose_path = None
        try:
            if rec:
                compose_path = rec.get('compose_path')
                logger.info(
                    "[vuln-node] metadata lookup node=%s compose_path=%s record_keys=%s",
                    n,
                    compose_path,
                    sorted(rec.keys()),
                )
                try:
                    startup = rec.get('Startup') or rec.get('startup')
                    if startup:
                        logger.info("[vuln-node] node=%s record startup=%s", n, startup)
                except Exception:
                    pass
                try:
                    command = rec.get('Command') or rec.get('command')
                    if command:
                        logger.info("[vuln-node] node=%s record command=%s", n, command)
                except Exception:
                    pass
        except Exception:
            compose_path = None
        if not compose_path:
            compose_path = f"/tmp/vulns/docker-compose-{n}.yml"
            logger.warning(
                "[vuln-node] node=%s compose_path missing in record; falling back to %s",
                n,
                compose_path,
            )
        path_exists = False
        path_size = None
        try:
            path_exists = os.path.exists(compose_path)
            if path_exists:
                path_size = os.path.getsize(compose_path)
        except Exception:
            path_exists = False
        if not path_exists:
            logger.warning(
                "[vuln-node] node=%s compose file not found at %s (CORE may fall back to default docker behavior)",
                n,
                compose_path,
            )
        else:
            logger.info(
                "[vuln-node] node=%s compose file ready path=%s size=%s bytes",
                n,
                compose_path,
                path_size,
            )
        vname = None
        try:
            if rec:
                vname = rec.get('Name') or rec.get('name') or rec.get('Title') or rec.get('title')
        except Exception:
            vname = None
        if not vname:
            try:
                vname = n
            except Exception:
                vname = None
        try:
            logger.debug("[vuln-node] node=%s existing compose attr=%s", n, getattr(node, 'compose', None))
        except Exception:
            pass
        try:
            setattr(node, 'compose', compose_path)
        except Exception:
            pass
        try:
            setattr(node, 'image', "")
        except Exception:
            pass
        if vname:
            try:
                setattr(node, 'compose_name', str(vname))
            except Exception:
                pass
        try:
            logger.debug(
                "[vuln-node] node=%s after attribute set compose=%s compose_name=%s",
                n,
                getattr(node, 'compose', None),
                getattr(node, 'compose_name', None),
            )
        except Exception:
            pass
        try:
            options = getattr(node, 'options', None)
            if options is not None:
                try:
                    logger.debug(
                        "[vuln-node] node=%s existing options before compose update=%s",
                        n,
                        vars(options) if hasattr(options, '__dict__') else options,
                    )
                except Exception:
                    pass
                try:
                    setattr(options, 'compose', compose_path)
                except Exception:
                    pass
                if vname:
                    try:
                        setattr(options, 'compose_name', str(vname))
                    except Exception:
                        pass
                try:
                    setattr(options, 'type', "")
                except Exception:
                    pass
                try:
                    setattr(options, 'image', "")
                except Exception:
                    pass
                try:
                    logger.debug(
                        "[vuln-node] node=%s options after compose update=%s",
                        n,
                        vars(options) if hasattr(options, '__dict__') else options,
                    )
                except Exception:
                    pass
        except Exception:
            pass
        if session is not None:
            image_hint = None
            try:
                if rec:
                    image_hint = rec.get('Image') or rec.get('image') or rec.get('DockerImage')
            except Exception:
                image_hint = None
            try:
                logger.info(
                    "[vuln-node] node=%s compose=%s compose_name=%s image=%s exists=%s size=%s session_edit=%s",
                    getattr(node, 'name', None),
                    compose_path,
                    vname,
                    image_hint,
                    path_exists,
                    path_size,
                    hasattr(session, 'edit_node'),
                )
            except Exception:
                pass
            try:
                options_obj = getattr(node, 'options', None)
            except Exception:
                options_obj = None
            if options_obj is None:
                options_obj = SimpleNamespace()
                try:
                    setattr(node, 'options', options_obj)
                except Exception:
                    pass
            else:
                try:
                    logger.debug(
                        "[vuln-node] node=%s options namespace pre-edit=%s",
                        n,
                        vars(options_obj) if hasattr(options_obj, '__dict__') else options_obj,
                    )
                except Exception:
                    pass
            try:
                setattr(options_obj, 'compose', compose_path)
            except Exception:
                pass
            if vname:
                try:
                    setattr(options_obj, 'compose_name', str(vname))
                except Exception:
                    pass
            try:
                setattr(options_obj, 'type', "")
            except Exception:
                pass
            try:
                setattr(options_obj, 'image', "")
            except Exception:
                pass
            try:
                if hasattr(session, 'edit_node'):
                    logger.debug(
                        "[vuln-node] edit_node id=%s compose=%s compose_name=%s options=%s",
                        node.id,
                        getattr(options_obj, 'compose', None),
                        getattr(options_obj, 'compose_name', None),
                        vars(options_obj) if hasattr(options_obj, '__dict__') else options_obj,
                    )
                    resp = session.edit_node(node.id, options=options_obj)
                    try:
                        logger.debug("[vuln-node] edit_node response node=%s resp=%s", n, resp)
                    except Exception:
                        pass
            except Exception:
                logger.debug('Failed to push compose options via edit_node for node %s', getattr(node, 'name', None))
    except Exception:
        logger.debug('Failed to set docker compose metadata for node %s', getattr(node, 'name', None))

def _router_node_type():
    """Return router-capable node type (prefer DOCKER if available for richer services)."""
    try:
        if hasattr(NodeType, 'ROUTER'):
            return getattr(NodeType, 'ROUTER')
    except Exception:
        pass
    return NodeType.DEFAULT


def build_star_from_roles(core,
                          role_counts: Dict[str, int],
                          services: Optional[List[ServiceInfo]] = None,
                          ip4_prefix: str = "10.0.0.0/24",
                          ip_mode: str = "private",
                          ip_region: str = "all",
                          docker_slot_plan: Optional[Dict[str, Dict[str, str]]] = None):
    logger.info("Creating CORE session and building star topology")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = safe_create_session(core)
    if DIAG_ENABLED:
        try:
            al = getattr(session, 'add_link', None)
            logger.info("[diag.session] star session=%r has_add_link=%s add_link_type=%s", session, bool(al), type(al))
        except Exception:
            pass

    cx, cy = 500, 400
    # Track every (node_a,node_b) link (unordered) we successfully create in this topology builder
    # to avoid accidental duplicate link attempts that can trigger interface rename collisions in CORE.
    existing_links, safe_add_link, link_counters = _make_safe_link_tracker()
    logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", 1, "switch", _type_desc(NodeType.SWITCH), cx, cy)
    switch_pos = Position(x=cx, y=cy)
    switch = session.add_node(1, _type=NodeType.SWITCH, position=switch_pos)
    _log_add_node_result(session, switch, 1, NodeType.SWITCH, "switch", position=switch_pos)
    try:
        setattr(switch, "model", "switch")
    except Exception:
        pass

    total_hosts = sum(role_counts.values())
    radius = 250
    node_infos: List[NodeInfo] = []

    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)

    sw_ifid = 0
    dev_next_ifid: Dict[int, int] = {}
    nodes_by_id: Dict[int, object] = {}
    # slot counter for host nodes (DEFAULT prior to any override)
    host_slot_idx = 0
    docker_by_name: Dict[str, Dict[str, str]] = {}
    created_docker = 0

    docker_slots_used: Set[str] = set()
    for idx, role in enumerate(expanded_roles):
        theta = (2 * math.pi * idx) / max(total_hosts, 1)
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))

        node_id = idx + 2
        node_type = map_role_to_node_type(role)
        node_name = f"{role.lower()}-{idx+1}"
        # If this role would be a DEFAULT host, check slot plan to possibly make it a DOCKER node
        if node_type == NodeType.DEFAULT:
            host_slot_idx += 1
            slot_key = f"slot-{host_slot_idx}"
            try:
                if docker_slot_plan and slot_key in docker_slot_plan:
                    if hasattr(NodeType, "DOCKER"):
                        node_type = getattr(NodeType, "DOCKER")
                        docker_by_name[node_name] = docker_slot_plan[slot_key]
                        created_docker += 1
                        docker_slots_used.add(slot_key)
                    else:
                        logger.warning("NodeType.DOCKER not available in this CORE build; cannot create docker nodes even though a slot plan exists")
            except Exception:
                pass
        logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", node_id, node_name, _type_desc(node_type), x, y)
        node_position = Position(x=x, y=y)
        node = session.add_node(node_id, _type=node_type, position=node_position, name=node_name)
        # set model for better XML typing
        try:
            if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                setattr(node, "model", "docker")
            elif node_type == NodeType.SWITCH:
                setattr(node, "model", "switch")
            elif node_type == NodeType.DEFAULT:
                setattr(node, "model", "PC")
        except Exception:
            pass
        logger.debug("Added node id=%s name=%s type=%s at (%s,%s)", node.id, node_name, node_type, x, y)
        nodes_by_id[node.id] = node

        # If this is a DOCKER node, attach compose/compose_name metadata now
        try:
            if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                rec = docker_by_name.get(node_name)
                try:
                    if rec:
                        logger.info(
                            "[vuln-node] created docker node id=%s name=%s from record keys=%s",
                            getattr(node, "id", node_id),
                            node_name,
                            sorted(rec.keys()),
                        )
                except Exception:
                    pass
                _apply_docker_compose_meta(node, rec, session=session)
                # Explicitly ensure DefaultRoute is NOT present on docker nodes
                try:
                    present = has_service(session, node.id, "DefaultRoute", node_obj=node)
                except Exception:
                    present = False
                if present:
                    try:
                        logger.info("Removing DefaultRoute from DOCKER node %s (id=%s)", getattr(node, "name", node.id), node.id)
                    except Exception:
                        pass
                    ok = remove_service(session, node.id, "DefaultRoute", node_obj=node)
                    try:
                        if ok:
                            logger.info("Removed DefaultRoute from DOCKER node %s (id=%s)", getattr(node, "name", node.id), node.id)
                        else:
                            logger.info("DefaultRoute not present or could not remove on DOCKER node %s (id=%s)", getattr(node, "name", node.id), node.id)
                    except Exception:
                        pass
        except Exception:
            pass

        _log_add_node_result(session, node, node_id, node_type, node_name, position=node_position)

        if node_type == NodeType.DEFAULT:
            host_ip, host_mask = mac_alloc.next_ip()
            host_mac = mac_alloc.next_mac()
            host_iface = Interface(id=0, name="eth0", ip4=host_ip, ip4_mask=host_mask, mac=host_mac)
            node_infos.append(NodeInfo(node_id=node.id, ip4=f"{host_ip}/{host_mask}", role=role))
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            safe_add_link(session, node, switch, iface1=host_iface, iface2=sw_iface)
            logger.debug("Link host %s <-> switch (ifids: host=0, sw=%d)", node.id, sw_ifid-1)
            # Ensure default routing service on hosts
            try:
                ensure_service(session, node.id, "DefaultRoute", node_obj=node)
            except Exception:
                pass
        else:
            # add explicit device and switch interfaces for visibility in XML
            dev_ifid = dev_next_ifid.get(node.id, 0)
            dev_iface = Interface(id=dev_ifid, name=f"{node_name}-uplink")
            dev_next_ifid[node.id] = dev_ifid + 1
            sw_iface = Interface(id=sw_ifid, name=f"sw{sw_ifid}", mac=mac_alloc.next_mac())
            sw_ifid += 1
            safe_add_link(session, node, switch, iface1=dev_iface, iface2=sw_iface)
            logger.debug("Link device %s <-> switch (dev ifid=%d, sw ifid=%d)", node.id, dev_ifid, sw_ifid-1)

    if docker_slot_plan:
        missing_slots = set(docker_slot_plan.keys()) - docker_slots_used
        if missing_slots:
            raise RuntimeError(
                f"Unable to provision Docker nodes for vulnerability assignments: {sorted(missing_slots)}"
            )

    service_assignments: Dict[int, List[str]] = {}
    if created_docker:
        logger.info("Docker nodes created in star topology: %d", created_docker)
    if services:
        service_assignments = distribute_services(node_infos, services)
        for node_id, service_list in service_assignments.items():
            for service_name in service_list:
                assigned = False
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=service_name)
                        assigned = True
                except Exception:
                    pass
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, service_name)
                            except TypeError:
                                node_obj_try = nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, service_name)
                                else:
                                    raise
                            assigned = True
                    except Exception:
                        pass
                if not assigned:
                    node_obj = nodes_by_id.get(node_id)
                    if node_obj is not None:
                        try:
                            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                node_obj.services.add(service_name)
                                assigned = True
                            elif hasattr(node_obj, "add_service"):
                                node_obj.add_service(service_name)
                                assigned = True
                        except Exception:
                            pass
                if assigned and service_name in ROUTING_STACK_SERVICES:
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                        elif hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, "zebra")
                            except TypeError:
                                node_obj_try = nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, "zebra")
                    except Exception:
                        pass
    if DIAG_ENABLED:
        try:
            link_len = len(getattr(session, 'links', []) or []) if hasattr(session,'links') else 'n/a'
            logger.info("[diag.summary.star] nodes=%s links_list=%s attempts=%s success=%s fail=%s", len(getattr(session,'nodes',{}) or {}), link_len, link_counters['attempts'], link_counters['success'], link_counters['fail_total'])
        except Exception:
            pass
        if int(os.getenv('CORETG_LINK_FAIL_HARD','0') not in ('0','false','False','')) and link_counters['success']==0:
            logger.error('[diag.summary.star] No links created; failing hard due to CORETG_LINK_FAIL_HARD')
            raise RuntimeError('No links created in star topology')
    return session, switch, node_infos, service_assignments, docker_by_name


def build_multi_switch_topology(core,
                                role_counts: Dict[str, int],
                                services: Optional[List[ServiceInfo]] = None,
                                ip4_prefix: str = "10.0.0.0/24",
                                ip_mode: str = "private",
                                ip_region: str = "all",
                                access_switches: int = 3,
                                layout_density: str = "normal",
                                docker_slot_plan: Optional[Dict[str, Dict[str, str]]] = None):
    """Build a simple multi-switch topology with an aggregation switch.

    Returns: session, [switch_ids], host NodeInfo list, service assignments
    """
    logger.info("Creating CORE session and building multi-switch topology (agg + access)")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = safe_create_session(core)
    existing_links, safe_add_link, link_counters = _make_safe_link_tracker()
    if DIAG_ENABLED:
        try:
            al = getattr(session, 'add_link', None)
            logger.info("[diag.session] multi-switch session=%r has_add_link=%s add_link_type=%s", session, bool(al), type(al))
        except Exception:
            pass

    cx, cy = 800, 800
    logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", 1, "agg-sw", _type_desc(NodeType.SWITCH), cx, cy)
    agg_position = Position(x=cx, y=cy)
    agg = session.add_node(1, _type=NodeType.SWITCH, position=agg_position, name="agg-sw")
    _log_add_node_result(session, agg, 1, NodeType.SWITCH, "agg-sw", position=agg_position)
    try:
        setattr(agg, "model", "switch")
    except Exception:
        pass
    switch_ids: List[int] = [agg.id]

    total_hosts = sum(role_counts.values())
    # Derive initial access switch count heuristically (1 per ~10 hosts) but never exceed host count.
    access_count = max(1, min(access_switches, max(1, total_hosts // 10)))
    # Ensure we do not create more access switches than there are hosts; each switch should have >=1 host.
    if total_hosts > 0 and access_count > total_hosts:
        access_count = total_hosts
    radius = 380 if layout_density == "compact" else (700 if layout_density == "spacious" else 500)
    # create access switches around aggregation
    # maintain interface id counters per-switch and for aggregation switch
    agg_ifid = 0
    for i in range(access_count):
        theta = (2 * math.pi * i) / access_count
        x = int(cx + radius * math.cos(theta))
        y = int(cy + radius * math.sin(theta))
        node_id = i + 2
        logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", node_id, f"sw-{i+1}", _type_desc(NodeType.SWITCH), x, y)
        sw_position = Position(x=x, y=y)
        sw = session.add_node(node_id, _type=NodeType.SWITCH, position=sw_position, name=f"sw-{i+1}")
        _log_add_node_result(session, sw, node_id, NodeType.SWITCH, f"sw-{i+1}", position=sw_position)
        switch_ids.append(sw.id)
        # link access switch to aggregation with explicit interfaces for clarity in saved XML
        try:
            sw_if = Interface(id=0, name=f"sw{i+1}-agg", mac=None)
            agg_if = Interface(id=agg_ifid, name=f"agg-sw-{i+1}", mac=None)
            agg_ifid += 1
            safe_add_link(session, sw, agg, iface1=sw_if, iface2=agg_if)
        except Exception:
            # fallback: attempt link without explicit ifaces using compatibility helper
            try:
                # Reuse internal compatibility logic by constructing a trivial call
                _ = session.add_link(node1_id=sw.id, node2_id=agg.id)
            except TypeError:
                try:
                    _ = session.add_link(node1=sw, node2=agg)
                except Exception:
                    try:
                        _ = session.add_link(sw.id, agg.id)
                    except Exception:
                        try:
                            _ = session.add_link(sw, agg)
                        except Exception:
                            pass

    # Expand roles
    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)
    random.shuffle(expanded_roles)

    node_infos: List[NodeInfo] = []
    service_assignments: Dict[int, List[str]] = {}
    # Place hosts spreading them across access switches
    host_radius = 120 if layout_density == "compact" else (240 if layout_density == "spacious" else 180)
    sw_ifid: Dict[int, int] = {sid: 0 for sid in switch_ids}
    nodes_by_id: Dict[int, object] = {}
    next_id = access_count + 2
    host_slot_idx = 0
    docker_by_name: Dict[str, Dict[str, str]] = {}
    created_docker = 0
    for idx, role in enumerate(expanded_roles):
        # pick an access switch in round-robin
        sw_index = (idx % access_count) + 1  # skip agg at index 0
        # position around that access switch
        theta = random.random() * 2 * math.pi
        r = max(40, int(random.gauss(host_radius, 20)))
        sw_node_id = switch_ids[sw_index]
        sw_node = session.get_node(sw_node_id)
        x = int(sw_node.position.x + r * math.cos(theta))
        y = int(sw_node.position.y + r * math.sin(theta))

        node_type = map_role_to_node_type(role)
        name = f"{role.lower()}-{idx+1}"
        if node_type == NodeType.DEFAULT:
            host_slot_idx += 1
            slot_key = f"slot-{host_slot_idx}"
            try:
                if docker_slot_plan and slot_key in docker_slot_plan:
                    if hasattr(NodeType, "DOCKER"):
                        node_type = getattr(NodeType, "DOCKER")
                        docker_by_name[name] = docker_slot_plan[slot_key]
                        created_docker += 1
                    else:
                        logger.warning("NodeType.DOCKER not available; cannot apply docker slot plan on multi-switch")
            except Exception:
                pass
        logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", next_id, name, _type_desc(node_type), x, y)
        node_position = Position(x=x, y=y)
        node = session.add_node(next_id, _type=node_type, position=node_position, name=name)
        try:
            if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                setattr(node, "model", "docker")
            elif node_type == NodeType.SWITCH:
                setattr(node, "model", "switch")
            elif node_type == NodeType.DEFAULT:
                setattr(node, "model", "PC")
        except Exception:
            pass

        actual_node_id = getattr(node, "id", next_id)

        # If this is a DOCKER node, attach compose/compose_name metadata now
        try:
            if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                rec = docker_by_name.get(name)
                try:
                    if rec:
                        logger.info(
                            "[vuln-node] created docker node id=%s name=%s from record keys=%s",
                            actual_node_id,
                            name,
                            sorted(rec.keys()),
                        )
                except Exception:
                    pass
                _apply_docker_compose_meta(node, rec, session=session)
                # Explicitly ensure DefaultRoute is NOT present on docker nodes
                present = False
                try:
                    present = has_service(session, node.id, "DefaultRoute", node_obj=node)
                except Exception:
                    present = False
                if present:
                    try:
                        logger.info("Removing DefaultRoute from DOCKER node %s (id=%s)", getattr(node, "name", node.id), node.id)
                    except Exception:
                        pass
                    ok = remove_service(session, node.id, "DefaultRoute", node_obj=node)
                    try:
                        if ok:
                            logger.info("Removed DefaultRoute from DOCKER node %s (id=%s)", getattr(node, "name", node.id), node.id)
                        else:
                            logger.info("DefaultRoute not present or could not remove on DOCKER node %s (id=%s)", getattr(node, "name", node.id), node.id)
                    except Exception:
                        pass
        except Exception:
            pass

        _log_add_node_result(session, node, next_id, node_type, name, position=node_position)
        nodes_by_id[node.id] = node
        next_id += 1

        if node_type == NodeType.DEFAULT:
            # Allocate a unique /24 LAN and assign the first host IP
            lan = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan.hosts())
            h_ip = str(lan_hosts[1])
            h_mac = mac_alloc.next_mac()
            host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan.prefixlen, mac=h_mac)
            sw_ifid[sw_node_id] += 1
            sw_if = Interface(id=sw_ifid[sw_node_id], name=f"sw{sw_node_id}-h{node.id}")
            safe_add_link(session, node, sw_node, iface1=host_if, iface2=sw_if)
            node_infos.append(NodeInfo(node_id=node.id, ip4=f"{h_ip}/{lan.prefixlen}", role=role))
            try:
                ensure_service(session, node.id, "DefaultRoute", node_obj=node)
            except Exception:
                pass
        else:
            sw_ifid[sw_node_id] += 1
            sw_if = Interface(id=sw_ifid[sw_node_id], name=f"sw{sw_node_id}-d{node.id}")
            safe_add_link(session, node, sw_node, iface2=sw_if)

    if created_docker:
        logger.info("Docker nodes created in multi-switch topology: %d", created_docker)
    if services:
        service_assignments = distribute_services(node_infos, services)
        for node_id, svc_list in service_assignments.items():
            for svc in svc_list:
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=svc)
                    elif hasattr(session, "services") and hasattr(session.services, "add"):
                        try:
                            session.services.add(node_id, svc)
                        except TypeError:
                            node_obj_try = session.get_node(node_id)
                            session.services.add(node_obj_try, svc)
                except Exception:
                    pass
                if svc in ROUTING_STACK_SERVICES:
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                        elif hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, "zebra")
                            except TypeError:
                                node_obj_try = session.get_node(node_id)
                                session.services.add(node_obj_try, "zebra")
                    except Exception:
                        pass

    if DIAG_ENABLED:
        try:
            link_len = len(getattr(session, 'links', []) or []) if hasattr(session,'links') else 'n/a'
            logger.info("[diag.summary.multi] nodes=%s switches=%s links_list=%s attempts=%s success=%s fail=%s", len(getattr(session,'nodes',{}) or {}), len(switch_ids), link_len, link_counters['attempts'], link_counters['success'], link_counters['fail_total'])
        except Exception:
            pass
        if int(os.getenv('CORETG_LINK_FAIL_HARD','0') not in ('0','false','False','')) and link_counters['success']==0:
            logger.error('[diag.summary.multi] No links created; failing hard due to CORETG_LINK_FAIL_HARD')
            raise RuntimeError('No links created in multi-switch topology')
    return session, switch_ids, node_infos, service_assignments, docker_by_name


def _sample_router_positions(count: int, width: int, height: int, min_dist: int = 140, max_tries: int = 5000) -> List[Tuple[int, int]]:
    """Sample router positions randomly within bounds with a minimum spacing.

    Simple rejection sampling: try random points, accept when far from previous.
    """
    rng = random.Random()
    positions: List[Tuple[int, int]] = []
    # keep some margins so nodes don't go off-canvas
    margin = max(60, min_dist // 2)
    tries = 0
    while len(positions) < count and tries < max_tries:
        tries += 1
        x = rng.randint(margin, width - margin)
        y = rng.randint(margin, height - margin)
        ok = True
        for (px, py) in positions:
            dx = px - x
            dy = py - y
            if dx * dx + dy * dy < (min_dist * min_dist):
                ok = False
                break
        if ok:
            positions.append((x, y))
    if len(positions) < count:
        # fallback to rough circle for any missing
        cx, cy = width // 2, height // 2
        radius = int(min(width, height) * 0.35)
        for i in range(count - len(positions)):
            theta = (2 * math.pi * i) / max(1, (count - len(positions)))
            positions.append((int(cx + radius * math.cos(theta)), int(cy + radius * math.sin(theta))))
    return positions


def _random_connected_pairs(n: int, extra_edges: Optional[int] = None) -> List[Tuple[int, int]]:
    """Build a connected undirected graph over n nodes and return edge index pairs.

    First create a random spanning tree, then add a few random extra edges.
    Node indices are 0..n-1.
    """
    if n <= 1:
        return []
    rng = random.Random()
    nodes = list(range(n))
    rng.shuffle(nodes)
    # spanning tree via randomized Prim-like growth
    in_tree: Set[int] = {nodes[0]}
    edges: List[Tuple[int, int]] = []
    remaining: Set[int] = set(nodes[1:])
    while remaining:
        a = rng.choice(list(in_tree))
        b = rng.choice(list(remaining))
        edges.append((a, b))
        in_tree.add(b)
        remaining.remove(b)
    # add extra edges to increase redundancy
    if extra_edges is None:
        extra_edges = max(0, n // 3)
    existing = set(tuple(sorted(e)) for e in edges)
    attempts = 0
    while extra_edges > 0 and attempts < n * n:
        attempts += 1
        a, b = rng.sample(range(n), 2)
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        if key in existing:
            continue
        existing.add(key)
        edges.append((a, b))
        extra_edges -= 1
    return edges


def _grid_positions(count: int, cols: Optional[int] = None, cell_w: int = 800, cell_h: int = 600, jitter: int = 60) -> List[Tuple[int, int]]:
    """Lay out positions on a spacious grid for readability.

    Returns a list of (x, y) coordinates. Jitter adds slight randomness.
    """
    if count <= 0:
        return []
    if cols is None:
        cols = max(1, int(math.ceil(math.sqrt(count))))
    rows = int(math.ceil(count / cols))
    positions: List[Tuple[int, int]] = []
    rng = random.Random()
    for i in range(count):
        r = i // cols
        c = i % cols
        x = c * cell_w + cell_w // 2 + rng.randint(-jitter, jitter)
        y = r * cell_h + cell_h // 2 + rng.randint(-jitter, jitter)
        positions.append((x, y))
    return positions


def _random_int_partition(total: int, parts: int, min_each: int = 0) -> List[int]:
    """Randomly partition an integer total into `parts` buckets.

    Ensures each bucket is at least min_each (clamped when infeasible) and that
    the returned list sums to `total`. Remaining units are distributed based on
    random weights with deterministic ordering by fractional remainder so that
    callers can rely on seeded pseudo-randomness.
    """
    if parts <= 0:
        return []
    min_each = max(0, min_each)
    if total <= 0:
        return [0 for _ in range(parts)]
    if min_each * parts > total:
        min_each = 0
    counts = [min_each] * parts
    remaining = total - min_each * parts
    if remaining <= 0:
        return counts
    weights = [random.random() + 0.01 for _ in range(parts)]
    sum_w = sum(weights)
    fractional: List[Tuple[float, int]] = []
    for idx, w in enumerate(weights):
        exact = (remaining * w) / sum_w if sum_w > 0 else 0.0
        floor_val = int(math.floor(exact))
        counts[idx] += floor_val
        fractional.append((exact - floor_val, idx))
    current = sum(counts)
    if current < total:
        fractional.sort(key=lambda t: t[0], reverse=True)
        idx_cycle = 0
        while current < total and idx_cycle < len(fractional):
            _, idx = fractional[idx_cycle]
            counts[idx] += 1
            current += 1
            idx_cycle += 1
        while current < total:
            idx = random.randrange(parts)
            counts[idx] += 1
            current += 1
    elif current > total:
        fractional.sort(key=lambda t: t[0])
        idx_cycle = 0
        while current > total and idx_cycle < len(fractional):
            _, idx = fractional[idx_cycle]
            if counts[idx] > min_each:
                counts[idx] -= 1
                current -= 1
            idx_cycle += 1
        while current > total:
            idx = random.randrange(parts)
            if counts[idx] > min_each:
                counts[idx] -= 1
                current -= 1
            else:
                break
    random.shuffle(counts)
    return counts


def _ensure_router_iface_name(router_iface_names: Dict[int, Set[str]], router_id: int, base: str) -> str:
    names = router_iface_names.setdefault(router_id, set())
    if base not in names:
        names.add(base)
        return base
    idx = 1
    while True:
        candidate = f"{base}-{idx}"
        if candidate not in names:
            names.add(candidate)
            return candidate
        idx += 1


def _try_build_segmented_topology_from_preview(
    core,
    services: Optional[List[ServiceInfo]],
    routing_items: List[RoutingInfo],
    ip4_prefix: str,
    ip_mode: str,
    ip_region: str,
    layout_density: str,
    preview_plan: Dict[str, Any],
) -> Optional[Tuple[Any, List[NodeInfo], List[NodeInfo], Dict[int, List[str]], Dict[int, List[str]], Dict[str, Dict[str, str]]]]:
    """Attempt to realize the provided preview plan exactly. Returns None on failure."""

    routers_data = preview_plan.get('routers') or []
    hosts_data = preview_plan.get('hosts') or []
    switches_detail = preview_plan.get('switches_detail') or []
    if not routers_data or not hosts_data:
        logger.debug("[preview] missing routers or hosts in preview payload; skipping preview realization")
        return None

    layout_positions = preview_plan.get('layout_positions') or {}

    def _layout_coord(layout_map: Any, node_id: int) -> Optional[Tuple[int, int]]:
        if not isinstance(layout_map, dict):
            return None
        raw = layout_map.get(str(node_id)) if str(node_id) in layout_map else layout_map.get(node_id)
        if not isinstance(raw, dict):
            return None
        try:
            x = int(float(raw.get('x')))
            y = int(float(raw.get('y')))
            return (x, y)
        except Exception:
            return None

    router_layout_map = layout_positions.get('routers') if isinstance(layout_positions, dict) else {}
    host_layout_map = layout_positions.get('hosts') if isinstance(layout_positions, dict) else {}
    switch_layout_map = layout_positions.get('switches') if isinstance(layout_positions, dict) else {}

    try:
        mac_alloc = UniqueAllocator(ip4_prefix)
    except Exception as exc:
        logger.warning("[preview] failed to init MAC allocator with prefix %s (%s); falling back to default pool", ip4_prefix, exc)
        try:
            mac_alloc = UniqueAllocator("10.0.0.0/16")
        except Exception as exc2:
            logger.warning("[preview] fallback MAC allocator init failed (%s); using emergency /8 pool", exc2)
            mac_alloc = UniqueAllocator("10.0.0.0/8")
    try:
        subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    except Exception as exc:
        logger.warning("[preview] failed to init subnet allocator with prefix=%s mode=%s region=%s (%s); falling back to private pool", ip4_prefix, ip_mode, ip_region, exc)
        try:
            subnet_alloc = make_subnet_allocator("private", "10.0.0.0/8", "all")
        except Exception as exc2:
            logger.error("[preview] fallback subnet allocator also failed (%s); preview realization cannot continue", exc2)
            return None

    session = safe_create_session(core)
    existing_links, safe_add_link, link_counters = _make_safe_link_tracker()
    if DIAG_ENABLED:
        try:
            al = getattr(session, 'add_link', None)
            logger.info("[diag.session.preview] session=%r has_add_link=%s add_link_type=%s", session, bool(al), type(al))
        except Exception:
            pass

    if layout_density == "compact":
        cell_w, cell_h = 600, 450
        host_radius_mean = 140
        host_radius_jitter = 40
    elif layout_density == "spacious":
        cell_w, cell_h = 1000, 750
        host_radius_mean = 260
        host_radius_jitter = 80
    else:
        cell_w, cell_h = 900, 650
        host_radius_mean = 220
        host_radius_jitter = 60

    router_grid_positions = _grid_positions(len(routers_data), cell_w=cell_w, cell_h=cell_h, jitter=50)
    router_index_order = sorted(routers_data, key=lambda r: r.get('node_id', 0))
    router_index_map: Dict[int, int] = {}
    router_coord_map: Dict[int, Tuple[int, int]] = {}

    router_objs: List[Any] = []
    router_nodes: Dict[int, Any] = {}
    routers_info: List[NodeInfo] = []
    router_iface_names: Dict[int, Set[str]] = {}
    router_next_ifid: Dict[int, int] = defaultdict(int)

    for idx, rdata in enumerate(router_index_order):
        try:
            rid = int(rdata.get('node_id', idx + 1))
        except Exception:
            rid = idx + 1
        router_index_map[rid] = idx
        name = str(rdata.get('name') or f"router-{idx+1}")
        layout_coord = _layout_coord(router_layout_map, rid)
        if layout_coord:
            x, y = layout_coord
        elif router_grid_positions:
            x, y = router_grid_positions[idx % len(router_grid_positions)]
        else:
            x, y = (500 + idx * 120, 400)
        router_coord_map[rid] = (x, y)
        logger.info("[preview] add_router id=%s name=%s pos=(%s,%s)", rid, name, x, y)
        router_position = Position(x=x, y=y)
        rtype = _router_node_type()
        node = session.add_node(rid, _type=rtype, position=router_position, name=name)
        _log_add_node_result(session, node, rid, rtype, name, position=router_position)
        mark_node_as_router(node, session)
        try:
            setattr(node, "model", "router")
        except Exception:
            pass
        router_iface_names[rid] = set()
        services_for_router = ["IPForward", "zebra"]
        set_node_services(session, rid, services_for_router, node_obj=node)
        routers_info.append(NodeInfo(node_id=rid, ip4=str(rdata.get('ip4') or ""), role="Router"))
        router_objs.append(node)
        router_nodes[rid] = node

    host_router_map_preview: Dict[int, int] = {}
    try:
        hrm_raw = preview_plan.get('host_router_map') or {}
        for key, val in hrm_raw.items():
            try:
                host_router_map_preview[int(key)] = int(val)
            except Exception:
                continue
    except Exception:
        host_router_map_preview = {}

    host_nodes_by_id: Dict[int, Any] = {}
    host_data_by_id: Dict[int, Dict[str, Any]] = {}
    host_next_ifid: Dict[int, int] = defaultdict(int)
    host_primary_ips: Dict[int, str] = {}
    hosts_info: List[NodeInfo] = []
    default_host_ids: Set[int] = set()

    sorted_hosts = sorted(hosts_data, key=lambda h: h.get('node_id', 0))
    for idx, hdata in enumerate(sorted_hosts):
        try:
            hid = int(hdata.get('node_id', idx + len(router_objs) + 1))
        except Exception:
            hid = idx + len(router_objs) + 1
        host_data_by_id[hid] = hdata
        role = hdata.get('role') or "Host"
        node_type = map_role_to_node_type(role)
        router_id = host_router_map_preview.get(hid)
        layout_coord = _layout_coord(host_layout_map, hid)
        if layout_coord:
            x, y = layout_coord
        else:
            if router_id in router_coord_map:
                base_x, base_y = router_coord_map[router_id]
            elif router_grid_positions:
                base_x, base_y = router_grid_positions[idx % len(router_grid_positions)]
            else:
                base_x, base_y = (500 + idx * 35, 500)
            angle = (idx % 12) * (math.pi / 6.0)
            radius = max(60, int(random.gauss(host_radius_mean, host_radius_jitter)))
            x = int(base_x + radius * math.cos(angle))
            y = int(base_y + radius * math.sin(angle))
        name = str(hdata.get('name') or f"host-{hid}")
        logger.info("[preview] add_host id=%s name=%s type=%s pos=(%s,%s)", hid, name, _type_desc(node_type), x, y)
        host_position = Position(x=x, y=y)
        host_node = session.add_node(hid, _type=node_type, position=host_position, name=name)
        _log_add_node_result(session, host_node, hid, node_type, name, position=host_position)
        try:
            if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                setattr(host_node, "model", "docker")
            elif node_type == NodeType.SWITCH:
                setattr(host_node, "model", "switch")
            elif node_type == NodeType.DEFAULT:
                setattr(host_node, "model", "PC")
        except Exception:
            pass
        host_nodes_by_id[hid] = host_node
        host_next_ifid[hid] = 0
        if node_type == NodeType.DEFAULT:
            default_host_ids.add(hid)
        ip_hint = str(hdata.get('ip4') or "")
        if node_type == NodeType.DEFAULT:
            hosts_info.append(NodeInfo(node_id=hid, ip4=ip_hint, role=role))

    switches_preview = preview_plan.get('switches') or []
    switch_name_map = {}
    for sval in switches_preview:
        try:
            switch_name_map[int(sval.get('node_id'))] = sval.get('name')
        except Exception:
            continue

    switch_nodes: Dict[int, Any] = {}
    for idx, detail in enumerate(switches_detail):
        try:
            sid = int(detail.get('switch_id'))
        except Exception:
            continue
        if sid in switch_nodes:
            continue
        router_id = int(detail.get('router_id') or 0)
        layout_coord = _layout_coord(switch_layout_map, sid)
        if layout_coord:
            sx, sy = layout_coord
        else:
            if router_id in router_coord_map:
                base_x, base_y = router_coord_map[router_id]
            elif router_grid_positions:
                base_x, base_y = router_grid_positions[idx % len(router_grid_positions)]
            else:
                base_x, base_y = (600 + idx * 40, 600)
            sx = base_x + 120 + (idx % 3) * 40
            sy = base_y + 60 + (idx % 5) * 35
        switch_name = switch_name_map.get(sid) or f"rsw-{router_id}-{idx+1}"
        logger.info("[preview] add_switch id=%s name=%s pos=(%s,%s)", sid, switch_name, sx, sy)
        sw_position = Position(x=sx, y=sy)
        sw_node = session.add_node(sid, _type=NodeType.SWITCH, position=sw_position, name=switch_name)
        _log_add_node_result(session, sw_node, sid, NodeType.SWITCH, switch_name, position=sw_position)
        try:
            setattr(sw_node, "model", "switch")
        except Exception:
            pass
        switch_nodes[sid] = sw_node

    def _normalize_host_if_ips(raw: Any) -> Dict[int, str]:
        out: Dict[int, str] = {}
        if not isinstance(raw, dict):
            return out
        for k, v in raw.items():
            try:
                out[int(k)] = str(v)
            except Exception:
                continue
        return out

    hosts_attached: Set[int] = set()
    host_switch_assignment: Dict[int, int] = {}

    for detail in switches_detail:
        try:
            sid = int(detail.get('switch_id'))
            router_id = int(detail.get('router_id'))
        except Exception:
            continue
        sw_node = switch_nodes.get(sid)
        router_node = router_nodes.get(router_id)
        if not sw_node or not router_node:
            continue

        rsw_subnet = detail.get('rsw_subnet')
        lan_subnet = detail.get('lan_subnet')
        router_ip = detail.get('router_ip')
        switch_ip = detail.get('switch_ip')
        try:
            rsw_net = ipaddress.ip_network(rsw_subnet, strict=False) if rsw_subnet else None
        except Exception:
            rsw_net = None
        try:
            lan_net = ipaddress.ip_network(lan_subnet, strict=False) if lan_subnet else None
        except Exception:
            lan_net = None
        rsw_hosts = list(rsw_net.hosts()) if rsw_net else []
        lan_hosts = list(lan_net.hosts()) if lan_net else []
        if (not router_ip or '/' not in str(router_ip)) and rsw_hosts:
            router_ip = f"{rsw_hosts[0]}/{rsw_net.prefixlen}"
        if (not switch_ip or '/' not in str(switch_ip)) and len(rsw_hosts) >= 2:
            switch_ip = f"{rsw_hosts[1]}/{rsw_net.prefixlen}"

        if router_ip and '/' in router_ip:
            r_ip_val, r_mask = router_ip.split('/', 1)
            r_mask_int = int(r_mask)
        else:
            r_ip_val = router_ip or None
            r_mask_int = rsw_net.prefixlen if rsw_net else 30

        if switch_ip and '/' in switch_ip:
            s_ip_val, s_mask = switch_ip.split('/', 1)
            s_mask_int = int(s_mask)
        else:
            s_ip_val = switch_ip or None
            s_mask_int = rsw_net.prefixlen if rsw_net else r_mask_int

        r_ifid = router_next_ifid[router_id]
        router_next_ifid[router_id] += 1
        base_name = f"r{router_id}-rsw{sid}"
        r_iface_name = _ensure_router_iface_name(router_iface_names, router_id, base_name)
        r_iface = Interface(id=r_ifid, name=r_iface_name, ip4=r_ip_val, ip4_mask=r_mask_int, mac=mac_alloc.next_mac())
        sw_iface = Interface(id=0, name=f"{getattr(sw_node, 'name', f'rsw-{sid}')}-r{router_id}", ip4=s_ip_val, ip4_mask=s_mask_int, mac=mac_alloc.next_mac())
        safe_add_link(session, router_node, sw_node, iface1=r_iface, iface2=sw_iface)
        link_counters['attempts'] += 1
        link_counters['success'] += 1

        host_if_ips = _normalize_host_if_ips(detail.get('host_if_ips'))
        host_list_raw = detail.get('hosts') or []
        host_list: List[int] = []
        seen_local: Set[int] = set()
        for h in host_list_raw:
            try:
                hid_val = int(h)
            except Exception:
                continue
            if hid_val in seen_local:
                continue
            seen_local.add(hid_val)
            host_list.append(hid_val)
        for index, hid in enumerate(host_list):
            host_node = host_nodes_by_id.get(hid)
            if not host_node:
                continue
            previous_sid = host_switch_assignment.get(hid)
            if previous_sid is not None:
                if previous_sid != sid:
                    logger.warning("[preview] host %s already attached to switch %s; skipping duplicate attachment to switch %s", hid, previous_sid, sid)
                else:
                    logger.debug("[preview] host %s already attached to switch %s; skipping duplicate entry", hid, sid)
                continue
            ip_str = host_if_ips.get(hid)
            if not ip_str and lan_hosts:
                assign_idx = min(index + 1, len(lan_hosts) - 1)
                try:
                    ip_str = f"{lan_hosts[assign_idx]}/{lan_net.prefixlen}"
                except Exception:
                    ip_str = None
            if ip_str and '/' in ip_str:
                hip_val, hip_mask = ip_str.split('/', 1)
                hip_mask_int = int(hip_mask)
            else:
                hip_val = None if not ip_str else str(ip_str)
                hip_mask_int = lan_net.prefixlen if lan_net else 24
            iface_id = host_next_ifid[hid]
            host_iface = Interface(id=iface_id, name=f"eth{iface_id}", ip4=hip_val, ip4_mask=hip_mask_int, mac=mac_alloc.next_mac())
            gateway_ip = str(lan_hosts[0]) if lan_hosts else None
            sw_host_iface = Interface(id=index + 1, name=f"{getattr(sw_node, 'name', 'rsw')}-h{hid}", ip4=gateway_ip, ip4_mask=(lan_net.prefixlen if lan_net else hip_mask_int), mac=mac_alloc.next_mac())
            if safe_add_link(session, host_node, sw_node, iface1=host_iface, iface2=sw_host_iface):
                host_next_ifid[hid] += 1
                link_counters['attempts'] += 1
                link_counters['success'] += 1
                hosts_attached.add(hid)
                host_switch_assignment[hid] = sid
                if hip_val:
                    host_primary_ips[hid] = f"{hip_val}/{hip_mask_int}"
            else:
                logger.warning("[preview] failed to link host %s to switch %s; host may remain unattached", hid, sid)

    for hid, rid in host_router_map_preview.items():
        if hid in hosts_attached:
            continue
        host_node = host_nodes_by_id.get(hid)
        router_node = router_nodes.get(rid)
        if not host_node or not router_node:
            continue
        hdata = host_data_by_id.get(hid, {})
        ip_hint = str(hdata.get('ip4') or "")
        hip_val = None
        hip_mask_int = 24
        router_ip_val = None
        if ip_hint and '/' in ip_hint:
            try:
                iface = ipaddress.ip_interface(ip_hint)
                hip_val = str(iface.ip)
                hip_mask_int = iface.network.prefixlen
                hosts_in_net = list(iface.network.hosts())
                if hosts_in_net:
                    router_ip_val = str(hosts_in_net[0]) if str(hosts_in_net[0]) != hip_val else (str(hosts_in_net[1]) if len(hosts_in_net) > 1 else None)
            except Exception:
                hip_val = None
        if hip_val is None:
            lan_net = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan_net.hosts())
            hip_val = str(lan_hosts[1]) if len(lan_hosts) > 1 else None
            router_ip_val = str(lan_hosts[0]) if lan_hosts else None
            hip_mask_int = lan_net.prefixlen
        iface_id = host_next_ifid[hid]
        host_next_ifid[hid] += 1
        host_iface = Interface(id=iface_id, name=f"eth{iface_id}", ip4=hip_val, ip4_mask=hip_mask_int, mac=mac_alloc.next_mac())
        r_ifid = router_next_ifid[rid]
        router_next_ifid[rid] += 1
        base_name = f"r{rid}-h{hid}"
        r_iface_name = _ensure_router_iface_name(router_iface_names, rid, base_name)
        router_iface = Interface(id=r_ifid, name=r_iface_name, ip4=router_ip_val, ip4_mask=hip_mask_int, mac=mac_alloc.next_mac())
        safe_add_link(session, host_node, router_node, iface1=host_iface, iface2=router_iface)
        link_counters['attempts'] += 1
        link_counters['success'] += 1
        hosts_attached.add(hid)
        if hip_val:
            host_primary_ips[hid] = f"{hip_val}/{hip_mask_int}"

    router_protocols: Dict[int, List[str]] = defaultdict(list)
    proto_sources = preview_plan.get('r2s_grouping_preview') or []
    for entry in proto_sources:
        try:
            rid = int(entry.get('router_id'))
        except Exception:
            continue
        proto = entry.get('protocol')
        if rid and proto:
            router_protocols[rid].append(proto)

    r2r_links_preview = preview_plan.get('r2r_links_preview') or []
    if not r2r_links_preview:
        edges_preview = preview_plan.get('r2r_edges_preview') or []
        for edge in edges_preview:
            if not isinstance(edge, (list, tuple)) or len(edge) != 2:
                continue
            r2r_links_preview.append({'routers': [{'id': edge[0]}, {'id': edge[1]}]})

    for link_entry in r2r_links_preview:
        routers_descr = link_entry.get('routers') or []
        if len(routers_descr) != 2:
            continue
        try:
            a_id = int(routers_descr[0].get('id'))
            b_id = int(routers_descr[1].get('id'))
        except Exception:
            continue
        a_node = router_nodes.get(a_id)
        b_node = router_nodes.get(b_id)
        if not a_node or not b_node:
            continue
        subnet_str = link_entry.get('subnet')
        try:
            subnet_obj = ipaddress.ip_network(subnet_str, strict=False) if subnet_str else None
        except Exception:
            subnet_obj = None
        if subnet_obj:
            hosts_in_net = list(subnet_obj.hosts())
        else:
            subnet_obj = subnet_alloc.next_random_subnet(30)
            hosts_in_net = list(subnet_obj.hosts())
        a_ip_entry = routers_descr[0].get('ip')
        b_ip_entry = routers_descr[1].get('ip')
        if not a_ip_entry and hosts_in_net:
            a_ip_entry = f"{hosts_in_net[0]}/{subnet_obj.prefixlen}"
        if not b_ip_entry and len(hosts_in_net) >= 2:
            b_ip_entry = f"{hosts_in_net[1]}/{subnet_obj.prefixlen}"
        if a_ip_entry and '/' in a_ip_entry:
            a_ip, a_mask = a_ip_entry.split('/', 1)
            a_mask_int = int(a_mask)
        else:
            a_ip = a_ip_entry or None
            a_mask_int = subnet_obj.prefixlen
        if b_ip_entry and '/' in b_ip_entry:
            b_ip, b_mask = b_ip_entry.split('/', 1)
            b_mask_int = int(b_mask)
        else:
            b_ip = b_ip_entry or None
            b_mask_int = subnet_obj.prefixlen
        a_ifid = router_next_ifid[a_id]
        router_next_ifid[a_id] += 1
        b_ifid = router_next_ifid[b_id]
        router_next_ifid[b_id] += 1
        a_iface_name = _ensure_router_iface_name(router_iface_names, a_id, f"r{a_id}-proto-{b_id}")
        b_iface_name = _ensure_router_iface_name(router_iface_names, b_id, f"r{b_id}-proto-{a_id}")
        a_iface = Interface(id=a_ifid, name=a_iface_name, ip4=a_ip, ip4_mask=a_mask_int, mac=mac_alloc.next_mac())
        b_iface = Interface(id=b_ifid, name=b_iface_name, ip4=b_ip, ip4_mask=b_mask_int, mac=mac_alloc.next_mac())
        safe_add_link(session, a_node, b_node, iface1=a_iface, iface2=b_iface)
        link_counters['attempts'] += 1
        link_counters['success'] += 1

    for rid, protos in router_protocols.items():
        node = router_nodes.get(rid)
        if not node:
            continue
        merged = ["IPForward", "zebra"]
        for proto in protos:
            if proto and proto not in merged:
                merged.append(proto)
        set_node_services(session, rid, merged, node_obj=node)
        try:
            setattr(node, "routing_protocol", protos[-1])
        except Exception:
            pass

    for hid in default_host_ids:
        node = host_nodes_by_id.get(hid)
        if not node:
            continue
        try:
            ensure_service(session, hid, "DefaultRoute", node_obj=node)
        except Exception:
            pass

    host_service_assignments: Dict[int, List[str]] = {}
    services_preview = preview_plan.get('services_preview') or {}
    for key, svc_list in services_preview.items():
        try:
            hid = int(key)
        except Exception:
            continue
        node = host_nodes_by_id.get(hid)
        if not node:
            continue
        assigned: List[str] = []
        for svc in svc_list or []:
            if not svc:
                continue
            try:
                ensure_service(session, hid, svc, node_obj=node)
                assigned.append(svc)
            except Exception as exc:
                logger.debug("[preview] failed to assign service %s to host %s: %s", svc, hid, exc)
        if assigned:
            host_service_assignments[hid] = assigned

    hosts_info_map = {ni.node_id: ni for ni in hosts_info}
    for hid, primary in host_primary_ips.items():
        info = hosts_info_map.get(hid)
        if info:
            info.ip4 = primary

    topo_stats: Dict[str, Any] = {}
    try:
        topo_stats.update({
            'routers_total_planned': len(router_objs),
            'preview_realized': True,
        })
        policy = preview_plan.get('r2r_policy_preview')
        if policy:
            topo_stats['router_edges_policy'] = policy
        degrees = preview_plan.get('r2r_degree_preview')
        if degrees:
            try:
                topo_stats['router_degrees'] = {int(k): int(v) for k, v in degrees.items()}
            except Exception:
                topo_stats['router_degrees'] = degrees
        r2s_policy = preview_plan.get('r2s_policy_preview')
        if r2s_policy:
            topo_stats['r2s_policy'] = r2s_policy
        host_counts: Dict[int, int] = defaultdict(int)
        for hid, rid in host_router_map_preview.items():
            host_counts[rid] += 1
        if host_counts:
            topo_stats['router_host_counts'] = dict(host_counts)
        router_plan_stats = preview_plan.get('router_plan_stats')
        if isinstance(router_plan_stats, dict):
            topo_stats['router_plan_stats'] = router_plan_stats
        setattr(session, 'topo_stats', topo_stats)
    except Exception:
        pass
    try:
        if preview_plan.get('r2s_grouping_preview'):
            setattr(session, 'r2s_grouping_preview', preview_plan.get('r2s_grouping_preview'))
    except Exception:
        pass

    docker_by_name: Dict[str, Dict[str, str]] = {}
    logger.info("[preview] topology realized from persisted preview: routers=%d hosts=%d switches=%d", len(router_objs), len(host_nodes_by_id), len(switch_nodes))

    return session, routers_info, [ni for ni in hosts_info], {k: v for k, v in host_service_assignments.items()}, {k: v for k, v in router_protocols.items()}, docker_by_name


def build_segmented_topology(core,
                             role_counts: Dict[str, int],
                             routing_density: float,
                             routing_items: List[RoutingInfo],
                             base_host_pool: int,
                             services: Optional[List[ServiceInfo]] = None,
                             ip4_prefix: str = "10.0.0.0/24",
                             ip_mode: str = "private",
                             ip_region: str = "all",
                             layout_density: str = "normal",
                             docker_slot_plan: Optional[Dict[str, Dict[str, str]]] = None,
                             router_mesh_style: str = "full",
                             preview_plan: Optional[Dict[str, Any]] = None):
    expected_switch_ids: Set[int] = set()
    if preview_plan:
        preview_result = _try_build_segmented_topology_from_preview(
            core=core,
            services=services,
            routing_items=routing_items,
            ip4_prefix=ip4_prefix,
            ip_mode=ip_mode,
            ip_region=ip_region,
            layout_density=layout_density,
            preview_plan=preview_plan,
        )
        if preview_result is not None:
            return preview_result
        try:
            switches_decl = preview_plan.get('switches') or []
            for sw in switches_decl:
                try:
                    expected_switch_ids.add(int(sw.get('node_id')))
                except Exception:
                    continue
            switches_detail = preview_plan.get('switches_detail') or []
            for detail in switches_detail:
                try:
                    expected_switch_ids.add(int(detail.get('switch_id')))
                except Exception:
                    continue
        except Exception:
            expected_switch_ids.clear()

    preview_seed: Optional[int] = None
    if preview_plan:
        try:
            raw_seed = preview_plan.get('seed')
            if raw_seed is not None:
                preview_seed = int(raw_seed)
        except Exception:
            preview_seed = None
    if preview_seed is not None:
        try:
            set_global_random_seed(preview_seed)
        except Exception:
            try:
                random.seed(preview_seed)
            except Exception:
                pass

    logger.info("Creating CORE session and building segmented topology with routers (randomized placement)")
    mac_alloc = UniqueAllocator(ip4_prefix)
    subnet_alloc = make_subnet_allocator(ip_mode, ip4_prefix, ip_region)
    session = safe_create_session(core)
    existing_links, safe_add_link, link_counters = _make_safe_link_tracker()
    if DIAG_ENABLED:
        try:
            al = getattr(session, 'add_link', None)
            logger.info("[diag.session] segmented session=%r has_add_link=%s add_link_type=%s", session, bool(al), type(al))
        except Exception:
            pass

    total_hosts = sum(role_counts.values())
    if preview_plan:
        try:
            hosts_preview = preview_plan.get('hosts') or []
            if isinstance(hosts_preview, list):
                preview_host_total = len(hosts_preview)
                if preview_host_total and preview_host_total != total_hosts:
                    logger.info("[preview] overriding host total from %s to %s", total_hosts, preview_host_total)
                    total_hosts = preview_host_total
        except Exception:
            pass
    # Use shared pure-planning helper for router counts
    _plan_stats = plan_router_counts(role_counts, routing_density, routing_items, base_host_pool)
    router_count = _plan_stats['router_count']
    if preview_plan:
        try:
            preview_router_override = len(preview_plan.get('routers') or [])
        except Exception:
            preview_router_override = 0
        if preview_router_override > 0 and preview_router_override != router_count:
            logger.info("[preview] overriding router count from %s to %s", router_count, preview_router_override)
            router_count = preview_router_override
            _plan_stats['preview_router_override'] = preview_router_override
    density_router_count = _plan_stats['density_router_count']
    count_router_count = _plan_stats['count_router_count']
    effective_base = _plan_stats['effective_base']
    try:
        logger.debug(
            "Router planning (shared helper): base=%s rd_raw=%.4f rd_clamped=%.4f weight_based=%s count_based=%s final=%s total_hosts=%s override=%s", 
            _plan_stats['effective_base'], _plan_stats['rd_raw'], _plan_stats['rd_clamped'], _plan_stats['weight_based'], count_router_count, router_count, _plan_stats['total_hosts'], _plan_stats['preview_router_override']
        )
    except Exception:
        pass
    # If no routers requested (no density, no counts) OR no hosts, fall back to simple star topology (no routers)
    if router_count <= 0 or total_hosts == 0:
        logger.info("No routers created: routing density=%s, count_router_count=%s, total_hosts=%s", routing_density, count_router_count, total_hosts)
        session, _switch_unused, nodes, svc, docker_by_name = build_star_from_roles(
            core,
            role_counts,
            services=services,
            ip4_prefix=ip4_prefix,
            ip_mode=ip_mode,
            ip_region=ip_region,
            docker_slot_plan=docker_slot_plan,
        )
        # Attach empty topo_stats for consistency
        try:
            setattr(session, "topo_stats", {
                "routers_density_count": density_router_count,
                "routers_count_count": count_router_count,
                "routers_total_planned": 0,
            })
        except Exception:
            pass
        return session, [], nodes, svc, {}, docker_by_name

    # placement parameters tuned by density
    if layout_density == "compact":
        cell_w, cell_h = 600, 450
        host_radius_mean = 140
        host_radius_jitter = 40
    elif layout_density == "spacious":
        cell_w, cell_h = 1000, 750
        host_radius_mean = 260
        host_radius_jitter = 80
    else:  # normal
        cell_w, cell_h = 900, 650
        host_radius_mean = 220
        host_radius_jitter = 60

    routers: List[NodeInfo] = []
    # Store stats for later reporting (attached to session to avoid changing return signature)
    try:
            setattr(session, "topo_stats", {
                "routers_density_count": density_router_count,
                "routers_count_count": count_router_count,
                "routers_total_planned": router_count,
            })
    except Exception:
        pass
    logger.debug("Router planning: density=%s weight_based=%s count_based=%s final=%s total_hosts=%s", routing_density, density_router_count, count_router_count, router_count, total_hosts)
    router_nodes: Dict[int, object] = {}
    router_objs: List[object] = []
    host_nodes_by_id: Dict[int, object] = {}
    # Track next interface id per host to avoid reusing id=0 during rehome (prevents 'interface(0) already exists')
    host_next_ifid: Dict[int, int] = {}
    router_next_ifid: Dict[int, int] = {}
    # Track router-facing interface names to guarantee uniqueness (avoid RTNETLINK rename collisions)
    router_iface_names: Dict[int, Set[str]] = {}

    # place routers on a spacious grid for easier viewing
    r_positions = _grid_positions(router_count, cell_w=cell_w, cell_h=cell_h, jitter=50)
    for i in range(router_count):
        x, y = r_positions[i]
        node_id = i + 1
        rtype = _router_node_type()
        logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", node_id, f"router-{i+1}", _type_desc(rtype), x, y)
        router_position = Position(x=x, y=y)
        node = session.add_node(node_id, _type=rtype, position=router_position, name=f"router-{i+1}")
        _log_add_node_result(session, node, node_id, rtype, f"router-{i+1}", position=router_position)
        logger.debug("Added router id=%s at (%s,%s)", node.id, x, y)
        mark_node_as_router(node, session)
        try:
            setattr(node, "model", "router")
        except Exception:
            pass
        # initialize iface name set for router
        router_iface_names[node.id] = set()
        # Always include mandatory router services
        merged_services = ["IPForward", "zebra"]
        set_node_services(session, node.id, merged_services, node_obj=node)
        routers.append(NodeInfo(node_id=node.id, ip4="", role="Router"))
        router_nodes[node.id] = node
        router_objs.append(node)

    # --- New Edge Connectivity Semantics ---
    existing_router_links: Set[Tuple[int, int]] = set()
    # Helper: compute stats (min/max/avg/std/gini) for a list of ints
    def _int_list_stats(values: List[int]):
        out = {"min": 0, "max": 0, "avg": 0.0, "std": 0.0, "gini": 0.0}
        if not values:
            return out
        import math as _math
        v = list(values)
        mn = min(v); mx = max(v); sm = sum(v); n = len(v)
        avg = sm / n if n else 0.0
        var = 0.0
        if n > 1:
            var = sum((x - avg) ** 2 for x in v) / (n - 1)
        std = _math.sqrt(var) if var > 0 else 0.0
        # Gini (safe) – if all zero, remains 0
        gini = 0.0
        if sm > 0 and n > 1:
            v_sorted = sorted(v)
            # Using: G = (2*sum(i*x_i))/(n*sum(x_i)) - (n+1)/n
            cum = 0
            for i, x in enumerate(v_sorted, start=1):
                cum += i * x
            gini = (2 * cum) / (n * sm) - (n + 1) / n
            # Numerical guard
            if gini < 0:
                gini = 0.0
        out.update({"min": mn, "max": mx, "avg": round(avg, 4), "std": round(std, 4), "gini": round(gini, 4)})
        return out

    def add_router_link(a_obj, b_obj, prefix=30, label=""):
        key = (min(a_obj.id, b_obj.id), max(a_obj.id, b_obj.id))
        if key in existing_router_links:
            return False
        a_ifid = router_next_ifid.get(a_obj.id, 0)
        b_ifid = router_next_ifid.get(b_obj.id, 0)
        router_next_ifid[a_obj.id] = a_ifid + 1
        router_next_ifid[b_obj.id] = b_ifid + 1
        rr_net = subnet_alloc.next_random_subnet(prefix)
        rr_hosts = list(rr_net.hosts())
        if len(rr_hosts) < 2:
            return False
        a_ip = str(rr_hosts[0]); b_ip = str(rr_hosts[1])
        tag = label or "to"
        # Unique naming guard
        def _uniq(router_id: int, base: str) -> str:
            names = router_iface_names.setdefault(router_id, set())
            if base not in names:
                names.add(base)
                return base
            # append incremental suffix until unique
            idx = 1
            while True:
                cand = f"{base}-{idx}"
                if cand not in names:
                    names.add(cand)
                    return cand
                idx += 1
        a_name = _uniq(a_obj.id, f"r{a_obj.id}-{tag}-r{b_obj.id}")
        b_name = _uniq(b_obj.id, f"r{b_obj.id}-{tag}-r{a_obj.id}")
        a_if = Interface(id=a_ifid, name=a_name, ip4=a_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
        b_if = Interface(id=b_ifid, name=b_name, ip4=b_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
        # Use global existing_links guard in addition to existing_router_links for safety
        key_all = (min(a_obj.id, b_obj.id), max(a_obj.id, b_obj.id))
        if key_all not in existing_links:
            safe_add_link(session, a_obj, b_obj, iface1=a_if, iface2=b_if)
            if GRPC_TRACE:
                logger.info("[grpc] add_router_link r1=%s r2=%s label=%s net=%s ifaceA=%s/%s ifaceB=%s/%s", a_obj.id, b_obj.id, label, rr_net, a_ip, rr_net.prefixlen, b_ip, rr_net.prefixlen)
        existing_router_links.add(key)
        return True
    # Determine connectivity mode & target before creating links (allow deterministic injection)
    connectivity_mode = 'Random'
    target_degree: Optional[int] = None
    injected_r2r = False
    # R2R connectivity mode derived directly from routing items (approval path removed)
    if not injected_r2r and routing_items and router_count > 1:
        # Collect modes and explicit edge targets
        modes_present = [ri.r2r_mode for ri in routing_items if getattr(ri, 'r2r_mode', None)]
        exact_values = [int(getattr(ri, 'r2r_edges', 0)) for ri in routing_items if getattr(ri, 'r2r_mode', '') == 'Exact' and int(getattr(ri, 'r2r_edges', 0)) > 0]
        uniform_values = [int(getattr(ri, 'r2r_edges', 0)) for ri in routing_items if getattr(ri, 'r2r_mode', '') == 'Uniform' and int(getattr(ri, 'r2r_edges', 0)) > 0]
        # Priority: Exact > Min > Uniform > NonUniform > Max > Random (legacy Max kept)
        if exact_values:
            # If differing values specified, use median for stability and log a warning
            unique_vals = sorted(set(exact_values))
            chosen = unique_vals[len(unique_vals)//2]
            if len(unique_vals) > 1:
                logger.warning("[r2r] Multiple Exact edge targets specified %s; using median=%s", unique_vals, chosen)
            target_degree = max(1, min(router_count - 1, chosen))
            connectivity_mode = 'Exact'
        elif 'Min' in modes_present:
            # Minimal connectivity spanning structure (chain) – cannot achieve true k=1 regular connected graph for n>2
            connectivity_mode = 'Min'
            target_degree = 1  # semantic intent
        elif 'Uniform' in modes_present:
            connectivity_mode = 'Uniform'
            if uniform_values:
                uv_unique = sorted(set(uniform_values))
                chosen = uv_unique[len(uv_unique)//2]
                if len(uv_unique) > 1:
                    logger.warning("[r2r] Multiple Uniform edge targets specified %s; using median=%s", uv_unique, chosen)
                target_degree = max(1, min(router_count - 1, chosen))
            else:
                target_degree = None  # will derive heuristic later
        elif 'NonUniform' in modes_present:
            connectivity_mode = 'NonUniform'
            if router_mesh_style == 'full':
                router_mesh_style = ''
        elif 'Max' in modes_present:
            connectivity_mode = 'Max'
        else:
            connectivity_mode = 'Random'
    # Build links according to connectivity_mode (unless injected already)
    if router_count > 1 and injected_r2r:
        logger.debug("R2R preview injection active: skipping connectivity_mode construction (using injected edges only)")
    elif router_count > 1:
        if connectivity_mode == 'Min':
            # Chain topology: r1-r2-r3-...-rn
            for i in range(router_count - 1):
                add_router_link(router_objs[i], router_objs[i+1], prefix=30, label="chain")
        elif connectivity_mode == 'Random':
            # Random spanning tree only
            order = list(range(router_count))
            random.shuffle(order)
            in_tree = {order[0]}; remaining = set(order[1:])
            while remaining:
                a_idx = random.choice(list(in_tree))
                b_idx = random.choice(list(remaining))
                add_router_link(router_objs[a_idx], router_objs[b_idx], prefix=30, label="tree")
                in_tree.add(b_idx); remaining.remove(b_idx)
        elif connectivity_mode == 'Uniform':
            # If a specific target_degree supplied (user-specified), attempt k-regular.
            # Otherwise derive heuristic and balance toward it.
            import math as _math
            if router_count == 2:
                add_router_link(router_objs[0], router_objs[1], prefix=30, label="u")
                target_degree = 1 if target_degree is None else target_degree
            else:
                if target_degree is None:
                    # Heuristic similar to previous but explicit now
                    td = min(router_count - 1, max(2, int(round(_math.log2(router_count))) + 1))
                    td = min(td, max(2, (router_count // 2) + 1))
                    target_degree = td
                # Attempt direct regular construction for uniformity (without labeling as Exact)
                def _build_regular(n: int, k: int) -> List[Tuple[int,int]]:
                    if k < 0 or k >= n: return []
                    if (n * k) % 2 != 0: return []
                    if k == 0: return []
                    import random as _r
                    if k == 1:
                        # Cannot produce connected k=1 for n>2; fallback to chain for minimal edges
                        return []
                    for _ in range(1200):
                        stubs=[]
                        for i in range(n): stubs.extend([i]*k)
                        _r.shuffle(stubs)
                        edges=set(); ok=True
                        while stubs:
                            if len(stubs) < 2: ok=False; break
                            a=stubs.pop(); b=stubs.pop()
                            if a==b: ok=False; break
                            e=(a,b) if a<b else (b,a)
                            if e in edges: ok=False; break
                            edges.add(e)
                        if ok:
                            degs={i:0 for i in range(n)}
                            for a,b in edges: degs[a]+=1; degs[b]+=1
                            if all(v==k for v in degs.values()): return list(edges)
                    return []
                reg = _build_regular(router_count, target_degree or 0)
                if reg:
                    for a_idx,b_idx in reg:
                        add_router_link(router_objs[a_idx], router_objs[b_idx], prefix=30, label="u-reg")
                else:
                    # Fallback: ring plus balancing toward target
                    for i in range(router_count):
                        add_router_link(router_objs[i], router_objs[(i+1) % router_count], prefix=30, label="u-ring")
                    degrees: Dict[int, int] = {r.id: 0 for r in router_objs}
                    for a_id, b_id in list(existing_router_links):
                        degrees[a_id] += 1; degrees[b_id] += 1
                    attempts = 0; max_attempts = router_count * router_count
                    while attempts < max_attempts:
                        attempts += 1
                        low_nodes = sorted(degrees.items(), key=lambda kv: kv[1])
                        if not low_nodes or low_nodes[0][1] >= (target_degree or 0):
                            break
                        a_id = low_nodes[0][0]
                        candidates_b = [rid for rid,_d in low_nodes[1:] if degrees[rid] < (target_degree or 0) and (min(rid,a_id), max(rid,a_id)) not in existing_router_links]
                        if not candidates_b:
                            continue
                        b_id = random.choice(candidates_b)
                        a_obj = router_nodes.get(a_id); b_obj = router_nodes.get(b_id)
                        if not a_obj or not b_obj:
                            continue
                        if add_router_link(a_obj, b_obj, prefix=30, label="u-bal"):
                            degrees[a_id]+=1; degrees[b_id]+=1
        elif connectivity_mode == 'NonUniform':
            # Build a biased hub-and-spoke style overlay with dense hub links and sparse periphery connections.
            order = list(range(router_count))
            random.shuffle(order)
            in_tree = {order[0]}; remaining = set(order[1:])
            while remaining:
                a_idx = random.choice(list(in_tree))
                b_idx = random.choice(list(remaining))
                add_router_link(router_objs[a_idx], router_objs[b_idx], prefix=30, label="base")
                in_tree.add(b_idx); remaining.remove(b_idx)
            degrees: Dict[int, int] = {r.id: 0 for r in router_objs}
            for a_id, b_id in existing_router_links:
                degrees[a_id] += 1; degrees[b_id] += 1
            router_id_list = [r.id for r in router_objs]

            def _try_add_edge(a_id: int, b_id: int, label: str) -> bool:
                if a_id == b_id:
                    return False
                key = (min(a_id, b_id), max(a_id, b_id))
                if key in existing_router_links:
                    return False
                a_obj = router_nodes.get(a_id)
                b_obj = router_nodes.get(b_id)
                if not a_obj or not b_obj:
                    return False
                if add_router_link(a_obj, b_obj, prefix=30, label=label):
                    degrees[a_id] += 1
                    degrees[b_id] += 1
                    return True
                return False

            if len(router_id_list) > 1:
                hub_pool = list(router_id_list)
                max_hubs = int(round(max(2.0, math.sqrt(router_count))))
                max_hubs = max(2, max_hubs)
                hub_count = min(max_hubs, router_count - 1)
                if hub_count <= 0:
                    hub_count = 1
                random.shuffle(hub_pool)
                hub_ids = hub_pool[:hub_count]
                if not hub_ids:
                    hub_ids = [hub_pool[0]]
                primary_hub = hub_ids[0]
                secondary_hubs = hub_ids[1:]
                periphery_ids = [rid for rid in router_id_list if rid not in hub_ids]
                nonhub_cap = 2 if router_count >= 5 else max(2, router_count // 2)

                def _eligible_target(hub_id: int, cand_id: int) -> bool:
                    if hub_id == cand_id:
                        return False
                    key = (min(hub_id, cand_id), max(hub_id, cand_id))
                    if key in existing_router_links:
                        return False
                    if cand_id in hub_ids:
                        return True
                    if hub_id == primary_hub:
                        return degrees[cand_id] < (nonhub_cap + 1)
                    return degrees[cand_id] < nonhub_cap

                # Step 1: build a dense hub clique to create heavy hitters.
                for idx, a_id in enumerate(hub_ids):
                    for b_id in hub_ids[idx + 1:]:
                        _try_add_edge(a_id, b_id, label="nu-hub")

                # Step 2: connect periphery nodes primarily to the dominant hub (and occasionally to secondaries).
                for per_id in periphery_ids:
                    if _eligible_target(primary_hub, per_id):
                        _try_add_edge(primary_hub, per_id, label="nu-pri")
                    if secondary_hubs and random.random() < 0.2:
                        hub_choice = random.choice(secondary_hubs)
                        if _eligible_target(hub_choice, per_id):
                            _try_add_edge(hub_choice, per_id, label="nu-sec")

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

                variance_target = 2 if router_count >= 5 else 1
                current_span = _degree_span()
                current_gini = _gini(list(degrees.values()))

                # Step 3: if spread is still low, add a few more primary-to-hub edges without touching periphery caps.
                if secondary_hubs and (current_span < variance_target or (router_count >= 5 and current_gini < 0.15)):
                    for hub_id in secondary_hubs:
                        if random.random() < 0.5 and _eligible_target(primary_hub, hub_id):
                            _try_add_edge(primary_hub, hub_id, label="nu-boost")
                    current_span = _degree_span()
                    current_gini = _gini(list(degrees.values()))
        elif connectivity_mode == 'Max':
            # Full mesh (legacy 'Max' -> still supported for backward compatibility)
            for i in range(router_count):
                for j in range(i+1, router_count):
                    add_router_link(router_objs[i], router_objs[j], prefix=30, label="mesh")
        elif connectivity_mode == 'Exact':
            # Build a k-regular simple graph (k = target_degree) if feasible.
            # Previous approach (chain + random augment) produced degrees >= target (not exact) and
            # forced interior nodes to exceed degree 1 when target_degree == 1. Replace with a
            # configuration-model style pairing to honor exact target degree semantics.
            def _build_regular_edges(n: int, k: int, max_tries: int = 2000) -> List[Tuple[int,int]]:
                # Basic feasibility checks: k < n and n*k even (handshaking lemma)
                if k < 0 or k >= n:
                    return []
                if (n * k) % 2 != 0:
                    return []
                if k == 0:
                    return []
                # Fast path k == 1: random perfect matching (may leave one node unmatched if n odd)
                import random as _r
                if k == 1:
                    nodes_idx = list(range(n))
                    _r.shuffle(nodes_idx)
                    pairs = []
                    while len(nodes_idx) >= 2:
                        a = nodes_idx.pop(); b = nodes_idx.pop()
                        pairs.append((a, b))
                    return pairs
                # General k: attempt stub matching with rejection of self-loops & duplicates.
                # (R2S/S2H approval-based injection previously occurred here; now unified path)
            # Routing protocol assignment retained below (simplified after approval removal)

    # (Former preview-based R2S/S2H injection path removed)
    # Ensure degree stats present even if earlier block skipped due to refactor
    try:
        topo_stats = getattr(session, 'topo_stats', {}) or {}
        if 'router_edges_policy' not in topo_stats:
            degs: Dict[int, int] = {}
            try:
                for a_id, b_id in list(existing_router_links):
                    degs[a_id] = degs.get(a_id, 0) + 1
                    degs[b_id] = degs.get(b_id, 0) + 1
            except Exception:
                pass
            def _stat(vals: List[int]):
                if not vals: return {'min':0,'max':0,'avg':0.0,'std':0.0,'gini':0.0}
                import math as _m
                v=vals; mn=min(v); mx=max(v); sm=sum(v); n=len(v); avg=sm/n if n else 0.0
                var = sum((x-avg)**2 for x in v)/(n-1) if n>1 else 0.0
                std=_m.sqrt(var) if var>0 else 0.0
                gini=0.0
                if sm>0 and n>1:
                    vs=sorted(v); cum=0
                    for i,x in enumerate(vs, start=1): cum += i*x
                    gini=(2*cum)/(n*sm)-(n+1)/n
                    if gini<0: gini=0.0
                return {'min':mn,'max':mx,'avg':round(avg,4),'std':round(std,4),'gini':round(gini,4)}
            ds=_stat(list(degs.values()))
            topo_stats['router_edges_policy'] = {
                'mode': connectivity_mode,
                'target_degree': target_degree or 0,
                'degree_min': ds['min'],
                'degree_max': ds['max'],
                'degree_avg': ds['avg'],
                'degree_std': ds['std'],
                'degree_gini': ds['gini'],
            }
            topo_stats['router_degrees'] = degs
            setattr(session, 'topo_stats', topo_stats)
    except Exception:
        pass

    expanded_roles: List[str] = []
    for role, count in role_counts.items():
        expanded_roles.extend([role] * count)

    random.shuffle(expanded_roles)
    min_each = 1 if router_count > 0 and len(expanded_roles) >= router_count else 0
    counts = _random_int_partition(len(expanded_roles), router_count, min_each=min_each)
    buckets: List[List[str]] = []
    cursor = 0
    for c in counts:
        if c <= 0:
            buckets.append([])
            continue
        next_cursor = min(len(expanded_roles), cursor + c)
        buckets.append(expanded_roles[cursor:next_cursor])
        cursor = next_cursor
    if len(buckets) < router_count:
        buckets.extend([[] for _ in range(router_count - len(buckets))])
    if cursor < len(expanded_roles) and buckets:
        buckets[-1].extend(expanded_roles[cursor:])

    hosts: List[NodeInfo] = []
    # Track mapping host->router and whether currently directly connected (True) or will later be regrouped
    host_router_map: Dict[int, int] = {}
    host_direct_link: Dict[int, bool] = {}
    # We defer LAN switch creation until AFTER R2S policy so R2S gets first priority creating hierarchical switches.
    lan_switch_by_router: Dict[int, int] = {}
    node_id_counter = router_count + 1
    host_slot_idx = 0
    docker_slots_used: Set[str] = set()
    docker_by_name: Dict[str, Dict[str, str]] = {}
    created_docker = 0
    for ridx, roles in enumerate(buckets):
        rx, ry = r_positions[ridx]
        router_node = router_objs[ridx]
        if len(roles) == 0:
            continue
        if len(roles) == 1:
            role = roles[0]
            theta = random.random() * math.tau
            radius_center = host_radius_mean + random.uniform(-host_radius_jitter * 0.3, host_radius_jitter * 0.3)
            radius_sigma = max(15, host_radius_jitter * random.uniform(0.5, 0.9))
            r = max(60, int(random.gauss(radius_center, radius_sigma)))
            x = int(rx + r * math.cos(theta) + random.uniform(-20, 20))
            y = int(ry + r * math.sin(theta) + random.uniform(-20, 20))
            node_type = map_role_to_node_type(role)
            name = f"{role.lower()}-{ridx+1}-1"
            if node_type == NodeType.DEFAULT:
                host_slot_idx += 1
                slot_key = f"slot-{host_slot_idx}"
                try:
                    if docker_slot_plan and slot_key in docker_slot_plan:
                        if hasattr(NodeType, "DOCKER"):
                            node_type = getattr(NodeType, "DOCKER")
                            docker_by_name[name] = docker_slot_plan[slot_key]
                            created_docker += 1
                            docker_slots_used.add(slot_key)
                        else:
                            logger.warning("NodeType.DOCKER not available; cannot apply docker slot plan on segmented (single-host)")
                except Exception:
                    pass
            logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", node_id_counter, name, _type_desc(node_type), x, y)
            host_position = Position(x=x, y=y)
            host = session.add_node(node_id_counter, _type=node_type, position=host_position, name=name)
            try:
                if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                    setattr(host, "model", "docker")
                elif node_type == NodeType.SWITCH:
                    setattr(host, "model", "switch")
                elif node_type == NodeType.DEFAULT:
                    setattr(host, "model", "PC")
            except Exception:
                pass
            logger.debug("Added host id=%s name=%s type=%s at (%s,%s)", host.id, name, node_type, x, y)
            actual_host_id = getattr(host, "id", node_id_counter)
            host_nodes_by_id[host.id] = host
            host_next_ifid[host.id] = 1  # eth0 consumed
            # Apply DOCKER compose metadata when applicable
            try:
                if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                    rec = docker_by_name.get(name)
                    try:
                        if rec:
                            logger.info(
                                "[vuln-node] created docker node id=%s name=%s from record keys=%s",
                                actual_host_id,
                                name,
                                sorted(rec.keys()),
                            )
                    except Exception:
                        pass
                    _apply_docker_compose_meta(host, rec, session=session)
                    # Explicitly ensure DefaultRoute is NOT present on docker nodes
                    present = False
                    try:
                        present = has_service(session, host.id, "DefaultRoute", node_obj=host)
                    except Exception:
                        present = False
                    if present:
                        try:
                            logger.info("Removing DefaultRoute from DOCKER node %s (id=%s)", getattr(host, "name", host.id), host.id)
                        except Exception:
                            pass
                        ok = remove_service(session, host.id, "DefaultRoute", node_obj=host)
                        try:
                            if ok:
                                logger.info("Removed DefaultRoute from DOCKER node %s (id=%s)", getattr(host, "name", host.id), host.id)
                            else:
                                logger.info("DefaultRoute not present or could not remove on DOCKER node %s (id=%s)", getattr(host, "name", host.id), host.id)
                        except Exception:
                            pass
            except Exception:
                pass
            _log_add_node_result(session, host, node_id_counter, node_type, name, position=host_position)
            node_id_counter += 1
            # Allocate a unique /24 LAN
            lan_net = subnet_alloc.next_random_subnet(24)
            lan_hosts = list(lan_net.hosts())
            r_ip = str(lan_hosts[0])
            h_ip = str(lan_hosts[1])
            h_mac = mac_alloc.next_mac()
            host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=h_mac)
            r_ifid = router_next_ifid.get(router_node.id, 0)
            router_next_ifid[router_node.id] = r_ifid + 1
            r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
            # enforce uniqueness for router iface names
            base_name = r_if.name
            if base_name in router_iface_names.setdefault(router_node.id, set()):
                suf = 1
                while f"{base_name}-{suf}" in router_iface_names[router_node.id]:
                    suf += 1
                r_if.name = f"{base_name}-{suf}"
            router_iface_names[router_node.id].add(r_if.name)
            safe_add_link(session, host, router_node, iface1=host_if, iface2=r_if)
            host_router_map[host.id] = router_node.id
            host_direct_link[host.id] = True
            logger.debug("Host %s <-> Router %s LAN /%s", host.id, router_node.id, lan_net.prefixlen)
            if node_type == NodeType.DEFAULT:
                hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                # Ensure default routing service on hosts
                try:
                    ensure_service(session, host.id, "DefaultRoute", node_obj=host)
                except Exception:
                    pass
        else:
            # Multi-host group: create hosts directly (temporarily) off the router; we'll regroup after R2S.
            roles = list(roles)
            random.shuffle(roles)
            base_angle = random.random() * math.tau
            angle_step = math.tau / max(len(roles), 1)
            angle_jitter = math.tau / max(len(roles) * 6, 18)
            angles = [base_angle + angle_step * idx + random.uniform(-angle_jitter, angle_jitter) for idx in range(len(roles))]
            random.shuffle(angles)
            for j, role in enumerate(roles):
                theta = angles[j % len(angles)] if angles else random.random() * math.tau
                radius_center = host_radius_mean + 10 * math.sqrt(len(roles)) + random.uniform(-host_radius_jitter * 0.2, host_radius_jitter * 0.2)
                radius_sigma = max(25, host_radius_jitter * random.uniform(0.5, 1.1))
                r = max(80, int(random.gauss(radius_center, radius_sigma)))
                x = int(rx + r * math.cos(theta) + random.uniform(-30, 30))
                y = int(ry + r * math.sin(theta) + random.uniform(-30, 30))
                node_type = map_role_to_node_type(role)
                name = f"{role.lower()}-{ridx+1}-{j+1}"
                if node_type == NodeType.DEFAULT:
                    host_slot_idx += 1
                    slot_key = f"slot-{host_slot_idx}"
                    try:
                        if docker_slot_plan and slot_key in docker_slot_plan:
                            if hasattr(NodeType, "DOCKER"):
                                node_type = getattr(NodeType, "DOCKER")
                                docker_by_name[name] = docker_slot_plan[slot_key]
                                created_docker += 1
                                docker_slots_used.add(slot_key)
                            else:
                                logger.warning("NodeType.DOCKER not available; cannot apply docker slot plan on segmented (multi-host deferred)")
                    except Exception:
                        pass
                logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", node_id_counter, name, _type_desc(node_type), x, y)
                host_position = Position(x=x, y=y)
                host = session.add_node(node_id_counter, _type=node_type, position=host_position, name=name)
                try:
                    if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                        setattr(host, "model", "docker")
                    elif node_type == NodeType.SWITCH:
                        setattr(host, "model", "switch")
                    elif node_type == NodeType.DEFAULT:
                        setattr(host, "model", "PC")
                except Exception:
                    pass
                actual_host_id = getattr(host, "id", node_id_counter)
                host_nodes_by_id[host.id] = host
                host_next_ifid[host.id] = 1
                # Addressing: allocate per-host /24 directly to router (direct link) for now
                lan_net = subnet_alloc.next_random_subnet(24)
                lan_hosts = list(lan_net.hosts())
                r_ip = str(lan_hosts[0])
                h_ip = str(lan_hosts[1])
                h_mac = mac_alloc.next_mac()
                host_if = Interface(id=0, name="eth0", ip4=h_ip, ip4_mask=lan_net.prefixlen, mac=h_mac)
                r_ifid = router_next_ifid.get(router_node.id, 0)
                router_next_ifid[router_node.id] = r_ifid + 1
                r_if = Interface(id=r_ifid, name=f"r{router_node.id}-h{host.id}", ip4=r_ip, ip4_mask=lan_net.prefixlen, mac=mac_alloc.next_mac())
                base_name = r_if.name
                if base_name in router_iface_names.setdefault(router_node.id, set()):
                    suf = 1
                    while f"{base_name}-{suf}" in router_iface_names[router_node.id]:
                        suf += 1
                    r_if.name = f"{base_name}-{suf}"
                router_iface_names[router_node.id].add(r_if.name)
                safe_add_link(session, host, router_node, iface1=host_if, iface2=r_if)
                host_router_map[host.id] = router_node.id
                host_direct_link[host.id] = True
                if node_type == NodeType.DEFAULT:
                    hosts.append(NodeInfo(node_id=host.id, ip4=f"{h_ip}/{lan_net.prefixlen}", role=role))
                    try:
                        ensure_service(session, host.id, "DefaultRoute", node_obj=host)
                    except Exception:
                        pass

                # If this is a DOCKER node, attach compose/compose_name metadata now
                try:
                    if hasattr(NodeType, "DOCKER") and node_type == getattr(NodeType, "DOCKER"):
                        rec = docker_by_name.get(name)
                        try:
                            if rec:
                                logger.info(
                                    "[vuln-node] created docker node id=%s name=%s from record keys=%s",
                                    actual_host_id,
                                    name,
                                    sorted(rec.keys()),
                                )
                        except Exception:
                            pass
                        _apply_docker_compose_meta(host, rec, session=session)
                        present = False
                        try:
                            present = has_service(session, host.id, "DefaultRoute", node_obj=host)
                        except Exception:
                            present = False
                        if present:
                            try:
                                logger.info("Removing DefaultRoute from DOCKER node %s (id=%s)", getattr(host, "name", host.id), host.id)
                            except Exception:
                                pass
                            ok = remove_service(session, host.id, "DefaultRoute", node_obj=host)
                            try:
                                if ok:
                                    logger.info("Removed DefaultRoute from DOCKER node %s (id=%s)", getattr(host, "name", host.id), host.id)
                                else:
                                    logger.info("DefaultRoute not present or could not remove on DOCKER node %s (id=%s)", getattr(host, "name", host.id), host.id)
                            except Exception:
                                pass
                except Exception:
                    pass

                _log_add_node_result(session, host, node_id_counter, node_type, name, position=host_position)
                node_id_counter += 1

    if docker_slot_plan:
        missing_slots = set(docker_slot_plan.keys()) - docker_slots_used
        if missing_slots:
            raise RuntimeError(
                "Unable to provision Docker nodes for vulnerability assignments: "
                + ", ".join(sorted(missing_slots))
            )

    # Prepare planner policy plan from preview metadata or routing items (legacy compatibility)
    r2s_policy_plan: Optional[Dict[str, Any]] = None
    if preview_plan:
        try:
            r2s_policy_plan = preview_plan.get('r2s_policy')  # type: ignore[assignment]
        except Exception:
            r2s_policy_plan = None
    if not r2s_policy_plan and routing_items:
        try:
            first_r2s = next((ri for ri in routing_items if getattr(ri, 'r2s_mode', None)), None)
        except Exception:
            first_r2s = None
        if first_r2s is not None:
            try:
                mode_val = getattr(first_r2s, 'r2s_mode', None)
            except Exception:
                mode_val = None
            if mode_val:
                if str(mode_val).lower() == 'exact':
                    try:
                        edges_val = int(getattr(first_r2s, 'r2s_edges', 0) or 0)
                    except Exception:
                        edges_val = 0
                    r2s_policy_plan = {'mode': 'Exact'}
                    if edges_val > 0:
                        r2s_policy_plan['target_per_router'] = edges_val
                else:
                    r2s_policy_plan = {'mode': mode_val}

    # --- Router-to-Switch grouping (shared planner for preview/runtime parity) ---
    def _remove_link(a_id: int, b_id: int) -> None:
        key = tuple(sorted((a_id, b_id)))
        try:
            if hasattr(session, 'delete_link'):
                session.delete_link(node1_id=key[0], node2_id=key[1])  # type: ignore
        except Exception:
            pass
        try:
            if hasattr(session, 'links') and isinstance(session.links, list):
                new_links = []
                for lk in session.links:
                    try:
                        n1 = getattr(lk, 'node1_id', getattr(lk, 'node1', None))
                        n2 = getattr(lk, 'node2_id', getattr(lk, 'node2', None))
                    except Exception:
                        if isinstance(lk, tuple) and len(lk) >= 2:
                            n1, n2 = lk[0], lk[1]
                        else:
                            n1 = n2 = None
                    if n1 is None or n2 is None:
                        new_links.append(lk)
                        continue
                    if tuple(sorted((n1, n2))) == key:
                        continue
                    new_links.append(lk)
                session.links = new_links
        except Exception:
            pass

    grouping_out: Optional[Dict[str, Any]] = None
    try:
        from ..planning.router_host_plan import plan_r2s_grouping  # local import to avoid cycles
        host_nodes_for_group = [SimpleNamespace(node_id=hid) for hid in sorted(host_nodes_by_id.keys())]
        grouping_seed = GLOBAL_RANDOM_SEED if GLOBAL_RANDOM_SEED is not None else random.randint(1, 2**31 - 1)
        grouping_out = plan_r2s_grouping(
            router_count,
            host_router_map,
            host_nodes_for_group,
            routing_items,
            r2s_policy_plan,
            grouping_seed,
            ip4_prefix=ip4_prefix,
            ip_mode=ip_mode,
            ip_region=ip_region,
        )
    except Exception:
        grouping_out = None

    try:
        switches_detail = (grouping_out or {}).get('switches_detail') or []
        switch_nodes_preview = (grouping_out or {}).get('switch_nodes') or []
        switch_name_map = {int(sn.get('node_id')): sn.get('name') for sn in switch_nodes_preview if isinstance(sn, dict) and 'node_id' in sn}
        computed_policy = (grouping_out or {}).get('computed_r2s_policy')
        grouping_preview = (grouping_out or {}).get('grouping_preview')

        created_switch_nodes: Dict[int, Any] = {}
        switch_offsets: Dict[int, int] = {rid: 0 for rid in range(1, router_count + 1)}
        rehomed_hosts: List[int] = []
        router_switch_counts: Dict[int, int] = defaultdict(int)
        switch_host_counts: Dict[int, List[int]] = defaultdict(list)

        for detail in switches_detail:
            try:
                switch_id = int(detail.get('switch_id'))
                router_id = int(detail.get('router_id'))
            except Exception:
                continue
            router_node = router_nodes.get(router_id)
            if not router_node:
                continue

            # Determine or create switch node
            sw_node = created_switch_nodes.get(switch_id)
            if sw_node is None:
                switch_offsets[router_id] = switch_offsets.get(router_id, 0) + 1
                offset_idx = switch_offsets[router_id]
                try:
                    pos = getattr(router_node, 'position', None)
                    if pos and hasattr(pos, 'x') and hasattr(pos, 'y'):
                        base_x, base_y = pos.x, pos.y
                    else:
                        base_x, base_y = r_positions[router_id - 1]
                except Exception:
                    base_x, base_y = r_positions[router_id - 1]
                sx = int(base_x + 60 + (offset_idx * 25))
                sy = int(base_y + 40 + (offset_idx * 20))
                name = switch_name_map.get(switch_id) or detail.get('name') or f"rsw-{router_id}-{offset_idx}"
                logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", switch_id, name, _type_desc(NodeType.SWITCH), sx, sy)
                sw_position = Position(x=sx, y=sy)
                sw_node = session.add_node(switch_id, _type=NodeType.SWITCH, position=sw_position, name=name)
                _log_add_node_result(session, sw_node, switch_id, NodeType.SWITCH, name, position=sw_position)
                try:
                    setattr(sw_node, 'model', 'switch')
                except Exception:
                    pass
                created_switch_nodes[switch_id] = sw_node

                # Create router-switch link using preview subnet information when available
                router_ip_raw = detail.get('router_ip')
                switch_ip_raw = detail.get('switch_ip')
                rsw_subnet = detail.get('rsw_subnet')
                r_ip = router_ip_raw
                s_ip = switch_ip_raw
                mask_len = None
                if not r_ip or '/' not in str(r_ip) or not s_ip or '/' not in str(s_ip):
                    if rsw_subnet:
                        try:
                            rsw_net = ipaddress.ip_network(rsw_subnet, strict=False)
                            hosts_iter = list(rsw_net.hosts())
                            if hosts_iter:
                                r_ip = r_ip or f"{hosts_iter[0]}/{rsw_net.prefixlen}"
                            if len(hosts_iter) >= 2:
                                s_ip = s_ip or f"{hosts_iter[1]}/{rsw_net.prefixlen}"
                        except Exception:
                            pass
                if r_ip and '/' in str(r_ip):
                    r_ip_val, mask = str(r_ip).split('/', 1)
                    mask_len = int(mask)
                else:
                    r_ip_val = None
                if s_ip and '/' in str(s_ip):
                    s_ip_val, mask = str(s_ip).split('/', 1)
                    mask_len = mask_len or int(mask)
                else:
                    s_ip_val = None
                if mask_len is None:
                    mask_len = 30
                r_ifid = router_next_ifid.get(router_id, 0)
                router_next_ifid[router_id] = r_ifid + 1
                base_name = f"r{router_id}-rsw{switch_id}-if{r_ifid}"
                r_iface_name = _ensure_router_iface_name(router_iface_names, router_id, base_name)
                r_iface = Interface(id=r_ifid, name=r_iface_name, ip4=r_ip_val, ip4_mask=mask_len, mac=mac_alloc.next_mac())
                sw_iface = Interface(id=0, name=f"{getattr(sw_node, 'name', f'rsw-{switch_id}')}-r{router_id}", ip4=s_ip_val, ip4_mask=mask_len, mac=mac_alloc.next_mac())
                safe_add_link(session, router_node, sw_node, iface1=r_iface, iface2=sw_iface)

            # Attach hosts for this switch
            host_ids_raw = detail.get('hosts') or []
            lan_subnet = detail.get('lan_subnet')
            host_if_ips_raw = detail.get('host_if_ips') or {}
            host_if_ips: Dict[int, str] = {}
            for hk, hv in host_if_ips_raw.items():
                try:
                    host_if_ips[int(hk)] = str(hv)
                except Exception:
                    continue
            lan_net = None
            lan_hosts: List[ipaddress.IPv4Address] = []
            if lan_subnet:
                try:
                    lan_net = ipaddress.ip_network(lan_subnet, strict=False)
                    lan_hosts = list(lan_net.hosts())
                except Exception:
                    lan_net = None
                    lan_hosts = []
            gateway_ip = str(lan_hosts[0]) if lan_hosts else None
            for idx, hid_raw in enumerate(host_ids_raw):
                try:
                    hid = int(hid_raw)
                except Exception:
                    continue
                h_obj = host_nodes_by_id.get(hid)
                if not h_obj:
                    continue
                if host_direct_link.get(hid):
                    _remove_link(hid, router_id)
                host_direct_link[hid] = False
                ip_cidr = host_if_ips.get(hid)
                if not ip_cidr and lan_net and len(lan_hosts) > (idx + 1):
                    ip_cidr = f"{lan_hosts[idx + 1]}/{lan_net.prefixlen}"
                if ip_cidr and '/' in ip_cidr:
                    hip, mask = ip_cidr.split('/', 1)
                    hip_mask = int(mask)
                else:
                    hip = ip_cidr or None
                    hip_mask = lan_net.prefixlen if lan_net else 24
                next_if = host_next_ifid.get(hid, 1)
                host_iface = Interface(id=next_if, name=f"eth{next_if}", ip4=hip, ip4_mask=hip_mask, mac=mac_alloc.next_mac())
                host_next_ifid[hid] = next_if + 1
                sw_iface = Interface(id=idx + 1, name=f"{getattr(created_switch_nodes[switch_id], 'name', f'rsw-{switch_id}')}-h{hid}-{idx+1}", ip4=gateway_ip, ip4_mask=hip_mask, mac=mac_alloc.next_mac())
                safe_add_link(session, h_obj, created_switch_nodes[switch_id], iface1=host_iface, iface2=sw_iface)
                rehomed_hosts.append(hid)

            if host_ids_raw:
                router_switch_counts[router_id] += 1
                switch_host_counts[router_id].append(len(host_ids_raw))

        if created_switch_nodes:
            node_id_counter = max(node_id_counter, max(created_switch_nodes.keys()) + 1)

        topo_stats = getattr(session, 'topo_stats', {}) or {}
        policy_summary: Dict[str, Any] = {}
        if computed_policy:
            policy_summary.update(computed_policy)
        if r2s_policy_plan:
            policy_summary.setdefault('mode_requested', r2s_policy_plan.get('mode'))
            if r2s_policy_plan.get('target_per_router') is not None:
                policy_summary.setdefault('target_per_router', r2s_policy_plan.get('target_per_router'))
        if policy_summary.get('target_per_router') is not None:
            try:
                policy_summary.setdefault('target', float(policy_summary['target_per_router']))
            except Exception:
                pass
        if 'mode' not in policy_summary:
            requested_mode = (r2s_policy_plan or {}).get('mode')
            if requested_mode:
                policy_summary['mode'] = requested_mode
        if 'counts' not in policy_summary and router_switch_counts:
            policy_summary['counts'] = dict(router_switch_counts)

        counts_dict = policy_summary.get('counts') if isinstance(policy_summary.get('counts'), dict) else {}
        applied_counts = list(counts_dict.values()) if counts_dict else []
        if applied_counts:
            stats = _int_list_stats(applied_counts)
            policy_summary['count_min'] = stats['min']
            policy_summary['count_max'] = stats['max']
            policy_summary['count_avg'] = stats['avg']
            policy_summary['count_std'] = stats['std']
            policy_summary['count_gini'] = stats['gini']
            policy_summary['display_min_count'] = stats['min']
            policy_summary['display_max_count'] = stats['max']

        if grouping_out:
            pairs_possible = policy_summary.get('host_pairs_possible_total') or policy_summary.get('host_pairs_possible')
            pairs_used = policy_summary.get('host_pairs_used_total') or policy_summary.get('host_pairs_used')
            if isinstance(pairs_possible, dict):
                policy_summary['host_pairs_possible'] = pairs_possible
                policy_summary['host_pairs_possible_total'] = sum(pairs_possible.values())
            if isinstance(pairs_used, dict):
                policy_summary['host_pairs_used'] = pairs_used
                policy_summary['host_pairs_used_total'] = sum(pairs_used.values())
            if 'host_pair_saturation' in policy_summary:
                policy_summary['saturation'] = policy_summary['host_pair_saturation']

        if rehomed_hosts:
            policy_summary['rehomed_hosts'] = sorted(set(rehomed_hosts))
        if switch_host_counts:
            policy_summary['switch_host_counts'] = {rid: counts for rid, counts in switch_host_counts.items() if counts}
        if grouping_out and 'per_router_bounds' in policy_summary:
            try:
                bounds_map = policy_summary['per_router_bounds']
                mins = [v.get('min') for v in bounds_map.values() if v and v.get('min')]
                maxs = [v.get('max') for v in bounds_map.values() if v and v.get('max')]
                host_counts_flat = [cnt for counts in switch_host_counts.values() for cnt in counts]
                policy_summary['host_group_bounds'] = {
                    'requested_min': min(mins) if mins else None,
                    'requested_max': max(maxs) if maxs else None,
                    'applied_min': min(host_counts_flat) if host_counts_flat else None,
                    'applied_max': max(host_counts_flat) if host_counts_flat else None,
                }
            except Exception:
                pass

        topo_stats['r2s_policy'] = policy_summary
        if grouping_preview is not None:
            topo_stats['r2s_grouping_preview'] = grouping_preview
        setattr(session, 'topo_stats', topo_stats)
    except Exception:
        logger.exception("R-to-S grouping application failed")

    # Post-pass cleanup: ensure no host remains connected to both an original LAN switch (lan-*) and a rehome switch (rsw-*).
    try:
        if hasattr(session, 'links') and hasattr(session, 'get_node'):
            # Build adjacency map host -> list of (switch_id, name)
            for h_id, h_obj in list(host_nodes_by_id.items()):
                switch_neighbors = []
                try:
                    for lk in list(getattr(session, 'links', []) or []):
                        try:
                            n1 = getattr(lk, 'node1_id', None)
                            if n1 is None: n1 = getattr(lk, 'node1', None)
                            n2 = getattr(lk, 'node2_id', None)
                            if n2 is None: n2 = getattr(lk, 'node2', None)
                        except Exception:
                            n1 = n2 = None
                        if n1 is None or n2 is None:
                            continue
                        if h_id not in (n1, n2):
                            continue
                        other = n2 if n1 == h_id else n1
                        try:
                            other_node = session.get_node(other)
                            oname = getattr(other_node, 'name', '') or ''
                            otype = getattr(other_node, 'type', '')
                        except Exception:
                            oname = ''
                        lname = oname.lower()
                        if lname.startswith('lan-') or lname.startswith('rsw-'):
                            switch_neighbors.append((other, oname))
                except Exception:
                    continue
                has_rsw = any(nm.startswith('rsw-') for _, nm in switch_neighbors)
                has_lan = any(nm.startswith('lan-') for _, nm in switch_neighbors)
                if has_rsw and has_lan:
                    # Prefer keeping rsw-*; remove lan-* connections.
                    for sid, nm in switch_neighbors:
                        if nm.startswith('lan-'):
                            _remove_link(h_id, sid)
                    try:
                        logger.debug("Host %s: removed legacy LAN switch links to avoid multi-switch attachment", h_id)
                    except Exception:
                        pass
    except Exception:
        logger.debug("Post R2S cleanup pass failed", exc_info=True)

    # Deferred LAN aggregation: For any router that (a) has multiple directly connected hosts remaining and (b) did not receive R2S switches covering them, create a single LAN switch now.
    try:
        if router_count > 0:
            # Build reverse: router -> list of directly connected host ids (still direct after R2S)
            router_direct_hosts: Dict[int, List[int]] = {r.id: [] for r in router_objs}
            for h_id, rid in host_router_map.items():
                # A host is still "direct" if it has a link to router and NOT a link to any rsw-* switch
                is_direct = False
                has_rsw = False
                try:
                    for lk in list(getattr(session, 'links', []) or []):
                        n1 = getattr(lk, 'node1_id', getattr(lk, 'node1', None))
                        n2 = getattr(lk, 'node2_id', getattr(lk, 'node2', None))
                        if n1 is None or n2 is None:
                            continue
                        if h_id not in (n1, n2):
                            continue
                        other = n2 if n1 == h_id else n1
                        if other == rid:
                            is_direct = True
                        else:
                            try:
                                other_node = session.get_node(other)
                                oname = getattr(other_node, 'name', '') or ''
                            except Exception:
                                oname = ''
                            if oname.startswith('rsw-'):
                                has_rsw = True
                    if is_direct and not has_rsw:
                        router_direct_hosts.setdefault(rid, []).append(h_id)
                except Exception:
                    pass
            for rid, hlist in router_direct_hosts.items():
                if len(hlist) <= 1:
                    continue  # no need to aggregate a single (or zero) host
                # Create one LAN switch for these leftover direct hosts
                try:
                    rnode = session.get_node(rid)
                    rx = getattr(rnode, 'position', getattr(rnode, 'position_x', None))
                    ry = None
                    try:
                        if rx and hasattr(rx, 'x'):
                            ry = rx.y; rx = rx.x
                        else:
                            rx = r_positions[rid-1][0]; ry = r_positions[rid-1][1]
                    except Exception:
                        rx = r_positions[rid-1][0]; ry = r_positions[rid-1][1]
                    sx = int(rx + random.randint(30, 70)); sy = int(ry + random.randint(30, 70))
                    logger.info("[grpc] add_node id=%s name=%s type=%s pos=(%s,%s)", node_id_counter, f"lan-{rid}", _type_desc(NodeType.SWITCH), sx, sy)
                    lan_position = Position(x=sx, y=sy)
                    lan_sw = session.add_node(node_id_counter, _type=NodeType.SWITCH, position=lan_position, name=f"lan-{rid}")
                    _log_add_node_result(session, lan_sw, node_id_counter, NodeType.SWITCH, f"lan-{rid}", position=lan_position)
                    try: setattr(lan_sw, 'model', 'switch')
                    except Exception: pass
                    node_id_counter += 1
                    # Link router <-> lan switch
                    r_ifid = router_next_ifid.get(rid, 0); router_next_ifid[rid] = r_ifid + 1
                    r_if = Interface(id=r_ifid, name=f"r{rid}-lan", mac=None)
                    sw_if = Interface(id=0, name=f"lan-r{rid}")
                    safe_add_link(session, rnode, lan_sw, iface1=r_if, iface2=sw_if)
                    # Move each direct host onto new LAN switch: remove direct link and create LAN link with new host iface (reuse host eth0)
                    for h_id in hlist:
                        _remove_link(h_id, rid)
                        # host side new iface id 1 (since eth0 id=0 already exists / may be reused for IP); treat as same IP, different link
                        next_if = host_next_ifid.get(h_id, 1)
                        h_if = Interface(id=next_if, name=f"eth{next_if}")
                        host_next_ifid[h_id] = next_if + 1
                        sw_ifid = next_if  # simplistic alignment
                        sw_l_if = Interface(id=sw_ifid, name=f"lan{rid}-h{h_id}-if{sw_ifid}")
                        try:
                            h_node = session.get_node(h_id)
                            safe_add_link(session, h_node, lan_sw, iface1=h_if, iface2=sw_l_if)
                        except Exception:
                            pass
                    logger.debug("Deferred LAN switch lan-%s created aggregating %d hosts post-R2S", rid, len(hlist))
                except Exception:
                    logger.debug("Failed deferred LAN aggregation for router %s", rid, exc_info=True)
    except Exception:
        logger.debug("Deferred LAN aggregation phase failed", exc_info=True)

    if created_docker:
        logger.info("Docker nodes created in segmented topology: %d", created_docker)
    router_protocols: Dict[int, List[str]] = {r.node_id: [] for r in routers}
    if routing_items:
        # Only allow protocols explicitly selected by user (excluding Random). If only Random provided, default to OSPFv2.
        concrete_protocols = [ri.protocol for ri in routing_items if ri.protocol and ri.protocol.lower() != 'random']
        fallback_pool = concrete_protocols or ["OSPFv2"]
        for ri in routing_items:
            try:
                if (not ri.protocol) or (ri.protocol.lower() == 'random'):
                    ri.protocol = random.choice(fallback_pool)
            except Exception:
                pass
        # Split routing items into count-based and weight-based
        count_items = [(ri.protocol, int(getattr(ri, 'abs_count', 0) or 0)) for ri in routing_items if int(getattr(ri, 'abs_count', 0) or 0) > 0]
        weight_items = [(ri.protocol, float(getattr(ri, 'factor', 0.0) or 0.0)) for ri in routing_items if not (int(getattr(ri, 'abs_count', 0) or 0) > 0) and float(getattr(ri, 'factor', 0.0) or 0.0) > 0]
        # Build expanded protocols list: first all count-based protocols (absolute), then density-based per weight (for density_router_count only)
        expanded_protocols: List[str] = []
        for proto, c in count_items:
            expanded_protocols.extend([proto] * c)
        # Now add density-based routers by weight factors up to density_router_count
        if density_router_count > 0 and weight_items:
            counts = compute_counts_by_factor(density_router_count, weight_items)
            for proto, c in counts.items():
                expanded_protocols.extend([proto] * c)
        # Truncate/pad to the number of available routers placed
        if len(expanded_protocols) > len(router_objs):
            expanded_protocols = expanded_protocols[:len(router_objs)]
        for i, rnode in enumerate(router_objs):
            rid = rnode.id
            if i < len(expanded_protocols):
                proto = expanded_protocols[i]
                router_protocols[rid].append(proto)
                # IMPORTANT: earlier during router creation we applied mandatory router services (IPForward + zebra).
                # This protocol-assignment pass overwrites the router service set, so ensure the mandatory services remain
                # present before appending protocol-specific daemons.
                base = ["IPForward", "zebra"]
                proto_list = base + [proto] if proto else base
                set_node_services(session, rid, proto_list, node_obj=rnode)
                try:
                    setattr(rnode, "routing_protocol", proto)
                except Exception:
                    pass
        # After assigning protocols, optionally enrich R2R links for protocol groups.
        # BUGFIX: Previously this block created a near/full mesh whenever all routers shared one protocol,
        # even if the base connectivity mode was Random / Exact / Min / NonUniform. We now restrict
        # enrichment to explicit 'Max' (and optionally 'Uniform' with degree budget) policies to avoid
        # divergence from preview specification.
        try:
            if injected_r2r:
                logger.debug("Skipping protocol-based R2R enrichment because preview edges were injected")
                raise RuntimeError('skip_enrichment_injected')
            protocol_groups: Dict[str, List[object]] = {}
            for rnode in router_objs:
                rid = rnode.id
                protos = router_protocols.get(rid) or []
                for p in protos:
                    protocol_groups.setdefault(p, []).append(rnode)
            # Track used interface ids per router (continue from router_next_ifid)
            # Use previously computed topo_stats if available to gauge target degree and avoid over-meshing
            policy = getattr(session, 'topo_stats', {}) or {}
            target_policy = (policy.get('router_edges_policy') or {}).get('mode')
            target_degree = (policy.get('router_edges_policy') or {}).get('target_degree') or 0
            # Build current degree map (refresh after earlier augmentations)
            current_degrees: Dict[int, int] = {r.id: 0 for r in router_objs}
            for a_id, b_id in list(existing_router_links):
                current_degrees[a_id] += 1
                current_degrees[b_id] += 1
            # Determine base connectivity policy to avoid over-enrichment
            base_policy = (policy.get('router_edges_policy') or {}).get('mode')
            for proto, group_nodes in protocol_groups.items():
                if len(group_nodes) <= 1:
                    continue
                # Enrichment permission matrix:
                #   Allow when base policy (connectivity mode) is 'Max'.
                #   Allow limited (degree-budgeted) augmentation for 'Uniform'.
                #   Disallow for ('Min','Exact','Random','NonUniform','Injected') to preserve preview edges.
                #   Additionally: if no base_policy metadata exists (tests / legacy) honor explicit router_mesh_style.
                # If router_mesh_style explicitly provided (tests / legacy), honor it regardless of base_policy.
                explicit_style = bool(router_mesh_style)
                allow_mesh = (base_policy in ('Max',)) or explicit_style
                allow_uniform = base_policy == 'Uniform'
                if not allow_mesh and not allow_uniform:
                    continue
                style = (router_mesh_style or "full").lower()
                ordered = list(group_nodes)
                # Budget: do not exceed target_degree (if specified) by more than +1 when adding protocol links
                def can_link(a_id, b_id):
                    if allow_mesh:
                        return True
                    if allow_uniform and target_degree > 0:
                        # Only add if both endpoints still below (target_degree + 1) to avoid runaway
                        return (current_degrees.get(a_id, 0) < (target_degree + 1) and
                                current_degrees.get(b_id, 0) < (target_degree + 1))
                    return False
                candidate_pairs: List[Tuple[object, object]] = []
                if style == 'ring' and len(ordered) > 2:
                    ring_pairs = [(ordered[i], ordered[(i+1)%len(ordered)]) for i in range(len(ordered))]
                    ring_keys = { (min(a.id,b.id), max(a.id,b.id)) for a,b in ring_pairs }
                    existing_total = sum(1 for k in existing_router_links if k[0] in {r.id for r in ordered} and k[1] in {r.id for r in ordered})
                    existing_ring = sum(1 for k in existing_router_links if k in ring_keys)
                    # Extra non-ring edges present
                    extra = existing_total - existing_ring
                    target_total = len(ordered)  # ring edge count
                    # We can only add up to (target_total - existing_total) edges
                    remaining_budget = max(0, target_total - existing_total)
                    candidate_pairs = []
                    for a,b in ring_pairs:
                        key = (min(a.id,b.id), max(a.id,b.id))
                        if key in existing_router_links:
                            continue
                        if remaining_budget <= 0:
                            break
                        candidate_pairs.append((a,b))
                        remaining_budget -= 1
                elif style == 'tree':
                    # Tree style: ensure no extra edges beyond existing spanning tree -> no candidate pairs
                    # Build simple chain if none exist yet
                    if explicit_style and not any(k[0] in {r.id for r in ordered} and k[1] in {r.id for r in ordered} for k in existing_router_links):
                        for i in range(len(ordered)-1):
                            candidate_pairs.append((ordered[i], ordered[i+1]))
                    else:
                        candidate_pairs = []
                else:
                    # Instead of full mesh, shuffle all potential pairs and apply budget
                    for i in range(len(ordered)):
                        for j in range(i+1, len(ordered)):
                            candidate_pairs.append((ordered[i], ordered[j]))
                    random.shuffle(candidate_pairs)
                    # If not full-mesh allowed, down-select based on degree budget
                    if not allow_mesh and allow_uniform and target_degree > 0:
                        # Filter to pairs where at least one endpoint below target_degree
                        candidate_pairs = [p for p in candidate_pairs if (current_degrees[p[0].id] < target_degree or current_degrees[p[1].id] < target_degree)]
                logger.debug("[mesh-debug] proto=%s style=%s allow_mesh=%s base_policy=%s candidates=%d existing_r2r=%d", proto, style, allow_mesh, base_policy, len(candidate_pairs), len(existing_router_links))
                for a, b in candidate_pairs:
                    key = (min(a.id, b.id), max(a.id, b.id))
                    if key in existing_router_links:
                        continue
                    if not can_link(a.id, b.id):
                        continue
                    a_ifid = router_next_ifid.get(a.id, 0)
                    b_ifid = router_next_ifid.get(b.id, 0)
                    router_next_ifid[a.id] = a_ifid + 1
                    router_next_ifid[b.id] = b_ifid + 1
                    rr_net = subnet_alloc.next_random_subnet(30)
                    rr_hosts = list(rr_net.hosts())
                    if len(rr_hosts) < 2:
                        continue
                    a_ip = str(rr_hosts[0]); b_ip = str(rr_hosts[1])
                    # Uniqueness for protocol augmentation links
                    an_base = f"r{a.id}-{proto.lower()}-{b.id}"
                    bn_base = f"r{b.id}-{proto.lower()}-{a.id}"
                    for rid, base in ((a.id, an_base),(b.id, bn_base)):
                        rset = router_iface_names.setdefault(rid, set())
                        if base in rset:
                            si = 1
                            while f"{base}-{si}" in rset:
                                si += 1
                            if rid == a.id:
                                an_base = f"{base}-{si}"
                            else:
                                bn_base = f"{base}-{si}"
                        # Add after potential rename
                        if rid == a.id:
                            router_iface_names[rid].add(an_base)
                        else:
                            router_iface_names[rid].add(bn_base)
                    a_if = Interface(id=a_ifid, name=an_base, ip4=a_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
                    b_if = Interface(id=b_ifid, name=bn_base, ip4=b_ip, ip4_mask=rr_net.prefixlen, mac=mac_alloc.next_mac())
                    # Guard against accidental duplicate augmentation links
                    key_all2 = (min(a.id, b.id), max(a.id, b.id))
                    if key_all2 not in existing_links:
                        safe_add_link(session, a, b, iface1=a_if, iface2=b_if)
                    existing_router_links.add(key)
                    current_degrees[a.id] += 1; current_degrees[b.id] += 1
                    logger.debug("Protocol %s link r%d<->r%d (style=%s deg=%s/%s)", proto, a.id, b.id, style, current_degrees[a.id], current_degrees[b.id])
        except RuntimeError as e:
            if str(e) != 'skip_enrichment_injected':
                logger.debug("RuntimeError during protocol enrichment: %s", e)
        except Exception as e:
            logger.debug("Failed building protocol-specific router mesh: %s", e)

    host_service_assignments: Dict[int, List[str]] = {}
    if services:
        host_service_assignments = distribute_services(hosts, services)
        for node_id, svc_list in host_service_assignments.items():
            for svc in svc_list:
                assigned = False
                try:
                    if hasattr(session, "add_service"):
                        session.add_service(node_id=node_id, service_name=svc)
                        assigned = True
                except Exception:
                    pass
                if not assigned:
                    try:
                        if hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, svc)
                            except TypeError:
                                node_obj_try = host_nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, svc)
                                    assigned = True
                    except Exception:
                        pass
                if not assigned:
                    node_obj = host_nodes_by_id.get(node_id)
                    if node_obj is not None:
                        try:
                            if hasattr(node_obj, "services") and hasattr(node_obj.services, "add"):
                                node_obj.services.add(svc)
                                assigned = True
                            elif hasattr(node_obj, "add_service"):
                                node_obj.add_service(svc)
                                assigned = True
                        except Exception:
                            pass
                if assigned and svc in ROUTING_STACK_SERVICES:
                    try:
                        if hasattr(session, "add_service"):
                            session.add_service(node_id=node_id, service_name="zebra")
                        elif hasattr(session, "services") and hasattr(session.services, "add"):
                            try:
                                session.services.add(node_id, "zebra")
                            except TypeError:
                                node_obj_try = host_nodes_by_id.get(node_id)
                                if node_obj_try is not None:
                                    session.services.add(node_obj_try, "zebra")
                    except Exception:
                        pass
    # --- Post-build cleanup: remove any orphan switches (only connected to routers, no host endpoints) ---
    try:
        # Heuristic: a switch is orphan if (a) its model is 'switch'; (b) it has no directly connected DEFAULT or DOCKER hosts;
        # and (c) every link involves only routers/switches. We exclude core LAN switches that actually have hosts.
        # Because CORE API for deletion may differ across versions, we do best-effort: detach links and skip node in stats.
        orphan_switch_ids: list[int] = []
        # Build adjacency map if links iterable is available
        link_entries = []
        try:
            if hasattr(session, 'links'):
                link_entries = list(getattr(session, 'links'))  # type: ignore
        except Exception:
            link_entries = []
        # Collect node objects if accessible
        node_index: dict[int, object] = {}
        try:
            if hasattr(session, 'nodes') and isinstance(session.nodes, dict):  # type: ignore
                node_index = session.nodes  # type: ignore
        except Exception:
            pass
        # Helper to classify node type quickly
        def _is_router(nid: int) -> bool:
            try:
                n = node_index.get(nid)
                nm = getattr(n, 'model', '') or getattr(n, 'name', '')
                return 'router' in str(nm).lower()
            except Exception:
                return False
        def _is_host(nid: int) -> bool:
            try:
                n = node_index.get(nid)
                m = getattr(n, 'model', '')
                if not m:
                    return False
                ml = str(m).lower()
                return ml in ('pc','docker','host','default')
            except Exception:
                return False
        def _is_switch(nid: int) -> bool:
            try:
                n = node_index.get(nid)
                return str(getattr(n, 'model', '')).lower() == 'switch'
            except Exception:
                return False
        # Count host-attached links per switch
        sw_links: dict[int, list[tuple[int,int]]] = {}
        for lk in link_entries:
            try:
                a, b = lk[:2]
            except Exception:
                continue
            if _is_switch(a):
                sw_links.setdefault(a, []).append((a,b))
            if _is_switch(b):
                sw_links.setdefault(b, []).append((a,b))
        for sw_id, edges in sw_links.items():
            # Determine if any edge connects to a host
            has_host = any(_is_host(b if a==sw_id else a) for a,b in edges)
            only_router_or_switch = all((_is_router(b if a==sw_id else a) or _is_switch(b if a==sw_id else a)) for a,b in edges)
            if not has_host and only_router_or_switch:
                if sw_id in expected_switch_ids:
                    try:
                        logger.debug("[preview] preserving switch %s without host attachments (expected in preview)", sw_id)
                    except Exception:
                        pass
                    continue
                orphan_switch_ids.append(sw_id)
        if orphan_switch_ids:
            try:
                logger.info("Removing %d orphan switches with no host attachments: %s", len(orphan_switch_ids), orphan_switch_ids)
            except Exception:
                pass
            # Remove associated links
            try:
                if hasattr(session, 'links') and isinstance(session.links, list):  # type: ignore
                    session.links = [lk for lk in session.links if not (lk[0] in orphan_switch_ids or lk[1] in orphan_switch_ids)]  # type: ignore
            except Exception:
                pass
            # Best effort node removal (depends on CORE API)
            for sw_id in orphan_switch_ids:
                try:
                    if hasattr(session, 'delete_node'):
                        session.delete_node(sw_id)  # type: ignore
                except Exception:
                    pass
                # Also prune from internal maps where used for stats
                try:
                    routers[:] = [r for r in routers if r.node_id != sw_id]
                except Exception:
                    pass
    except Exception:
        logger.debug("Orphan switch cleanup failed", exc_info=True)

    # Record host counts per router (direct + via any switches) for report connectivity matrix enrichment
    try:
        topo_stats = getattr(session, 'topo_stats', {}) or {}
        # Build mapping from existing host_router_map if present in locals; else infer via links
        if 'host_router_map' in locals() and isinstance(host_router_map, dict):
            counts = {}
            for hid, rid in host_router_map.items():
                counts[rid] = counts.get(rid, 0) + 1
            topo_stats['router_host_counts'] = counts
        elif hasattr(session, 'links') and isinstance(session.links, list):  # fallback inference
            # naive inference: host id > router_count and link to router id <= router_count
            counts = {}
            for lk in getattr(session, 'links'):
                try:
                    a, b = lk[:2]
                    for r_id, h_id in ((a,b),(b,a)):
                        if isinstance(r_id, int) and isinstance(h_id, int) and r_id <= router_count and h_id > router_count:
                            counts[r_id] = counts.get(r_id, 0) + 1
                except Exception:
                    continue
            if counts:
                topo_stats['router_host_counts'] = counts
        # Attach R2S grouping preview if not already attached (reuse shared helper)
        if not hasattr(session, 'r2s_grouping_preview'):
            try:
                from ..planning.router_host_plan import plan_r2s_grouping  # local import to avoid cycles
                # Build minimal host list for helper
                _hosts_for_group = hosts if 'hosts' in locals() else []  # type: ignore
                # host_router_map is defined earlier in segmented path; if missing, synthesize round-robin
                if 'host_router_map' not in locals() or not isinstance(host_router_map, dict):
                    synth_map: Dict[int,int] = {}
                    seq = 0
                    for h in _hosts_for_group:
                        seq += 1
                        if router_count > 0:
                            synth_map[h.node_id] = ((seq-1) % router_count) + 1
                    host_router_map_local = synth_map
                else:
                    host_router_map_local = host_router_map  # type: ignore
                grouping_seed = GLOBAL_RANDOM_SEED if GLOBAL_RANDOM_SEED is not None else random.randint(1,2**31-1)
                grouping_out = plan_r2s_grouping(router_count, host_router_map_local, _hosts_for_group, routing_items, None, grouping_seed, ip4_prefix=ip4_prefix, ip_mode=ip_mode, ip_region=ip_region)  # type: ignore
                setattr(session, 'r2s_grouping_preview', grouping_out.get('grouping_preview'))
                setattr(session, 'r2s_policy_preview', grouping_out.get('computed_r2s_policy'))
            except Exception:
                pass
        setattr(session, 'topo_stats', topo_stats)
    except Exception:
        pass
    if DIAG_ENABLED:
        try:
            link_len = len(getattr(session, 'links', []) or []) if hasattr(session,'links') else 'n/a'
            logger.info('[diag.summary.segmented.final] routers=%s hosts=%s links_list=%s attempts=%s success=%s fail=%s', len(routers), len(hosts), link_len, link_counters['attempts'], link_counters['success'], link_counters['fail_total'])
        except Exception:
            pass
        if int(os.getenv('CORETG_LINK_FAIL_HARD','0') not in ('0','false','False','')) and link_counters['success']==0:
            raise RuntimeError('No links created in segmented topology')
    return session, routers, hosts, host_service_assignments, router_protocols, docker_by_name
    
