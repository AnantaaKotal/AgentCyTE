from __future__ import annotations
"""Unified planning orchestrator.

All section calculations (nodes, routers, services, vulnerabilities, segmentation, traffic)
are centralized here so both CLI and Web preview can share identical logic.
"""
from typing import Optional, Dict, Any, List, Tuple
import logging

from .node_plan import compute_node_plan
from .router_plan import compute_router_plan
from .service_plan import compute_service_plan, ServiceSpec
from .vulnerability_plan import compute_vulnerability_plan, VulnerabilityItem
from .segmentation_plan import compute_segmentation_plan, SegmentationItem
from .traffic_plan import compute_traffic_plan, TrafficItem

from ..parsers.base import parse_base_reference
from ..parsers.node_info import parse_node_info
from ..parsers.routing import parse_routing_info
from ..parsers.services import parse_services
from ..parsers.vulnerabilities import parse_vulnerabilities_info
from ..parsers.segmentation import parse_segmentation_info

logger = logging.getLogger(__name__)

def compute_full_plan(
    xml_path: str,
    scenario: Optional[str] = None,
    seed: Optional[int] = None,
    include_breakdowns: bool = True,
) -> Dict[str, Any]:
    """Compute a unified planning object for all scenario sections.

    Returns a dict containing role counts, routers planned, and per-section plan + breakdowns.
    This function intentionally mirrors (and supersedes) ad-hoc logic previously in CLI and web preview.
    """
    # --- Node Information ---
    density_base, weight_items, count_items, services_list = parse_node_info(xml_path, scenario)
    role_counts, node_breakdown = compute_node_plan(density_base, weight_items, count_items)

    # --- Routing ---
    routing_density, routing_items = parse_routing_info(xml_path, scenario)
    routers_planned, router_breakdown = compute_router_plan(
        total_hosts=sum(role_counts.values()),
        base_host_pool=density_base,
        routing_density=routing_density,
        routing_items=routing_items,
    )
    router_breakdown['routing_density_input'] = routing_density
    try:
        router_breakdown['routing_items_count'] = len(routing_items or [])
    except Exception:
        pass
    # lightweight simple plan mapping protocol -> abs_count (for display)
    simple_routing_plan = {}
    try:
        for ri in routing_items:
            if getattr(ri, 'abs_count', 0) > 0:
                simple_routing_plan[getattr(ri, 'protocol', 'proto')] = int(getattr(ri, 'abs_count', 0))
    except Exception:
        pass
    router_breakdown['simple_plan'] = simple_routing_plan

    # --- Services ---
    svc_specs = [ServiceSpec(s.name, density=getattr(s, 'density', 0.0), abs_count=getattr(s, 'abs_count', 0)) for s in services_list]
    service_plan, service_breakdown = compute_service_plan(svc_specs, density_base)

    # --- Vulnerabilities ---
    vuln_density, vuln_items_xml = parse_vulnerabilities_info(xml_path, scenario)
    vuln_items: List[VulnerabilityItem] = []
    for it in (vuln_items_xml or []):
        name = (it.get('selected') or 'Item') if hasattr(it, 'get') else 'Item'
        vm_raw = (it.get('v_metric') if hasattr(it, 'get') else '') or ''
        vm = vm_raw.strip() or ('Count' if ((it.get('selected') or '').strip() == 'Specific' and (it.get('v_count') or '').strip()) else 'Weight')
        abs_c = 0
        if vm.lower() == 'count':
            try:
                abs_c = int(it.get('v_count') or 0)
            except Exception:
                abs_c = 0
        try:
            factor_val = float((it.get('factor') or 0.0)) if hasattr(it, 'get') else 0.0
        except Exception:
            factor_val = 0.0
        kind = (it.get('selected') or name) if hasattr(it, 'get') else name
        vuln_items.append(VulnerabilityItem(name=name, density=vuln_density, abs_count=abs_c, kind=kind, factor=factor_val, metric=vm))
    vulnerability_plan, vuln_breakdown = compute_vulnerability_plan(density_base, vuln_density, vuln_items)

    # --- Segmentation ---
    seg_density, seg_items = parse_segmentation_info(xml_path, scenario)
    segmentation_plan, seg_breakdown = compute_segmentation_plan(seg_density, seg_items, density_base)
    seg_breakdown['raw_items_serialized'] = [{'selected': si.name, 'factor': si.factor} for si in seg_items]

    # --- Traffic (optional, parse if module available) ---
    traffic_plan_out: List[Dict[str, Any]] | None = None
    traffic_breakdown: Dict[str, Any] | None = None
    try:
        from ..parsers.traffic import parse_traffic_info  # type: ignore
        traffic_density, traffic_items_xml = parse_traffic_info(xml_path, scenario)
        # Represent traffic via factors/pattern if needed; currently pass-through minimal usage
        t_items: List[TrafficItem] = []
        for it in (traffic_items_xml or []):
            try:
                pattern = it.get('pattern') if hasattr(it, 'get') else 'continuous'
                rate = it.get('rate_kbps') if hasattr(it, 'get') else None
                factor_raw = it.get('factor') if hasattr(it, 'get') else 1.0
                try:
                    factor = float(factor_raw or 0.0)
                except Exception:
                    factor = 0.0
                t_items.append(TrafficItem(pattern=pattern or 'continuous', rate_kbps=rate, factor=factor))
            except Exception:
                continue
        if t_items:
            traffic_plan_out, traffic_breakdown = compute_traffic_plan(t_items)
            traffic_breakdown['traffic_density_input'] = traffic_density
    except Exception:
        pass

    plan: Dict[str, Any] = {
        'seed': seed,
        'density_base': density_base,
        'role_counts': role_counts,
        'routers_planned': routers_planned,
        'routing_density': routing_density,
        'routing_items': routing_items,  # raw objects for downstream preview builder
        'service_plan': service_plan,
        'vulnerability_plan': vulnerability_plan,
        'segmentation_plan': segmentation_plan,
        'traffic_plan': traffic_plan_out,
        # raw items for build path reuse (not all JSON-serializable; caller should sanitize if emitting)
        'vulnerability_items_raw': vuln_items_xml,
        'segmentation_items_raw': seg_items,
    }
    try:
        base_ref = parse_base_reference(xml_path, scenario)
        if base_ref:
            plan['base_scenario'] = base_ref
    except Exception:
        pass
    if include_breakdowns:
        plan['breakdowns'] = {
            'node': node_breakdown,
            'router': router_breakdown,
            'services': service_breakdown,
            'vulnerabilities': vuln_breakdown,
            'segmentation': seg_breakdown,
            'traffic': traffic_breakdown,
        }
    return plan
