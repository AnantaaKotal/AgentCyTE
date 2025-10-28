from __future__ import annotations
from typing import List, Tuple
import logging
from ..types import RoutingInfo

logger = logging.getLogger(__name__)


def compute_router_plan(total_hosts: int, base_host_pool: int, routing_density: float, routing_items: List[RoutingInfo]) -> Tuple[int, dict]:
    """Compute router count with simplified rule (no absolute legacy mode):

    final = count_based + floor(clamp01(routing_density) * base_host_pool)
    then clamped to total_hosts.
    """
    # 1) Classify routing items (count-based vs weight-based vs ignored) and accumulate absolute counts.
    item_classifications = []
    count_based = 0
    if logger.isEnabledFor(logging.INFO):
        logger.info("[router.plan] ---- ROUTER PLANNING START ----")
        logger.info(
            "[router.plan] inputs: total_hosts=%s base_host_pool(raw)=%s routing_density(raw)=%.6f items=%d", 
            total_hosts, base_host_pool, (routing_density or 0.0), len(routing_items or [])
        )
    # Expand Random placeholder protocols (weight-based only) before classification.
    # Web UI enumeration (excluding 'Random'): ["RIP", "RIPv2", "BGP", "OSPFv2", "OSPFv3"]
    DEFAULT_RANDOM_PROTOCOLS = ["RIP", "RIPv2", "BGP", "OSPFv2", "OSPFv3"]
    expanded_items: List[RoutingInfo] = []
    random_weight_factor = 0.0
    for ri in (routing_items or []):
        proto = getattr(ri, 'protocol', '') or ''
        if proto.strip().lower() == 'random':
            try:
                factor_val = float(getattr(ri, 'factor', 0.0) or 0.0)
            except Exception:
                factor_val = 0.0
            try:
                abs_val = int(getattr(ri, 'abs_count', 0) or 0)
            except Exception:
                abs_val = 0
            # Count-based Random: split absolute count evenly across defaults
            if abs_val > 0:
                base_each = abs_val // len(DEFAULT_RANDOM_PROTOCOLS)
                residual = abs_val - base_each * len(DEFAULT_RANDOM_PROTOCOLS)
                for idx_p, p in enumerate(DEFAULT_RANDOM_PROTOCOLS):
                    c = base_each + (1 if idx_p < residual else 0)
                    if c > 0:
                        expanded_items.append(RoutingInfo(protocol=p, factor=0.0, abs_count=c, r2r_mode=getattr(ri,'r2r_mode',None), r2r_edges=getattr(ri,'r2r_edges',0), r2s_mode=getattr(ri,'r2s_mode',None), r2s_edges=getattr(ri,'r2s_edges',0), r2s_hosts_min=getattr(ri,'r2s_hosts_min',0), r2s_hosts_max=getattr(ri,'r2s_hosts_max',0)))
            elif factor_val > 0:
                random_weight_factor += factor_val
            # else ignored
        else:
            expanded_items.append(ri)
    # Distribute accumulated Random weight factor across defaults
    if random_weight_factor > 0:
        share = random_weight_factor / len(DEFAULT_RANDOM_PROTOCOLS)
        for p in DEFAULT_RANDOM_PROTOCOLS:
            expanded_items.append(RoutingInfo(protocol=p, factor=share, abs_count=0))

    try:
        for idx, ri in enumerate(expanded_items or []):
            try:
                abs_c = int(getattr(ri, 'abs_count', 0) or 0)
            except Exception:
                abs_c = 0
            try:
                factor = float(getattr(ri, 'factor', 0) or 0.0)
            except Exception:
                factor = 0.0
            if abs_c > 0:
                classification = 'count'
                count_based += abs_c
            elif abs_c == 0 and factor > 0.0:
                classification = 'weight'
            else:
                classification = 'ignored'
            item_classifications.append({
                'index': idx,
                'protocol': getattr(ri, 'protocol', f'proto{idx}'),
                'abs_count': abs_c,
                'factor': factor,
                'classification': classification,
            })
            if logger.isEnabledFor(logging.INFO):
                logger.info(
                    "[router.plan.item] #%d protocol=%s abs_count=%d factor=%.6f classification=%s", 
                    idx, getattr(ri, 'protocol', f'proto{idx}'), abs_c, factor, classification
                )
    except Exception as e:  # pragma: no cover
        if logger.isEnabledFor(logging.WARNING):
            logger.warning("[router.plan] item classification failed: %s", e)
    effective_base = max(0, int(base_host_pool or 0))
    import math as _math
    try:
        rd_val = float(routing_density or 0.0)
    except Exception:  # pragma: no cover
        rd_val = 0.0
    # 2) Determine density eligibility.
    has_weight_based = any(ic['classification'] == 'weight' for ic in item_classifications)
    d = max(0.0, min(1.0, rd_val)) if has_weight_based else 0.0
    if logger.isEnabledFor(logging.INFO):
        if not has_weight_based and rd_val not in (0, 0.0):
            logger.info("[router.plan] density suppressed: no weight-based items (need abs_count==0 AND factor>0). raw=%.6f", rd_val)
        logger.info(
            "[router.plan] eligibility: has_weight_based=%s rd_raw=%.6f rd_clamped=%.6f", 
            has_weight_based, rd_val, d
        )
    # 3) Compute density component.
    density_component = int(_math.floor(effective_base * d + 1e-9))
    density_component = max(0, min(effective_base, density_component))
    if logger.isEnabledFor(logging.INFO):
        logger.info(
            "[router.plan] density_component=floor(rd_clamped * effective_base)=floor(%.6f * %d)=%d", 
            d, effective_base, density_component
        )
    # 4) Combine with count-based component.
    router_count = min(total_hosts, count_based + density_component)
    if logger.isEnabledFor(logging.INFO):
        raw_total = count_based + density_component
        if raw_total != router_count:
            logger.info(
                "[router.plan] final cap: min(total_hosts=%d, raw_total=%d) => %d", 
                total_hosts, raw_total, router_count
            )
        logger.info(
            "[router.plan] components: count_based=%d + density_component=%d => raw_total=%d", 
            count_based, density_component, raw_total
        )
        logger.info("[router.plan] ---- ROUTER PLANNING END (final=%d) ----", router_count)
    breakdown = {
        'density_raw': rd_val,
        'density_component': density_component,
        'count_based_component': count_based,
        'effective_base': effective_base,
        'final_router_count': router_count,
        'has_weight_based': has_weight_based,
        'items': item_classifications,
        'random_weight_factor': random_weight_factor,
        'random_defaults': DEFAULT_RANDOM_PROTOCOLS,
    }
    return router_count, breakdown
