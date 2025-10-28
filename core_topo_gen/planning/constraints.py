from __future__ import annotations
from typing import Dict, List, Tuple, Optional

class ConstraintViolation(Exception):
    pass

def validate_pool_final(state: Dict) -> List[str]:
    messages: List[str] = []
    # Basic allocations
    if state.get("routers_allocated", 0) > state.get("routers_planned", 0):
        messages.append("Allocated more routers than planned")
    if state.get("hosts_allocated", 0) > state.get("hosts_total", 0):
        messages.append("Allocated more hosts than available")
    # Services upper bounds
    sp = state.get("services_plan", {}) or {}
    sa = state.get("services_assigned", {}) or {}
    for name, planned in sp.items():
        if planned >= 0 and sa.get(name, 0) > planned:
            messages.append(f"Service {name} assigned {sa.get(name)} > planned {planned}")
    # R2R policy validation: enforce stricter semantics for Exact target_degree (esp. 1)
    r2r = state.get("r2r_policy") or {}
    target_deg = r2r.get("target_degree") or 0
    n = state.get("routers_planned", 0) or state.get("routers_total_planned", 0) or 0
    actual_edges = state.get("r2r_edges_created", 0) or state.get("r2r_edges") or 0
    degrees_map = state.get("router_degrees") or {}
    if target_deg > 0 and n > 0:
        expected_edges = (n * target_deg) / 2.0
        if target_deg == 1:
            expected_matching = n // 2
            if actual_edges != expected_matching:
                messages.append(f"Exact degree 1 mismatch: edges {actual_edges} != expected {expected_matching}")
            if degrees_map:
                deg_values = list(degrees_map.values())
                zeros = sum(1 for d in deg_values if d == 0)
                invalid = [d for d in deg_values if d not in (0,1)]
                if invalid:
                    messages.append(f"Exact degree 1 violation: found degrees {sorted(set(invalid))}")
                if zeros > (1 if n % 2 == 1 else 0):
                    messages.append("Too many zero-degree routers for target_degree=1")
        else:
            # Tightened tolerance: allow at most +/- n*0.1 edges (rounded) before flagging; min 1 edge slack.
            diff = abs(actual_edges - expected_edges)
            allowed = max(1, int(round(n * 0.1)))
            if diff > allowed:
                messages.append(f"R2R edges {actual_edges} deviate from expected {expected_edges:.1f} (>±{allowed} allowed) (target_degree={target_deg})")
            if degrees_map:
                min_d = min(degrees_map.values()) if degrees_map else 0
                max_d = max(degrees_map.values()) if degrees_map else 0
                if min_d < target_deg and (target_deg - min_d) > 1:
                    messages.append(f"Min router degree {min_d} below target {target_deg}")
                if max_d > target_deg + 1:
                    messages.append(f"Max router degree {max_d} exceeds target {target_deg}+1 tolerance")
    # R2S Exact semantics validation (mirrors degree-like target of switches per router)
    r2s = state.get('r2s_policy') or {}
    r2s_target = r2s.get('target_per_router') or r2s.get('target') or 0
    r2s_counts = r2s.get('counts') or {}
    if r2s_target and r2s_counts:
        vals = list(r2s_counts.values())
        if vals:
            mn, mx = min(vals), max(vals)
            if mn < r2s_target - 1:
                messages.append(f"R2S min count {mn} below target {r2s_target}-1 tolerance")
            if mx > r2s_target + 1:
                messages.append(f"R2S max count {mx} exceeds target {r2s_target}+1 tolerance")
    # Vulnerabilities
    vplan = state.get("vulnerabilities_plan") or {}
    v_assigned = state.get("vulnerabilities_assigned", 0)
    if vplan:
        planned_total = sum(vplan.values())
        if v_assigned > planned_total:
            messages.append(f"Vulnerabilities assigned {v_assigned} > planned {planned_total}")
    return messages

# Incremental / phase validations
def validate_phase(state: Dict, phase: str) -> List[str]:
    issues: List[str] = []
    if phase == 'routers':
        if state.get('routers_allocated', 0) != state.get('routers_planned', 0):
            issues.append(f"Routers allocated {state.get('routers_allocated')} != planned {state.get('routers_planned')}")
    elif phase == 'r2r':
        if state.get('routers_planned', 0) > 1 and state.get('r2r_edges_created', 0) == 0:
            issues.append('No R2R edges created')
    elif phase == 'hosts':
        if state.get('hosts_allocated', 0) != state.get('hosts_total', 0):
            # soft warning; host counts can be capped externally
            issues.append('Host allocation mismatch (allocated vs total)')
    elif phase == 'r2s':
        pol = state.get('r2s_policy') or {}
        counts = pol.get('counts') or {}
        # Support legacy ratio mode and new Exact semantics
        ratio = pol.get('ratio')
        target = pol.get('target_per_router') or pol.get('target')
        if (ratio or target) and not counts:
            issues.append('R2S policy specified but no switch counts recorded')
    elif phase == 'vulns':
        vp = state.get('vulnerabilities_plan') or {}
        if vp and state.get('vulnerabilities_assigned', 0) == 0:
            # informational – assignment may occur later
            pass
    return issues

def enforce_no_drift(planned: Dict, actual: Dict, strict: bool = True) -> List[str]:
    """Compare planned summary vs runtime actual; return list of drift violations."""
    violations: List[str] = []
    keys_hard = [ ('routers_planned','routers_allocated','routers'), ('hosts_total','hosts_allocated','hosts') ]
    for p_key, a_key, label in keys_hard:
        if planned.get(p_key) is not None and actual.get(a_key) is not None:
            if planned[p_key] != actual[a_key]:
                violations.append(f"Drift: {label} planned {planned[p_key]} != actual {actual[a_key]}")
    # R2S ratio
    p_ratio = planned.get('r2s_ratio_used') or (planned.get('r2s_policy') or {}).get('ratio')
    a_ratio = actual.get('r2s_ratio_used') or (actual.get('r2s_policy') or {}).get('ratio')
    if p_ratio and a_ratio and abs(float(p_ratio) - float(a_ratio)) > 1e-6:
        violations.append(f"Drift: r2s ratio planned {p_ratio} != actual {a_ratio}")
    # Vulnerabilities total (soft tolerance)
    pv_total = 0
    if planned.get('vulnerabilities_plan'):
        pv_total = sum((planned['vulnerabilities_plan'] or {}).values())
    av_total = actual.get('vulnerabilities_assigned')
    if pv_total and av_total and av_total != pv_total:
        violations.append(f"Drift: vulnerabilities assigned {av_total} != planned {pv_total}")
    return violations
