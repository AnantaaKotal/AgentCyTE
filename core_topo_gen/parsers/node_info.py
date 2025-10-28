from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from ..types import ServiceInfo
from .common import find_scenario, has_unexpected_container
from .services import parse_services

logger = logging.getLogger(__name__)


def parse_node_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[int, List[Tuple[str, float]], List[Tuple[str, int]], List[ServiceInfo]]:
    default_count = 10
    default_items = [("Workstation", 1.0)]
    if not os.path.exists(xml_path):
        logger.warning("XML file not found: %s; defaulting total_nodes=%s, items=%s", xml_path, default_count, default_items)
        return default_count, default_items, [], []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        if has_unexpected_container(root):
            logger.error("Node Info parse aborted: XML contains <container> (CORE session XML). Using defaults.")
            return default_count, default_items, [], []
    except Exception as e:
        logger.warning("Failed to parse XML (%s); defaulting values", e)
        return default_count, default_items, [], []
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found; defaulting values")
        return default_count, default_items, [], []
    section = scenario.find(".//section[@name='Node Information']")
    if section is None:
        logger.warning("'Node Information' section not found; defaulting values")
        return default_count, default_items, [], []
    density_base: Optional[int] = None
    try:
        scen_attr = scenario.get("density_count") if scenario is not None else None
        if scen_attr is not None and str(scen_attr).strip() != "":
            density_base = int(str(scen_attr).strip())
        else:
            for raw in [section.get("density_count"), section.get("base_nodes"), section.get("total_nodes")]:
                if raw is None:
                    continue
                s = str(raw).strip()
                if not s:
                    continue
                try:
                    density_base = int(s)
                    break
                except Exception:
                    continue
    except Exception:
        density_base = None
    if density_base is None:
        density_base = default_count
    if density_base < 0:
        density_base = 0
    items_el = section.findall("./item")
    count_map: Dict[str, int] = {}
    weight_items: List[Tuple[str, float]] = []
    # Optional gating: only consider weight-based rows if section attribute weight_rows > 0
    try:
        weight_rows_attr = section.get("weight_rows")
        weight_rows_val = int(str(weight_rows_attr).strip()) if (weight_rows_attr is not None and str(weight_rows_attr).strip() != "") else None
    except Exception:
        weight_rows_val = None
    for it in items_el:
        role = (it.get("selected") or "").strip() or "Workstation"
        vm = (it.get("v_metric") or "").strip()
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
            except Exception:
                vc = 0
            if vc > 0:
                count_map[role] = count_map.get(role, 0) + vc
            continue
        # Only collect weight items if gating attribute allows (>0) or attribute absent (backward compatible)
        gating_ok = (weight_rows_val is None) or (weight_rows_val > 0)
        try:
            f = float((it.get("factor") or "0").strip()) if gating_ok else 0.0
        except Exception:
            f = 0.0
        if gating_ok and f > 0:
            weight_items.append((role, f))
    count_items = [(r, c) for r, c in sorted(count_map.items())]
    services: List[ServiceInfo] = parse_services(scenario)
    return density_base, weight_items, count_items, services
