from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Union
from .common import find_scenario, has_unexpected_container
from .node_info import parse_node_info
from .routing import parse_routing_info
from .vulnerabilities import parse_vulnerabilities_info

logger = logging.getLogger(__name__)


def parse_planning_metadata(xml_path: str, scenario_name: Optional[str]) -> Dict[str, Dict[str, Union[int, float]]]:
    meta: Dict[str, Dict[str, Union[int, float]]] = {}
    if not os.path.exists(xml_path):
        return meta
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        if has_unexpected_container(root):
            logger.error("Planning metadata parse aborted: XML contains <container> (session XML). Returning empty meta.")
            return meta
    except Exception:
        return meta
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        return meta

    scen_total_raw = scenario.get('scenario_total_nodes')
    if scen_total_raw is not None:
        try:
            scen_total = int(str(scen_total_raw).strip())
            meta['scenario'] = {'scenario_total_nodes': scen_total}
        except Exception:
            pass

    def _int(val: Optional[str]) -> Optional[int]:
        if val is None or val == "":
            return None
        try:
            return int(val)
        except Exception:
            return None

    def _float(val: Optional[str]) -> Optional[float]:
        if val is None or val == "":
            return None
        try:
            return float(val)
        except Exception:
            return None

    ni = scenario.find(".//section[@name='Node Information']")
    if ni is not None:
        base_nodes = _int(ni.get("base_nodes"))
        additive_nodes = _int(ni.get("additive_nodes"))
        combined_nodes = _int(ni.get("combined_nodes"))
        weight_rows = _int(ni.get("weight_rows"))
        count_rows = _int(ni.get("count_rows"))
        weight_sum = _float(ni.get("weight_sum"))
        if base_nodes is None or additive_nodes is None or combined_nodes is None:
            density_base, weight_items, count_items, _ = parse_node_info(xml_path, scenario_name)
            if base_nodes is None:
                base_nodes = density_base
            if additive_nodes is None:
                additive_nodes = sum(c for _r, c in count_items)
            if combined_nodes is None:
                combined_nodes = (base_nodes or 0) + (additive_nodes or 0)
            if weight_rows is None:
                weight_rows = len(weight_items)
            if count_rows is None:
                count_rows = len(count_items)
            if weight_sum is None:
                weight_sum = float(sum(f for _r, f in weight_items))
        meta['node_info'] = {
            'base_nodes': base_nodes or 0,
            'additive_nodes': additive_nodes or 0,
            'combined_nodes': combined_nodes or ((base_nodes or 0) + (additive_nodes or 0)),
            'weight_rows': weight_rows or 0,
            'count_rows': count_rows or 0,
            'weight_sum': weight_sum or 0.0,
        }

    def _parse_section(sec_name: str, key: str):
        sec = scenario.find(f".//section[@name='{sec_name}']")
        if sec is None:
            return
        explicit = _int(sec.get("explicit_count"))
        derived = _int(sec.get("derived_count"))
        total_planned = _int(sec.get("total_planned"))
        weight_rows = _int(sec.get("weight_rows"))
        count_rows = _int(sec.get("count_rows"))
        weight_sum = _float(sec.get("weight_sum"))
        if explicit is None or total_planned is None:
            if sec_name == 'Routing':
                _density, r_items = parse_routing_info(xml_path, scenario_name)
                explicit = sum(i.abs_count for i in r_items if i.abs_count > 0) if explicit is None else explicit
                if weight_rows is None:
                    weight_rows = sum(1 for i in r_items if i.factor > 0)
                if count_rows is None:
                    count_rows = sum(1 for i in r_items if i.abs_count > 0)
                if weight_sum is None:
                    weight_sum = float(sum(i.factor for i in r_items if i.factor > 0))
            else:  # Vulnerabilities
                _density, v_items = parse_vulnerabilities_info(xml_path, scenario_name)
                exp_counts = 0
                weight_items_cnt = 0
                weight_sum_tmp = 0.0
                for rec in v_items:
                    vm = rec.get('v_metric')
                    if rec.get('selected') == 'Specific' and 'v_count' in rec:
                        try:
                            exp_counts += int(rec['v_count'])
                        except Exception:
                            pass
                    else:
                        try:
                            f = float(rec.get('factor', 0) or 0)
                        except Exception:
                            f = 0.0
                        if f > 0:
                            weight_items_cnt += 1
                            weight_sum_tmp += f
                if explicit is None:
                    explicit = exp_counts
                if weight_rows is None:
                    weight_rows = weight_items_cnt
                if count_rows is None:
                    count_rows = 0 if exp_counts == 0 else 1
                if weight_sum is None:
                    weight_sum = weight_sum_tmp
        if total_planned is None and (explicit is not None) and (derived is not None):
            total_planned = explicit + derived
        if explicit is None and total_planned is not None and derived is not None:
            explicit = total_planned - derived
        if derived is None:
            derived = 0
        if explicit is None:
            explicit = 0
        if total_planned is None:
            total_planned = explicit + derived
        if weight_rows is None:
            weight_rows = 0
        if count_rows is None:
            count_rows = 0
        if weight_sum is None:
            weight_sum = 0.0
        meta[key] = {
            'explicit_count': explicit,
            'derived_count': derived,
            'total_planned': total_planned,
            'weight_rows': weight_rows,
            'count_rows': count_rows,
            'weight_sum': weight_sum,
        }

    _parse_section('Routing', 'routing')
    _parse_section('Vulnerabilities', 'vulnerabilities')
    return meta
