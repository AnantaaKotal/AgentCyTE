from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple
from ..types import TrafficInfo
from .common import find_scenario

logger = logging.getLogger(__name__)


def parse_traffic_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[TrafficInfo]]:
    density = 0.0
    items: List[TrafficInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for traffic parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for traffic (%s)", e)
        return density, items
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for traffic parse")
        return density, items
    section = scenario.find(".//section[@name='Traffic']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            density = max(0.0, min(1.0, density))
        except Exception:
            logger.warning("Invalid Traffic density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        kind = (it.get("selected") or "").strip()
        if not kind:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
        pattern = (it.get("pattern") or "").strip()
        try:
            rate_kbps = float((it.get("rate") or it.get("rate_kbps") or "0").strip())
        except Exception:
            rate_kbps = 0.0
        try:
            period_s = float((it.get("period") or it.get("period_s") or "0").strip())
        except Exception:
            period_s = 0.0
        try:
            jitter_pct = float((it.get("jitter") or it.get("jitter_pct") or "0").strip())
        except Exception:
            jitter_pct = 0.0
        content_type = (it.get("content") or it.get("content_type") or "").strip()
        rate_kbps = max(0.0, rate_kbps)
        period_s = max(0.0, period_s)
        jitter_pct = max(0.0, min(100.0, jitter_pct))
        vm = (it.get("v_metric") or "").strip()
        abs_count = 0
        if vm == "Count":
            try:
                vc = int((it.get("v_count") or "0").strip())
                if vc >= 0:
                    abs_count = vc
            except Exception:
                abs_count = 0
        if factor > 0 or abs_count > 0:
            items.append(TrafficInfo(
                kind=kind,
                factor=factor,
                pattern=pattern,
                rate_kbps=rate_kbps,
                period_s=period_s if period_s > 0 else 10.0,
                jitter_pct=jitter_pct,
                content_type=content_type,
                abs_count=abs_count,
            ))
    logger.debug("Parsed traffic: density=%s items=%s", density, [
        (i.kind, i.factor, i.pattern, i.rate_kbps, i.period_s, i.jitter_pct) for i in items
    ])
    return density, items
