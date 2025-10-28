from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple
from ..types import SegmentationInfo
from .common import find_scenario

logger = logging.getLogger(__name__)


def parse_segmentation_info(xml_path: str, scenario_name: Optional[str]) -> Tuple[float, List[SegmentationInfo]]:
    density = 0.0
    items: List[SegmentationInfo] = []
    if not os.path.exists(xml_path):
        logger.warning("XML not found for segmentation parse: %s", xml_path)
        return density, items
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        logger.warning("Failed to parse XML for segmentation (%s)", e)
        return density, items
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.warning("No <Scenario> found for segmentation parse")
        return density, items
    section = scenario.find(".//section[@name='Segmentation']")
    if section is None:
        return density, items
    den_raw = (section.get("density") or "").strip()
    if den_raw:
        try:
            density = float(den_raw)
            if density < 0:
                density = 0.0
        except Exception:
            logger.warning("Invalid Segmentation density '%s'", den_raw)
            density = 0.0
    for it in section.findall("./item"):
        name = (it.get("selected") or "").strip()
        if not name:
            continue
        try:
            factor = float((it.get("factor") or "0").strip())
        except Exception:
            factor = 0.0
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
            items.append(SegmentationInfo(name=name, factor=factor, abs_count=abs_count))
    logger.debug("Parsed segmentation: density=%s items=%s", density, [(i.name, i.factor) for i in items])
    return density, items
