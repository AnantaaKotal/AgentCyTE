from __future__ import annotations
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Optional

from .common import find_scenario, has_unexpected_container

logger = logging.getLogger(__name__)


def parse_base_reference(xml_path: str, scenario_name: Optional[str]) -> Optional[Dict[str, str]]:
    """Extract the BaseScenario filepath for the requested scenario.

    Returns a dict containing:
      - filepath_raw: original value from XML
      - filepath: absolute, expanded path (if resolvable)
    """
    if not xml_path or not os.path.exists(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        if has_unexpected_container(root):
            logger.debug("Base scenario parse skipped: session XML detected")
            return None
    except Exception as exc:
        logger.debug("Base scenario parse failed for %s: %s", xml_path, exc)
        return None

    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        return None

    base_el = scenario.find(".//BaseScenario")
    if base_el is None:
        return None
    raw_path = (base_el.get("filepath") or "").strip()
    if not raw_path:
        return None
    expanded = os.path.expanduser(raw_path)
    if not os.path.isabs(expanded):
        expanded = os.path.abspath(os.path.join(os.path.dirname(xml_path), expanded))
    return {
        "filepath_raw": raw_path,
        "filepath": expanded,
        "exists": os.path.exists(expanded),
    }
