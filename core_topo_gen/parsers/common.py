from __future__ import annotations
import logging
import xml.etree.ElementTree as ET
from typing import Optional

logger = logging.getLogger(__name__)


def has_unexpected_container(root: ET.Element) -> bool:
    """Return True if XML appears to be a CORE session export (contains <container>)."""
    try:
        return root.find('.//container') is not None
    except Exception:
        return False


def find_scenario(root: ET.Element, scenario_name: Optional[str]) -> Optional[ET.Element]:
    scenarios = root.findall('.//Scenario')
    if not scenarios:
        return None
    if scenario_name:
        for s in scenarios:
            if s.get('name') == scenario_name:
                return s
    return scenarios[0]
