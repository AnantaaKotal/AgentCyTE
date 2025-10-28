from __future__ import annotations
import logging
import os
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .common import find_scenario, has_unexpected_container

logger = logging.getLogger(__name__)


_ATTACHMENT_ALLOWED = {
    "existing_router",
    "existing_switch",
    "new_router",
    "new_switch",
}
_DEFAULT_ATTACHMENT = "existing_router"


def _normalize_attachment(value: Any) -> str:
    if value is None:
        return _DEFAULT_ATTACHMENT
    try:
        normalized = str(value).strip().lower().replace('-', '_').replace(' ', '_')
    except Exception:
        return _DEFAULT_ATTACHMENT
    if normalized in _ATTACHMENT_ALLOWED:
        return normalized
    return _DEFAULT_ATTACHMENT


def _normalize_interface_element(element: ET.Element) -> Optional[Dict[str, Any]]:
    name = (element.get("name") or element.get("interface") or "").strip()
    if not name:
        return None
    entry: Dict[str, Any] = {"name": name}
    alias = (element.get("alias") or element.get("display") or element.get("description") or "").strip()
    if alias:
        entry["alias"] = alias
    mac = (element.get("mac") or element.get("hwaddr") or "").strip()
    if mac:
        entry["mac"] = mac
    entry["attachment"] = _normalize_attachment(element.get("attachment") or element.get("attach"))
    for attr in ("ipv4", "ipv4_addresses"):
        raw = element.get(attr)
        if raw:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if parts:
                entry["ipv4"] = parts
            break
    for attr in ("ipv6", "ipv6_addresses"):
        raw = element.get(attr)
        if raw:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if parts:
                entry["ipv6"] = parts
            break
    return entry


def parse_hitl_info(xml_path: str, scenario_name: Optional[str]) -> Dict[str, Any]:
    """Parse Hardware-In-The-Loop configuration from the scenario XML."""
    result: Dict[str, Any] = {"enabled": False, "interfaces": []}
    if not xml_path or not os.path.exists(xml_path):
        return result
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as exc:
        logger.debug("Failed parsing XML for HITL info: %s", exc)
        return result
    if has_unexpected_container(root):
        logger.warning("HITL parse skipped: XML appears to be a CORE session export with <container> elements")
        return result
    scenario = find_scenario(root, scenario_name)
    if scenario is None:
        logger.debug("HITL parse: scenario %s not found", scenario_name)
        return result
    se = scenario.find("ScenarioEditor")
    if se is None:
        se = scenario.find(".//ScenarioEditor")
    if se is None:
        logger.debug("HITL parse: ScenarioEditor missing for scenario %s", scenario_name)
        return result
    hitl_element = se.find("HardwareInLoop")
    if hitl_element is None:
        return result
    enabled_raw = (hitl_element.get("enabled") or "").strip().lower()
    result["enabled"] = enabled_raw in {"1", "true", "yes", "on"}
    interfaces: List[Dict[str, Any]] = []
    for iface_el in hitl_element.findall("Interface"):
        normalized = _normalize_interface_element(iface_el)
        if normalized:
            interfaces.append(normalized)
    result["interfaces"] = interfaces
    return result
