from __future__ import annotations
import logging
import os
import xml.etree.ElementTree as ET
from typing import List, Optional
from ..types import ServiceInfo
from .common import find_scenario, has_unexpected_container

logger = logging.getLogger(__name__)


def parse_services(scenario: ET.Element) -> List[ServiceInfo]:  # unchanged signature (expects scenario element)
    services: List[ServiceInfo] = []
    section = scenario.find(".//section[@name='Services']")
    if section is not None:
        den_section_raw = (section.get("density") or "").strip()
        if not den_section_raw:
            logger.warning("'Services' section missing 'density'; no services will be assigned from this section")
        try:
            section_density = float(den_section_raw) if den_section_raw else 0.0
            if section_density < 0:
                section_density = 0.0
        except Exception:
            logger.warning("'Services' section has invalid 'density' value '%s'", den_section_raw)
            section_density = 0.0
        for it in section.findall("./item"):
            name = (it.get("selected") or "").strip()
            if name.lower() == "auto":
                logger.warning("Skipping legacy Services item 'auto' (not supported)")
                continue
            if not name:
                continue
            try:
                factor = float((it.get("factor") or "0").strip())
            except Exception:
                factor = 0.0
            vm = (it.get("v_metric") or "").strip()
            vc_raw = (it.get("v_count") or "").strip()
            count_override: Optional[int] = None
            if vm == "Count" and vc_raw:
                try:
                    vc = int(vc_raw)
                    if vc >= 0:
                        count_override = vc
                except Exception:
                    count_override = None
            if it.get("density"):
                logger.warning("Ignoring item-level 'density' for service '%s'; using section-level density or count override", name)
            item_density = float(count_override) if count_override is not None else section_density
            if factor > 0 and (item_density > 0 or (count_override is not None and count_override == 0)):
                services.append(ServiceInfo(name=name, factor=factor, density=item_density, abs_count=(count_override or 0)))
    return services
