"""Deprecated module.

The legacy monolithic parser module has been removed.

Import from the dedicated section modules instead:
  from core_topo_gen.parsers.node_info import parse_node_info
  from core_topo_gen.parsers.routing import parse_routing_info
  from core_topo_gen.parsers.services import parse_services
  from core_topo_gen.parsers.traffic import parse_traffic_info
  from core_topo_gen.parsers.segmentation import parse_segmentation_info
  from core_topo_gen.parsers.vulnerabilities import parse_vulnerabilities_info
  from core_topo_gen.parsers.planning_metadata import parse_planning_metadata

Rationale: Improves modularity, test focus, and future evolution of individual
section grammars without a catch‑all import side effect. This stub now raises
an ImportError so lingering imports fail fast.
"""

raise ImportError(
    "core_topo_gen.parsers.xml_parser has been removed; import the specific parser modules (see module docstring)"
)

