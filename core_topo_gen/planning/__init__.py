"""Planning subpackage initialization and public plan computation helpers.

Purpose: provide small, focused computation modules that derive counts and
allocation plans for each scenario section (hosts, routers, services, etc.).
This allows the CLI and web full preview to share consistent semantics while enabling fine-grained unit tests.
"""

from .router_plan import compute_router_plan  # noqa: F401
from .node_plan import compute_node_plan  # noqa: F401
from .service_plan import compute_service_plan  # noqa: F401
from .vulnerability_plan import compute_vulnerability_plan  # noqa: F401
from .traffic_plan import compute_traffic_plan  # noqa: F401
from .segmentation_plan import compute_segmentation_plan  # noqa: F401

__all__ = [
    "compute_router_plan",
    "compute_node_plan",
    "compute_service_plan",
    "compute_vulnerability_plan",
    "compute_traffic_plan",
    "compute_segmentation_plan",
]

# Best-effort eager import of full_preview to ensure availability for web preview endpoints; fall back silently.
try:  # pragma: no cover
    from . import full_preview  # noqa: F401
except Exception:  # pragma: no cover
    pass
