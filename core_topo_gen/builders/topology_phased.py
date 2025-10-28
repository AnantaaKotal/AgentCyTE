"""Removed phased builder (minimal stub).

Any import of this module should switch to:
    from core_topo_gen.builders.topology import build_segmented_topology
"""

__all__: list[str] = []

def __getattr__(name: str):  # pragma: no cover
    raise ImportError(
        "Phased builder removed. Use build_segmented_topology from core_topo_gen.builders.topology instead."
    )
