from __future__ import annotations
from dataclasses import dataclass
from typing import List

@dataclass
class ServiceInfo:
    name: str
    factor: float
    density: float
    # When > 0, indicates an absolute number of hosts to assign this service to.
    # Takes precedence over fractional density.
    abs_count: int = 0

@dataclass
class RoutingInfo:
    protocol: str
    factor: float
    abs_count: int = 0  # Absolute routers for this protocol (additive)
    # Router-to-Router policy
    r2r_mode: str = ""   # "", Random, Min, Uniform, Exact, NonUniform
    r2r_edges: int = 0       # Used only when r2r_mode == Exact (>0)
    # Router-to-Switch policy
    r2s_mode: str = ""   # Random, Min, Uniform, Exact, NonUniform
    r2s_edges: int = 0    # Used only when r2s_mode == Exact (>0)
    # Per-routing-item host grouping constraints (hosts per switch) propagated from XML/UI.
    # When 0 (or <1) they are considered unspecified and default scenario-level bounds apply.
    r2s_hosts_min: int = 0
    r2s_hosts_max: int = 0

@dataclass
class NodeInfo:
    node_id: int
    ip4: str
    role: str

@dataclass
class TrafficInfo:
    kind: str
    factor: float
    pattern: str = ""
    rate_kbps: float = 0.0
    period_s: float = 10.0
    jitter_pct: float = 0.0
    content_type: str = ""
    # When > 0, indicates an absolute number of sender/receiver pairs to create for this item.
    abs_count: int = 0

@dataclass
class SegmentationInfo:
    name: str
    factor: float
    # When > 0, indicates an absolute number of segmentation slots to plan for this service.
    abs_count: int = 0
