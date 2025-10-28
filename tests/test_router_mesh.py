import os
import random
import types

import pytest

from core_topo_gen.builders import topology as topo_mod
from core_topo_gen.types import RoutingInfo, ServiceInfo


class FakeNode:
    def __init__(self, node_id: int, name: str = ""):
        self.id = node_id
        self.name = name or f"n{node_id}"
        self.position = types.SimpleNamespace(x=0, y=0)
        # services can be tracked if needed
        self.services = []


class FakeServices:
    def __init__(self):
        self._map = {}

    def add(self, node_id_or_obj, service_name):
        if hasattr(node_id_or_obj, "id"):
            nid = node_id_or_obj.id
        else:
            nid = node_id_or_obj
        self._map.setdefault(nid, set()).add(service_name)


class FakeSession:
    def __init__(self):
        self.nodes = {}
        self.links = []  # list of (a,b)
        self.services = FakeServices()

    def add_node(self, node_id, _type=None, position=None, name=None):  # noqa: D401 - minimal
        n = FakeNode(node_id, name=name or f"n{node_id}")
        self.nodes[node_id] = n
        return n

    def get_node(self, node_id):
        return self.nodes[node_id]

    def add_link(self, node1=None, node2=None, iface1=None, iface2=None):
        if node1 is None or node2 is None:
            return
        a = getattr(node1, "id", node1)
        b = getattr(node2, "id", node2)
        if a == b:
            return
        key = tuple(sorted((a, b)))
        if key not in self.links:
            self.links.append(key)

    def add_service(self, node_id=None, service_name=None):  # mimic core API
        if node_id is None:
            return
        self.services.add(node_id, service_name)


class DummyClient:  # passed into builder; not used because we patch safe_create_session
    pass


def _patch_safe_create_session(monkeypatch, session):
    monkeypatch.setattr(topo_mod, "safe_create_session", lambda core: session)


def _build(role_counts, routing_density, routing_items, mesh_style, monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)
    # Ensure deterministic random for test reproducibility
    random.seed(0)
    # Call builder
    sess, routers, hosts, svc_assign, router_protocols, docker_by_name = topo_mod.build_segmented_topology(
        DummyClient(),
        role_counts=role_counts,
        routing_density=routing_density,
        routing_items=routing_items,
        base_host_pool=sum(role_counts.values()),
        services=None,
        router_mesh_style=mesh_style,
    )
    return session, routers, router_protocols


def _count_router_links(session, router_ids):
    rid_set = set(router_ids)
    return sum(1 for a, b in session.links if a in rid_set and b in rid_set)


@pytest.mark.parametrize("style,expected", [
    ("full", 6),   # 4 routers => 4*3/2 = 6
    ("ring", 4),   # cycle size n
    ("tree", 3),   # chain n-1
])
def test_router_mesh_styles(style, expected, monkeypatch):
    # Four routers all with same protocol via abs_count
    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=4)]
    session, routers, proto_map = _build({"workstation": 4}, routing_density=0.0 + 0.0001, routing_items=routing_items, mesh_style=style, monkeypatch=monkeypatch)
    # routing_density tiny positive to avoid early return path
    router_ids = [r.node_id for r in routers]
    assert len(router_ids) == 4
    link_count = _count_router_links(session, router_ids)
    assert link_count == expected, f"mesh style {style} expected {expected} links among routers, got {link_count}"


def test_random_protocol_expansion(monkeypatch):
    # Two random routing entries, density sets number of routers
    routing_items = [RoutingInfo(protocol="Random", factor=1.0), RoutingInfo(protocol="Random", factor=1.0)]
    session, routers, proto_map = _build({"workstation": 4}, routing_density=4, routing_items=routing_items, mesh_style="full", monkeypatch=monkeypatch)
    # Protocol map should have concrete protocols, none == 'Random'
    for rid, protos in proto_map.items():
        for p in protos:
            assert p.lower() != "random", "Random placeholder should be expanded"


def test_router_count_additive_density_and_counts(monkeypatch):
    # New semantics: density contributes only if at least one weight-based (non-abs_count) routing item exists.
    # Here all items are absolute counts, so density=5 is ignored. Only 3 routers created.
    routing_items = [RoutingInfo(protocol="OSPFv2", factor=0.0, abs_count=3)]
    session, routers, proto_map = _build({"workstation": 10}, routing_density=5, routing_items=routing_items, mesh_style="full", monkeypatch=monkeypatch)
    assert len(routers) == 3, f"Expected 3 routers (density ignored without weight-based items), got {len(routers)}"


def test_report_vulnerability_summary(monkeypatch, tmp_path):
    # Directly call write_report to ensure summary line present
    from core_topo_gen.utils.report import write_report
    out = tmp_path / "rep.md"
    vulnerabilities_cfg = {
        "density": 0.0,
        "items": [
            {"selected": "Specific", "v_metric": "Count", "v_count": 2, "v_name": "A"},
            {"selected": "Specific", "v_metric": "Count", "v_count": 1, "v_name": "B"},
        ],
    }
    report_path, summary_path = write_report(str(out), "test-scenario", routers=[], router_protocols={}, switches=[], hosts=[], vulnerabilities_cfg=vulnerabilities_cfg)
    txt = out.read_text(encoding="utf-8")
    assert "Vulnerabilities assigned:" in txt
    # 2 + 1 = 3
    assert "Vulnerabilities assigned: 3" in txt
    assert os.path.exists(report_path)
    assert summary_path is not None and os.path.exists(summary_path)
