from core_topo_gen.builders import topology as topo_mod
from core_topo_gen.planning.full_preview import build_full_preview
from core_topo_gen.types import RoutingInfo
from tests.test_router_mesh import FakeSession, DummyClient, _patch_safe_create_session


def test_builder_matches_preview_switch_assignments(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    role_counts = {"Workstation": 6}
    routing_items = [RoutingInfo(protocol="OSPFv2", factor=1.0, abs_count=2, r2s_mode="Exact", r2s_edges=1)]

    preview = build_full_preview(
        role_counts=role_counts,
        routers_planned=2,
        services_plan={},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={"mode": "Exact", "target_per_router": 1},
        routing_items=routing_items,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=None,
        traffic_plan=[],
        seed=1234,
        ip4_prefix="10.0.0.0/16",
        ip_mode="private",
        ip_region="all",
    )

    sess, routers, hosts, *_ = topo_mod.build_segmented_topology(
        DummyClient(),
        role_counts=role_counts,
        routing_density=0.0,
        routing_items=routing_items,
        base_host_pool=sum(role_counts.values()),
        services=None,
        preview_plan=preview,
    )

    assert sess is session
    preview_detail = preview.get("switches_detail") or []
    assert preview_detail, "Expected preview to include switch details"

    router_ids = {r.node_id for r in routers}
    host_ids = {h.node_id for h in hosts}

    preview_switch_ids = {int(detail.get("switch_id")) for detail in preview_detail}
    session_switch_ids = {nid for nid in session.nodes if nid not in router_ids and nid not in host_ids}

    assert session_switch_ids == preview_switch_ids

    link_map = {sid: set() for sid in session_switch_ids}
    for a, b in session.links:
        if a in link_map and b in host_ids:
            link_map[a].add(b)
        elif b in link_map and a in host_ids:
            link_map[b].add(a)

    for detail in preview_detail:
        sid = int(detail.get("switch_id"))
        expected_hosts = {int(h) for h in detail.get("hosts", [])}
        assert link_map.get(sid) == expected_hosts

def test_preview_switch_without_hosts_preserved(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    preview = {
        'routers': [{'node_id': 1, 'name': 'r1', 'ip4': '10.0.0.1/24'}],
        'hosts': [{'node_id': 2, 'name': 'h1', 'role': 'Workstation', 'ip4': '10.0.1.2/24'}],
        'host_router_map': {'2': 1},
        'switches': [{'node_id': 10, 'name': 'rsw-1-1'}],
        'switches_detail': [
            {
                'switch_id': 10,
                'router_id': 1,
                'hosts': [],
                'rsw_subnet': '10.10.0.0/30',
                'lan_subnet': '10.10.0.64/26',
                'router_ip': '10.10.0.1/30',
                'switch_ip': '10.10.0.2/30',
                'host_if_ips': {},
            }
        ],
    }

    result = topo_mod._try_build_segmented_topology_from_preview(
        DummyClient(),
        services=None,
        routing_items=[],
        ip4_prefix='10.0.0.0/24',
        ip_mode='private',
        ip_region='all',
        layout_density='normal',
        preview_plan=preview,
    )

    assert result is not None
    sess, *_ = result
    assert 10 in sess.nodes, "Switch declared in preview should be retained even without hosts"