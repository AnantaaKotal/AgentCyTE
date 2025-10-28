from core_topo_gen.builders import topology as topo_mod
from tests.test_router_mesh import FakeSession, DummyClient, _patch_safe_create_session


def test_preview_deduplicates_host_switch_links(monkeypatch):
    session = FakeSession()
    _patch_safe_create_session(monkeypatch, session)

    preview_plan = {
        'routers': [{'node_id': 1, 'name': 'r1', 'ip4': '10.0.0.1/24'}],
        'hosts': [
            {'node_id': 2, 'name': 'h1', 'role': 'Workstation', 'ip4': '10.0.1.2/24'},
            {'node_id': 3, 'name': 'h2', 'role': 'Workstation', 'ip4': '10.0.1.3/24'},
        ],
        'host_router_map': {'2': 1, '3': 1},
        'switches_detail': [
            {
                'switch_id': 10,
                'router_id': 1,
                'hosts': [2, 3],
                'rsw_subnet': '10.10.0.0/30',
                'lan_subnet': '10.10.0.64/26',
                'router_ip': '10.10.0.1/30',
                'switch_ip': '10.10.0.2/30',
                'host_if_ips': {
                    2: '10.10.0.66/26',
                    3: '10.10.0.67/26',
                },
            },
            {
                'switch_id': 11,
                'router_id': 1,
                'hosts': [2],
                'rsw_subnet': '10.10.1.0/30',
                'lan_subnet': '10.10.1.64/26',
                'router_ip': '10.10.1.1/30',
                'switch_ip': '10.10.1.2/30',
                'host_if_ips': {
                    2: '10.10.1.66/26',
                },
            },
        ],
        'r2r_edges_preview': [],
    }

    result = topo_mod._try_build_segmented_topology_from_preview(
        DummyClient(),
        services=None,
        routing_items=[],
        ip4_prefix='10.0.0.0/24',
        ip_mode='private',
        ip_region='all',
        layout_density='standard',
        preview_plan=preview_plan,
    )

    assert result is not None

    # Links are stored as sorted tuples in FakeSession
    link_pairs = {tuple(sorted(pair)) for pair in session.links}

    # Host 2 should only link to switch 10, not switch 11
    assert (2, 10) in link_pairs
    assert (2, 11) not in link_pairs

    # Host 3 should remain linked to switch 10 as expected
    assert (3, 10) in link_pairs
