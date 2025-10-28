import math

from core_topo_gen.planning.full_preview import build_full_preview


def _build_sample_preview(seed: int = 321) -> dict:
    role_counts = {
        'Workstation': 6,
        'Server': 2,
    }
    return build_full_preview(
        role_counts=role_counts,
        routers_planned=2,
        services_plan={'DNS': 2},
        vulnerabilities_plan={},
        r2r_policy=None,
        r2s_policy={'mode': 'Exact', 'target_per_router': 1},
        routing_items=None,
        routing_plan={},
        segmentation_density=0.0,
        segmentation_items=[],
        traffic_plan=None,
        seed=seed,
        ip4_prefix='10.50.0.0/16',
    )


def test_layout_positions_within_bounds():
    preview = _build_sample_preview()
    layout = preview.get('layout_positions')
    assert layout and isinstance(layout, dict)

    for group in ('routers', 'switches', 'hosts'):
        coords = layout.get(group) or {}
        for node_id, pos in coords.items():
            assert isinstance(pos, dict), f"layout entry for {group} {node_id} malformed"
            x = pos.get('x')
            y = pos.get('y')
            assert isinstance(x, int) and isinstance(y, int)
            assert 0 <= x <= 2000, f"x out of bounds for {group} {node_id}: {x}"
            assert 0 <= y <= 2000, f"y out of bounds for {group} {node_id}: {y}"


def test_hosts_cluster_near_router():
    preview = _build_sample_preview(seed=777)
    layout = preview['layout_positions']
    routers_layout = layout.get('routers') or {}
    hosts_layout = layout.get('hosts') or {}
    host_router_map = preview.get('host_router_map') or {}

    # ensure every host with a router assignment is reasonably close (euclidean <= 500)
    for host_id_str, router_id in host_router_map.items():
        host_id = int(host_id_str)
        host_pos = hosts_layout.get(str(host_id)) or hosts_layout.get(host_id)
        router_pos = routers_layout.get(str(router_id)) or routers_layout.get(router_id)
        if not host_pos or not router_pos:
            continue
        dx = host_pos['x'] - router_pos['x']
        dy = host_pos['y'] - router_pos['y']
        dist = math.sqrt(dx * dx + dy * dy)
        assert dist <= 500, f"host {host_id} too far from router {router_id}: {dist}"
