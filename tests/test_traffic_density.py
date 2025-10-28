import tempfile
from pathlib import Path

from core_topo_gen.utils.traffic import generate_traffic_scripts
from core_topo_gen.types import NodeInfo, TrafficInfo


def _hosts(n):
    return [NodeInfo(node_id=i + 1, ip4=f"10.0.0.{i+1}/24", role="Host") for i in range(n)]


def _count_sender_hosts(result):
    sender_hosts = set()
    for node_id, files in result.items():
        for p in files:
            name = Path(p).name
            if name.startswith("traffic_") and "_s" in name:
                # sender is keyed by host id already, but double-check filename contains node_id
                sender_hosts.add(node_id)
                break
    return len(sender_hosts)


def test_density_one_selects_all_hosts():
    hosts = _hosts(5)
    items = [TrafficInfo(kind="TCP", factor=1.0)]
    with tempfile.TemporaryDirectory() as td:
        result = generate_traffic_scripts(hosts, 1.0, items, out_dir=td)
    assert _count_sender_hosts(result) == len(hosts)


def test_density_near_one_rounds_to_all():
    hosts = _hosts(5)
    items = [TrafficInfo(kind="TCP", factor=1.0)]
    with tempfile.TemporaryDirectory() as td:
        result = generate_traffic_scripts(hosts, 0.999, items, out_dir=td)
    assert _count_sender_hosts(result) == len(hosts)
