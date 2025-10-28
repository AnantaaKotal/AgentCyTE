import tempfile
from core_topo_gen.utils.traffic import generate_traffic_scripts
from core_topo_gen.types import NodeInfo, TrafficInfo


def _hosts(n):
    return [NodeInfo(node_id=i + 1, ip4=f"10.0.0.{i+1}/24", role="Host") for i in range(n)]


def _count_pairs(result):
    senders = {nid for nid, files in result.items() for p in files if p.endswith('.py') and f"_{nid}_s" in p}
    receivers = {nid for nid, files in result.items() for p in files if p.endswith('.py') and f"_{nid}_r" in p}
    # Pairs approximate by min of senders and receivers sets
    return min(len(senders), len(receivers))


def test_one_traffic_pair_with_abs_count():
    hosts = _hosts(3)
    items = [TrafficInfo(kind="TCP", factor=0.0, abs_count=1)]
    with tempfile.TemporaryDirectory() as td:
        result = generate_traffic_scripts(hosts, density=0.0, items=items, out_dir=td)
    assert _count_pairs(result) == 1
