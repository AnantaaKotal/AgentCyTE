import json
from pathlib import Path

from core_topo_gen.types import NodeInfo, SegmentationInfo
from core_topo_gen.utils.segmentation import plan_and_apply_segmentation


class _DummyServices:
    def __init__(self):
        self._data = {}

    def _key(self, node):
        return getattr(node, "id", node)

    def get(self, node):
        return self._data.get(self._key(node), [])

    def set(self, node, services):
        self._data[self._key(node)] = list(services)


class _DummyNode:
    def __init__(self, node_id: int, name: str):
        self.id = node_id
        self.name = name
        self.services = []
        self.type = "DOCKER"


class _DummySession:
    def __init__(self, nodes):
        self.nodes = {n.id: n for n in nodes}
        self.services = _DummyServices()

    def get_node(self, node_id):
        return self.nodes.get(node_id)


def test_segmentation_allows_docker_ports_when_option_enabled(tmp_path):
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        """
version: '3.9'
services:
  web:
    image: nginx:latest
    ports:
      - "80"
      - "443/tcp"
      - "53/udp"
      - target: 8080
        protocol: tcp
""".strip()
        + "\n",
        encoding="utf-8",
    )

    node = _DummyNode(1, "docker-host-1")
    session = _DummySession([node])

    routers = []
    hosts = [NodeInfo(node_id=1, ip4="10.0.0.10/24", role="Workstation")]
    items = [SegmentationInfo(name="Firewall", factor=1.0, abs_count=1)]

    docker_record = {
        "Name": "Test Docker",
        "Type": "docker-compose",
        "Path": str(compose_path),
    }
    docker_nodes = {node.name: docker_record}

    seg_dir = tmp_path / "seg"
    summary = plan_and_apply_segmentation(
        session=session,
        routers=routers,
        hosts=hosts,
        density=0.0,
        items=items,
        out_dir=str(seg_dir),
        include_hosts=True,
        allow_docker_ports=True,
        docker_nodes=docker_nodes,
    )

    rules = summary.get("rules") or []
    allowed_entries = [r for r in rules if r.get("node_id") == node.id]
    assert allowed_entries, "Expected segmentation rules for docker node"

    docker_metadata = [
        r["rule"].get("docker_ports_allowed")
        for r in allowed_entries
        if isinstance(r.get("rule"), dict)
    ]
    flat_meta = [entry for sub in docker_metadata if sub for entry in sub]
    assert flat_meta, "docker_ports_allowed metadata should be populated"

    expected = {("tcp", 80), ("tcp", 443), ("udp", 53), ("tcp", 8080)}
    observed = {
        (str(entry.get("protocol")).lower(), int(entry.get("port")))
        for entry in flat_meta
    }
    assert expected.issubset(observed)

    script_paths = [Path(r.get("script")) for r in allowed_entries if r.get("script")]
    assert script_paths, "Segmentation script path missing"
    script_text = script_paths[0].read_text("utf-8")
    for proto, port in expected:
        line = f"iptables -I INPUT 1 -p {proto} --dport {port} -j ACCEPT"
        assert line in script_text

    summary_path = Path(seg_dir) / "segmentation_summary.json"
    assert summary_path.exists()
    summary_json = json.loads(summary_path.read_text("utf-8"))
    docker_entries = [
        entry
        for entry in summary_json.get("rules", [])
        if (entry.get("node_id") == node.id and entry.get("rule", {}).get("docker_ports_allowed"))
    ]
    assert docker_entries, "Summary JSON should record docker_ports_allowed"