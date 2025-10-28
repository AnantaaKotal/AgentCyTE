import os
from types import SimpleNamespace

from core_topo_gen.builders.topology import _apply_docker_compose_meta, NodeType
from core_topo_gen.utils.vuln_process import prepare_compose_for_assignments


class DummySession:
    def __init__(self):
        self.calls = []

    def edit_node(self, node_id, options=None, **kwargs):
        self.calls.append((node_id, options, kwargs))


def test_prepare_compose_for_assignments_records_compose_path(tmp_path):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
    ports:
      - "8080:80"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    name_to_vuln = {"host-1": record}

    created = prepare_compose_for_assignments(name_to_vuln, out_base=str(tmp_path))

    expected_path = os.path.join(str(tmp_path), "docker-compose-host-1.yml")
    assert expected_path in created
    assert record.get("compose_path") == expected_path


def test_apply_docker_compose_meta_pushes_options(tmp_path):
    record = {"Name": "Example Vuln", "compose_path": str(tmp_path / "docker-compose-host-1.yml")}
    node = SimpleNamespace(id=5, name="host-1", options=None, type=NodeType.DOCKER, image="pre-image")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose") == record["compose_path"]
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose") == record["compose_path"]
    assert getattr(node, "options").compose == record["compose_path"]
    assert getattr(node, "type") == NodeType.DOCKER
    assert getattr(node, "image") == ""
    assert getattr(options, "type") == ""
    assert getattr(options, "image") == ""
