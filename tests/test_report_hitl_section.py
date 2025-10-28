from pathlib import Path

from core_topo_gen.types import NodeInfo
from core_topo_gen.utils.report import write_report


def test_report_includes_hitl_attachment_section(tmp_path: Path) -> None:
    report_path = tmp_path / "report.md"
    routers = [NodeInfo(node_id=1, ip4="10.0.0.1", role="router")]
    metadata = {
        "hitl_attachment": {
            "enabled": True,
            "session_option_enabled": True,
            "interfaces": [
                {
                    "name": "en0",
                    "attachment": "existing_router",
                    "assignment": "peer",
                    "rj45_node_id": 200,
                    "peer_node_id": 1,
                    "linked": True,
                    "uplink_router_node_id": 1,
                },
                {
                    "name": "en1",
                    "attachment": "new_switch",
                    "assignment": "network",
                    "rj45_node_id": 201,
                    "peer_node_id": 42,
                    "linked": False,
                    "uplink_router_node_id": 5,
                    "uplink_linked": False,
                },
            ],
            "created_nodes": [200, 201],
            "created_network_nodes": [301],
        }
    }

    out_md, out_json = write_report(
        str(report_path),
        "Demo Scenario",
        routers=routers,
        hosts=[],
        switches=[],
        metadata=metadata,
    )

    assert Path(out_md).exists()
    text = Path(out_md).read_text(encoding="utf-8")
    assert "## Hardware-in-the-Loop Attachments" in text
    assert "| Interface | Preference | Assignment |" in text
    assert "en0" in text
    assert "linked" in text
    assert "uplink pending" in text

    assert Path(out_json).exists()
