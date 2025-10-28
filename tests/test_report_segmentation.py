import json
import os
from pathlib import Path
from core_topo_gen.utils.report import write_report


def test_report_includes_segmentation(tmp_path):
    # Prepare fake segmentation summary
    seg_summary = {
        "rules": [
            {
                "node_id": 1,
                "service": "Firewall",
                "rule": {"type": "subnet_block", "src": "10.0.0.0/24", "dst": "10.0.1.0/24"},
                "script": "/tmp/segmentation/subnet_block_1_1.py",
            },
            {
                "node_id": 2,
                "service": "ACL",
                "rule": {"type": "protect_internal", "subnet": "10.0.2.0/24"},
                "script": "/tmp/segmentation/protect_internal_2_1.py",
            },
        ]
    }
    seg_path = tmp_path / "segmentation_summary.json"
    seg_path.write_text(json.dumps(seg_summary), encoding="utf-8")

    # Output path for report
    out_md = tmp_path / "report.md"

    # Minimal inputs
    scenario_name = "test-scenario"

    report_path, summary_path = write_report(
        str(out_md),
        scenario_name,
        routers=[],
        router_protocols={},
        switches=[],
        hosts=[],
        service_assignments={},
        traffic_summary_path=None,
        segmentation_summary_path=str(seg_path),
        metadata={"seed": 123},
        routing_cfg={"density": 0, "items": []},
        traffic_cfg={"density": 0, "items": []},
        services_cfg=[],
        segmentation_cfg={"density": 0.5, "items": [{"name": "Firewall", "factor": 1.0}]},
    )

    assert os.path.exists(report_path)
    assert summary_path is not None and os.path.exists(summary_path)
    content = out_md.read_text(encoding="utf-8")
    # Summary counts
    assert "Segmentation rules: 2" in content
    # Section and rows
    assert "## Segmentation Rules" in content
    assert "subnet_block_1_1.py" in content
    assert "protect_internal_2_1.py" in content
    # Details section
    assert "### Segmentation config" in content
    assert "Density: 0.5" in content

    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    assert summary.get("counts", {}).get("segmentation_rules") == 2
    assert summary.get("segmentation", {}).get("rules_total") == 2
