from pathlib import Path
import sys

# Ensure the repository root is on the import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import parse_scenarios


def test_parse_sample_xml_summary_counts():
    """parse_scenarios.parse_file correctly summarizes sample.xml counts."""
    sample_path = Path(__file__).resolve().parent.parent / "sample.xml"
    result = parse_scenarios.parse_file(sample_path)
    expected_summary = {
        "node_count": 0,
        "link_count": 0,
        "service_count": 0,
        "traffic_count": 0,
        "segment_count": 0,
        "vuln_count": 0,
    }
    assert result["summary"] == expected_summary
