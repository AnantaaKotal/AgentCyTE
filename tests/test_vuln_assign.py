import random

from core_topo_gen.utils.vuln_process import assign_compose_to_nodes


def test_count_assign_overrides_density_specific():
    # Deterministic randomness in function
    random.seed(0)
    node_names = [f"n{i}" for i in range(5)]
    density = 0.0  # implies 0 by density alone
    # Catalog contains one docker-compose entry identified by Name/Path
    catalog = [
        {
            "Name": "VulnA",
            "Path": "https://example.com/repo/tree/main/path",  # not fetched in this test
            "Type": "docker-compose",
            "Vector": "web",
        }
    ]
    # Items config requests a Specific item with Count=1
    items_cfg = [
        {
            "selected": "Specific",
            "v_metric": "Count",
            "v_count": 1,
            "v_name": "VulnA",
            "v_path": "https://example.com/repo/tree/main/path",
        }
    ]
    assignments = assign_compose_to_nodes(
        node_names, density, items_cfg, catalog, out_base="/tmp/vulns", require_pulled=False
    )
    assert 1 == len(assignments)
    # Ensure assignment maps to a valid node and the right catalog record
    ((node, rec),) = list(assignments.items())
    assert node in node_names
    assert rec["Name"] == "VulnA"


def test_count_assign_overrides_density_multiple():
    random.seed(0)
    node_names = [f"n{i}" for i in range(3)]
    density = 0.0
    catalog = [
        {"Name": "VulnA", "Path": "p1", "Type": "docker-compose", "Vector": "web"},
        {"Name": "VulnB", "Path": "p2", "Type": "docker-compose", "Vector": "db"},
    ]
    items_cfg = [
        {
            "selected": "Type/Vector",
            "v_metric": "Count",
            "v_type": "docker-compose",
            "v_vector": "web",
            "factor": 1.0,
            "v_count": 2,
        }
    ]
    assignments = assign_compose_to_nodes(
        node_names, density, items_cfg, catalog, out_base="/tmp/vulns", require_pulled=False
    )
    assert 2 == len(assignments)
    # All assigned records should be docker-compose type
    for rec in assignments.values():
        assert rec["Type"].lower() == "docker-compose"


def test_vulnerability_additive_density_and_counts():
    # 10 nodes, density 0.3 => target 3 plus count item 2 => expect 5 total assignments if enough eligible nodes
    import random
    random.seed(0)
    node_names = [f"n{i}" for i in range(10)]
    density = 0.3
    catalog = [
        {"Name": f"Vuln{i}", "Path": f"p{i}", "Type": "docker-compose", "Vector": "web"} for i in range(10)
    ]
    items_cfg = [
        {"selected": "Type/Vector", "v_metric": "Count", "v_type": "docker-compose", "v_vector": "web", "v_count": 2},
        {"selected": "Type/Vector", "factor": 1.0, "v_type": "docker-compose", "v_vector": "web"},
    ]
    assignments = assign_compose_to_nodes(node_names, density, items_cfg, catalog, out_base="/tmp/vulns", require_pulled=False)
    assert len(assignments) == 5, f"Expected 5 assignments (2 count + 3 density), got {len(assignments)}"
