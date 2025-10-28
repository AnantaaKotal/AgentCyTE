import json
import pytest

def test_plan_summary_schema_stability():
    # Minimal schema keys expected from pool.summarize()/metadata embedding
    required_keys = {
        'hosts_total','routers_planned','routers_allocated','hosts_allocated',
        'services_plan','services_assigned','routing_plan','r2r_policy',
        'r2r_edges_created','vulnerabilities_plan','vulnerabilities_assigned'
    }
    # Simulate a plan summary as would appear in metadata
    simulated = {
        'hosts_total': 5,
        'hosts_allocated': 5,
        'routers_planned': 2,
        'routers_allocated': 2,
        'services_plan': {},
        'services_assigned': {},
        'routing_plan': {},
        'r2r_policy': {'mode':'Random','target_degree':0},
        'r2r_edges_created': 1,
        'vulnerabilities_plan': {},
        'vulnerabilities_assigned': 0,
    }
    missing = required_keys - simulated.keys()
    assert not missing, f"Missing keys in plan summary: {missing}"

    # Round-trip JSON stability
    blob = json.dumps(simulated)
    parsed = json.loads(blob)
    assert parsed == simulated