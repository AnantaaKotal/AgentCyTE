import json
import pytest
from pathlib import Path
from core_topo_gen.planning.pool import AllocationPool
from core_topo_gen.planning.constraints import enforce_no_drift


def test_enforce_no_drift_basic():
    planned = {
        'hosts_total': 10,
        'routers_planned': 2,
        'r2s_ratio_used': 1.0,
        'vulnerabilities_plan': {'v1': 3},
    }
    actual = {
        'hosts_allocated': 10,
        'routers_allocated': 2,
        'r2s_ratio_used': 1.0,
        'vulnerabilities_assigned': 3,
    }
    drift = enforce_no_drift(planned, actual)
    assert drift == []


def test_enforce_no_drift_detects_variance():
    planned = {
        'hosts_total': 8,
        'routers_planned': 3,
        'r2s_ratio_used': 2.0,
    }
    actual = {
        'hosts_allocated': 7,
        'routers_allocated': 2,
        'r2s_ratio_used': 2.0,
    }
    drift = enforce_no_drift(planned, actual)
    assert any('hosts' in d for d in drift)
    assert any('routers' in d for d in drift)


def test_allocation_pool_summarize_contains_new_fields():
    pool = AllocationPool(
        hosts_total=5,
        role_counts={'User': 5},
        routers_planned=1,
        services_plan={},
        routing_plan={},
    )
    pool.r2s_ratio_used = 1.5
    pool.switches_allocated = 2
    summary = pool.summarize()
    assert 'switches_allocated' in summary
    assert summary['r2s_ratio_used'] == 1.5
