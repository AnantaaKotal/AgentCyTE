import math
import random
import pytest
from core_topo_gen.planning.pool import AllocationPool
from core_topo_gen.planning.constraints import validate_phase


def synthetic_degree_stats(degrees):
    vals = list(degrees.values())
    return min(vals), max(vals), sum(vals)/len(vals)


def test_validate_phase_r2r_requires_edges():
    state = {'routers_planned': 3, 'r2r_edges_created': 0}
    issues = validate_phase(state, 'r2r')
    assert issues and 'R2R' in issues[0]


def test_validate_phase_r2s_ratio_missing_counts():
    state = {'r2s_policy': {'mode': 'Exact', 'target_per_router': 2.0, 'counts': {}}}
    issues = validate_phase(state, 'r2s')
    assert issues and 'R2S' in issues[0]
