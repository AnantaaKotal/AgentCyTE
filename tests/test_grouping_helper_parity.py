from core_topo_gen.planning.router_host_plan import plan_r2s_grouping

class DummyHost:
    def __init__(self, node_id):
        self.node_id = node_id


def test_plan_r2s_grouping_exact_single_group_sizes():
    routers = 3
    # 9 hosts mapped round-robin -> each router gets 3 hosts
    host_router_map = {i+1: (i % routers)+1 for i in range(9)}
    hosts = [DummyHost(i+1) for i in range(9)]
    out = plan_r2s_grouping(routers, host_router_map, hosts, routing_items=None, r2s_policy={'mode':'Exact','target_per_router':1}, seed=4321)
    gp = out['grouping_preview']
    assert len(gp) == routers
    assert all(rec['group_sizes'] == [3] for rec in gp if rec['group_sizes'])
