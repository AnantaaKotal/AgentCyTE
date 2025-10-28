import random, types
from core_topo_gen.builders import topology as topo_mod
from core_topo_gen.types import RoutingInfo

# Reuse lightweight fake session approach (subset) similar to other tests
class FakeNode:
    def __init__(self, node_id: int, name: str = ""):
        self.id = node_id
        self.name = name or f"n{node_id}"
        self.position = types.SimpleNamespace(x=0, y=0)
        self.services = []
        # model is set by builder; default empty
        self.model = ""

class FakeServices:
    def __init__(self):
        self._map = {}
    def add(self, node_id_or_obj, service_name):
        nid = getattr(node_id_or_obj, 'id', node_id_or_obj)
        self._map.setdefault(nid, set()).add(service_name)

class FakeSession:
    def __init__(self):
        self.nodes = {}
        self.links = []
        self.services = FakeServices()
    def add_node(self, node_id, _type=None, position=None, name=None):
        n = FakeNode(node_id, name or f"n{node_id}")
        self.nodes[node_id] = n
        return n
    def add_link(self, node1=None, node2=None, iface1=None, iface2=None):
        if not node1 or not node2:
            return
        a = getattr(node1, 'id', node1); b = getattr(node2, 'id', node2)
        if a == b:
            return
        key = tuple(sorted((a,b)))
        if key not in self.links:
            self.links.append(key)
    def add_service(self, node_id=None, service_name=None):
        if node_id is not None:
            self.services.add(node_id, service_name)
    def delete_link(self, node1_id=None, node2_id=None, iface1_id=None, iface2_id=None):
        key = tuple(sorted((node1_id, node2_id)))
        self.links = [lk for lk in self.links if lk != key]
    def delete_node(self, node_id):  # builder may call this
        self.nodes.pop(node_id, None)
        self.links = [lk for lk in self.links if node_id not in lk]

class DummyClient: pass


def _patch(monkeypatch, sess):
    monkeypatch.setattr(topo_mod, 'safe_create_session', lambda core: sess)


def test_no_empty_r2s_switches(monkeypatch):
    # Use Exact R2S with target large enough to trigger creation attempts
    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2s_mode='Exact', r2s_edges=3)]
    role_counts = {'workstation': 18}  # plenty of hosts to distribute
    sess = FakeSession(); _patch(monkeypatch, sess)
    random.seed(2)
    _res = topo_mod.build_segmented_topology(DummyClient(), role_counts=role_counts, routing_density=0.5, routing_items=ritems, base_host_pool=sum(role_counts.values()), services=None)
    # Identify switches: model set to 'switch'
    switches = [nid for nid, node in sess.nodes.items() if getattr(node, 'model', '').lower() == 'switch']
    # A switch is empty if all its incident links connect only to routers/switches and no host models
    def is_router(nid):
        n = sess.nodes.get(nid); return 'router' in (getattr(n, 'model', '') or getattr(n,'name','')).lower()
    def is_host(nid):
        n = sess.nodes.get(nid); return getattr(n, 'model', '').lower() in ('pc','docker','host','default')
    empty_switches = []
    for sw in switches:
        incident = [lk for lk in sess.links if sw in lk]
        if not incident:
            empty_switches.append(sw); continue
        has_host = any(is_host(a if b==sw else b) for a,b in incident)
        only_r_or_sw = all((is_router(a if b==sw else b) or (getattr(sess.nodes.get(a if b==sw else b), 'model','').lower()=='switch')) for a,b in incident)
        if (not has_host) and only_r_or_sw:
            empty_switches.append(sw)
    assert not empty_switches, f"Orphan R2S switches still present: {empty_switches}"


def test_nonuniform_respects_host_bounds(monkeypatch):
    ritems = [RoutingInfo(protocol='OSPFv2', factor=0.0, abs_count=2, r2s_mode='NonUniform', r2s_edges=4, r2s_hosts_min=3, r2s_hosts_max=5)]
    role_counts = {'workstation': 24}
    sess = FakeSession(); _patch(monkeypatch, sess)
    random.seed(12345)
    topo_mod.build_segmented_topology(DummyClient(), role_counts=role_counts, routing_density=0.6, routing_items=ritems, base_host_pool=sum(role_counts.values()), services=None)

    host_models = {'pc', 'docker', 'host', 'default'}
    switch_host_counts = {}
    for nid, node in sess.nodes.items():
        name = getattr(node, 'name', '') or ''
        if not name.startswith('rsw-'):
            continue
        neighbors = [lk[0] if lk[1] == nid else lk[1] for lk in sess.links if nid in lk]
        hosts_attached = [sess.nodes.get(nb) for nb in neighbors if getattr(sess.nodes.get(nb), 'model', '').lower() in host_models]
        if hosts_attached:
            switch_host_counts[nid] = len(hosts_attached)

    assert switch_host_counts, "Expected at least one non-uniform R2S switch to be created"
    for count in switch_host_counts.values():
        assert 3 <= count <= 5, f"Switch host count {count} outside bounds"

    topo_stats = getattr(sess, 'topo_stats', {}) or {}
    policy = topo_stats.get('r2s_policy', {}) if isinstance(topo_stats, dict) else {}
    bounds = policy.get('host_group_bounds', {}) if isinstance(policy, dict) else {}
    if bounds:
        assert bounds.get('requested_min') == 3
        assert bounds.get('requested_max') == 5
        applied_min = bounds.get('applied_min')
        applied_max = bounds.get('applied_max')
        if applied_min is not None:
            assert applied_min >= 3
        if applied_max is not None:
            assert applied_max <= 5
