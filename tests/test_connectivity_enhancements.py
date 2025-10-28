import random, types, os, tempfile
import math
from core_topo_gen.builders import topology as topo_mod
from core_topo_gen.types import RoutingInfo

# Reuse lightweight fake session approach (copy minimal from test_router_mesh)
class FakeNode:
    def __init__(self, node_id: int, name: str = ""):
        self.id = node_id
        self.name = name or f"n{node_id}"
        self.position = types.SimpleNamespace(x=0, y=0)
        self.services = []

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
        if not node1 or not node2: return
        a = getattr(node1, 'id', node1); b = getattr(node2, 'id', node2)
        if a == b: return
        key = tuple(sorted((a,b)))
        if key not in self.links:
            self.links.append(key)
    def add_service(self, node_id=None, service_name=None):
        if node_id is not None:
            self.services.add(node_id, service_name)
    # Optional delete_link for rehome path
    def delete_link(self, node1_id=None, node2_id=None, iface1_id=None, iface2_id=None):  # noqa: D401
        key = tuple(sorted((node1_id, node2_id)))
        self.links = [lk for lk in self.links if lk != key]

class DummyClient: pass

def _patch_session(monkeypatch, sess):
    monkeypatch.setattr(topo_mod, 'safe_create_session', lambda core: sess)

def _build(role_counts, routing_items, monkeypatch):
    sess = FakeSession(); _patch_session(monkeypatch, sess)
    random.seed(1)
    return topo_mod.build_segmented_topology(DummyClient(), role_counts=role_counts, routing_density=0.6, routing_items=routing_items, base_host_pool=sum(role_counts.values()), services=None)

def _degrees(sess, routers):
    rids = {r.node_id for r in routers}
    deg = {rid:0 for rid in rids}
    for a,b in sess.links:
        if a in rids and b in rids:
            deg[a]+=1; deg[b]+=1
    return deg

def test_uniform_balancing(monkeypatch):
    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2r_mode='Uniform')]
    sess, routers, hosts, *_ = _build({'workstation':12}, ritems, monkeypatch)
    assert len(routers) > 3
    topo_stats = getattr(sess, 'topo_stats', {})
    rep = topo_stats.get('router_edges_policy') or {}
    assert rep.get('mode') == 'Uniform'
    degs = _degrees(sess, routers)
    vals = list(degs.values())
    assert max(vals) - min(vals) <= 2, f"Uniform degrees not balanced: {vals}"  # heuristic tolerance
    # target degree recorded
    assert rep.get('target_degree') >= 2
    # Metrics present
    for k in ['degree_min','degree_max','degree_avg','degree_std','degree_gini']:
        assert k in rep

def test_nonuniform_gini(monkeypatch):
    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2r_mode='NonUniform')]
    sess, routers, hosts, *_ = _build({'workstation':10}, ritems, monkeypatch)
    degs = _degrees(sess, routers)
    vals = list(degs.values())
    assert len(vals) >= 2
    spread = max(vals) - min(vals)
    if len(vals) >= 5:
        assert spread >= 2, f"Expected substantial degree spread for NonUniform mode, got {vals}"
    elif len(vals) >= 3:
        assert spread >= 1, f"Expected some degree spread for NonUniform mode, got {vals}"
    # Compute gini replicate to ensure variance is meaningful.
    v = sorted(vals)
    n = len(v)
    sm = sum(v)
    if sm > 0 and n > 1:
        cum = sum((i + 1) * x for i, x in enumerate(v))
        gini = (2 * cum) / (n * sm) - (n + 1) / n
        if n >= 4:
            assert gini >= 0.18, f"NonUniform gini too low: {gini} from degrees {vals}"
    topo_stats = getattr(sess, 'topo_stats', {})
    rep = topo_stats.get('router_edges_policy') or {}
    assert rep.get('mode') in ('NonUniform','Random','Min','Exact','Uniform')

def test_r2s_rehome(monkeypatch):
    # Use Exact R2S with target 2 ensuring rehome attempt. Enough hosts per router.
    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2s_mode='Exact', r2s_edges=2)]
    sess, routers, hosts, *_ = _build({'workstation':16}, ritems, monkeypatch)
    topo_stats = getattr(sess, 'topo_stats', {})
    r2s = topo_stats.get('r2s_policy') or {}
    assert r2s.get('mode') == 'Exact'
    assert 'target_per_router' in r2s
    # Some switches expected (count histogram not exposed directly, but counts map present)
    counts = r2s.get('counts') or {}
    assert isinstance(counts, dict)
    # Rehomed host list present
    reh = r2s.get('rehomed_hosts') or []
    assert isinstance(reh, list)
    # Ensure rehomed hosts no longer have duplicate direct links and interface indices would have advanced (>0)
    # (We cannot access actual interface objects in FakeSession; we assert structural result only.)
    # Ensure no direct duplicate link host-router for rehomed (best-effort): host-router link should exist only through switch now
    direct_pairs = set(sess.links)
    for h in reh:
        for r in routers:
            if (min(h, r.node_id), max(h, r.node_id)) in direct_pairs:
                # allow single residual if delete_link unsupported, but break if many
                # For strictness we assert absence
                assert False, 'Host still directly linked to router after rehome'

def test_report_metrics_present(monkeypatch, tmp_path):
    ritems = [RoutingInfo(protocol='OSPFv2', factor=1.0, r2r_mode='Uniform', r2s_mode='Min')]
    sess, routers, hosts, *_ = _build({'workstation':14}, ritems, monkeypatch)
    from core_topo_gen.utils.report import write_report
    out = tmp_path / 'rep.md'
    topo_stats = getattr(sess, 'topo_stats', {})
    report_path, summary_path = write_report(str(out), 'scen', routers=routers, router_protocols={}, hosts=hosts, metadata=topo_stats)
    txt = out.read_text()
    assert 'Degree stats:' in txt
    assert 'Router-to-Switch Connectivity' in txt
    assert os.path.exists(report_path)
    assert summary_path is not None and os.path.exists(summary_path)
