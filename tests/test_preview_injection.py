import json
import types
from pathlib import Path

# Minimal fakes / stubs for session and interfaces to exercise injection logic without CORE runtime.
class FakeInterface:
    def __init__(self, id, name, ip4, ip4_mask, mac):
        self.id=id; self.name=name; self.ip4=ip4; self.ip4_mask=ip4_mask; self.mac=mac

class FakeNode:
    def __init__(self, node_id, _type, position=None, name=None):
        self.id=node_id; self.type=_type; self.position=position; self.name=name or f"n{node_id}"

class FakeSession:
    def __init__(self):
        self.nodes = {}
        self.links = []
        self.topo_stats = {}
    def add_node(self, node_id, _type=None, position=None, name=None):
        n=FakeNode(node_id,_type,position,name); self.nodes[node_id]=n; return n
    def add_link(self, a, b, iface1=None, iface2=None):
        # Normalize ids
        if hasattr(a,'id'): a=a.id
        if hasattr(b,'id'): b=b.id
        self.links.append((a,b,iface1,iface2))
    # Compatibility attempts may call with keyword names
    def delete_link(self, node1_id, node2_id):
        self.links=[l for l in self.links if {l[0],l[1]}!={node1_id,node2_id}]

# Lightweight MAC/Subnet alloc fakes
class FakeMacAlloc:
    def next_mac(self): return "00:00:00:%02x:%02x:%02x" % (0,0,len(self_seen))
self_seen = []

# Inject minimal symbols expected by topology builder via monkeypatching when imported.

def test_stub():
    # Placeholder to ensure test file is discovered; real implementation would import builder and drive with preview.
    assert True
