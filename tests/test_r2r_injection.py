import sys, types, importlib, pytest

# Obsolete test module: approval / preview edge injection path removed.
pytest.skip("obsolete: approved_plan R2R edge injection removed in full_preview refactor", allow_module_level=True)

def _install_core_stubs():
    # Create package hierarchy core.api.grpc.wrappers
    if 'core' not in sys.modules:
        core_mod = types.ModuleType('core'); sys.modules['core'] = core_mod
    if 'core.api' not in sys.modules:
        api_mod = types.ModuleType('core.api'); sys.modules['core.api'] = api_mod
    if 'core.api.grpc' not in sys.modules:
        grpc_mod = types.ModuleType('core.api.grpc'); sys.modules['core.api.grpc'] = grpc_mod
    if 'core.api.grpc.wrappers' not in sys.modules:
        wrappers_mod = types.ModuleType('core.api.grpc.wrappers'); sys.modules['core.api.grpc.wrappers'] = wrappers_mod
        class NodeType:
            ROUTER='router'; SWITCH='switch'; DEFAULT='host'; HUB='hub'; EMANE='emane'
        class Position:
            def __init__(self, x=0, y=0): self.x=x; self.y=y
        class Interface:
            def __init__(self, id=0, name='', ip4='', ip4_mask=0, mac=''):
                self.id=id; self.name=name; self.ip4=ip4; self.ip4_mask=ip4_mask; self.mac=mac
        wrappers_mod.NodeType = NodeType
        wrappers_mod.Position = Position
        wrappers_mod.Interface = Interface
    if 'core.api.grpc.client' not in sys.modules:
        client_mod = types.ModuleType('core.api.grpc.client'); sys.modules['core.api.grpc.client'] = client_mod
        class CoreGrpcClient: pass
        client_mod.CoreGrpcClient = CoreGrpcClient

class DummyCore:
    def add_session(self):
        class S:
            def __init__(self):
                self.nodes={}; self.links=[]
            def add_node(self, nid, _type=None, position=None, name=None):
                n=types.SimpleNamespace(id=nid, name=name or f'n{nid}', services=[], position=position)
                self.nodes[nid]=n; return n
            def add_link(self, *args, **kwargs):
                if args and len(args)>=2:
                    a=args[0]; b=args[1]
                else:
                    a=kwargs.get('node1') or kwargs.get('node1_id')
                    b=kwargs.get('node2') or kwargs.get('node2_id')
                if hasattr(a,'id'): a=a.id
                if hasattr(b,'id'): b=b.id
                pair=tuple(sorted((a,b)))
                if pair not in self.links:
                    self.links.append(pair)
        return S()

def test_r2r_preview_injection_respected():  # kept for historical reference
    pass
