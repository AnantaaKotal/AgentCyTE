import sys
from pathlib import Path

# Ensure repository root is on sys.path so imports like 'webapp.app_backend' work
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Provide a minimal stub for missing CORE gRPC dependency in testing environments
try:  # only create if real package absent
    import core.api.grpc.client  # type: ignore
except Exception:  # pragma: no cover - defensive
    import types
    core_mod = sys.modules.setdefault('core', types.ModuleType('core'))
    api_mod = sys.modules.setdefault('core.api', types.ModuleType('core.api'))
    grpc_mod = sys.modules.setdefault('core.api.grpc', types.ModuleType('core.api.grpc'))
    client_mod = types.ModuleType('core.api.grpc.client')
    class CoreGrpcClient:  # minimal placeholder
        pass
    client_mod.CoreGrpcClient = CoreGrpcClient
    sys.modules['core.api.grpc.client'] = client_mod
    # wrappers stub
    wrappers_mod = types.ModuleType('core.api.grpc.wrappers')
    class Position:
        def __init__(self, x=0, y=0): self.x=x; self.y=y
    class Interface:
        def __init__(self, id=0, name='', ip4='', ip4_mask=24, mac=''): self.id=id; self.name=name; self.ip4=ip4; self.ip4_mask=ip4_mask; self.mac=mac
    class NodeType:
        DEFAULT=0; SWITCH=1; DOCKER=2
    wrappers_mod.Position = Position
    wrappers_mod.Interface = Interface
    wrappers_mod.NodeType = NodeType
    sys.modules['core.api.grpc.wrappers'] = wrappers_mod
