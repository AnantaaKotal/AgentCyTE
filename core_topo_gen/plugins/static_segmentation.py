from __future__ import annotations
"""
Static custom segmentation plugin sample.

Provides a minimal handler that logs packets on either INPUT/FORWARD and
adds a harmless rate-limit rule. This mirrors the traffic static plugin
style and is useful as a starting template.

Usage:
- Call register() before generation, and include an item with name="CUSTOM"
  in the segmentation config to route to this plugin.
"""
from typing import List, Any
from . import segmentation as registry

NodeInfo = Any  # avoid hard dependency for import-time typing


def _static_segmentation_script(node: NodeInfo, on_router: bool, subnets: List[str], hosts: List[NodeInfo]) -> str:
    chain = "FORWARD" if on_router else "INPUT"
    # Choose a subnet to log if available, fall back to all
    target = subnets[0] if subnets else None
    match = f"-s {target} " if target else ""
    return f"""#!/usr/bin/env python3
import subprocess, shlex
cmds = [
    # log a small sample of traffic for visibility (rate-limited)
    "iptables -A {chain} {match}-m limit --limit 2/second -j LOG --log-prefix '[custom-seg]'",
]
for c in cmds:
    try:
        subprocess.check_call(shlex.split(c))
    except Exception:
        pass
print('[custom-seg] applied', len(cmds), 'commands on node', {getattr(node, 'node_id', 'unknown')})
"""


def register() -> None:
    """Register the static custom segmentation plugin with the registry."""
    registry.register(_static_segmentation_script)
