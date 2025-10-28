"""
Minimal plugin API for custom segmentation policies.

External code can register a custom generator that will be invoked when a
segmentation item selects type "CUSTOM". This mirrors the Traffic CUSTOM
plugin approach: the plugin returns a complete, executable Python script
string to be written to disk and executed on the target node.

Contract:
- handler(node: NodeInfo, on_router: bool, subnets: List[str], hosts: List[NodeInfo]) -> str
  Returns a full Python script (as text) that applies the desired policy
  for the given node. The script will be saved and marked executable.

Notes:
- Keep side effects in the generated script, not in the handler, so that
  the same policy can be persisted/replayed. The handler itself should be
  pure and only return text.
"""
from __future__ import annotations
from typing import Callable, Optional, List

try:
    # Local imports only for type hints; avoid runtime dependency
    from ..types import NodeInfo  # type: ignore
except Exception:  # pragma: no cover - typing aid only
    NodeInfo = object  # type: ignore

SegmentationHandler = Callable[["NodeInfo", bool, List[str], List["NodeInfo"]], str]

_handler: Optional[SegmentationHandler] = None

def register(handler: SegmentationHandler) -> None:
    """Register a custom segmentation policy generator.

    Passing None resets the registry to empty.
    """
    global _handler
    _handler = handler


def get() -> Optional[SegmentationHandler]:
    """Return the current custom segmentation handler (may be None)."""
    return _handler
