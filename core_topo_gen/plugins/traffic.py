"""
Minimal plugin API for custom traffic profiles.

External code can register a custom sender/receiver generator that will be
invoked when a traffic item selects kind="CUSTOM". This keeps the main
generator stable while allowing future pluggable behavior.

Contract:
- sender(host, port, rate_kbps, period_s, jitter_pct, content_type, protocol) -> str (script contents)
- receiver(port, protocol) -> str (script contents)

Both functions should return complete, executable Python scripts as strings.
Either may be omitted; the built-in default will be used when not provided.
"""
from __future__ import annotations
from typing import Callable, Optional, Tuple

CustomSender = Callable[[str, int, float, float, float, str, str], str]
CustomReceiver = Callable[[int, str], str]

_sender: Optional[CustomSender] = None
_receiver: Optional[CustomReceiver] = None

def register(sender: CustomSender, receiver: Optional[CustomReceiver] = None) -> None:
    """Register custom traffic profile generators.

    Provide a sender function, and optionally a receiver function. Passing None
    clears the previously set functions.
    """
    global _sender, _receiver
    _sender = sender
    _receiver = receiver

def get() -> Tuple[Optional[CustomSender], Optional[CustomReceiver]]:
    """Return the currently registered (sender, receiver) pair (may be None)."""
    return _sender, _receiver
