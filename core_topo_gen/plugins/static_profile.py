from __future__ import annotations
"""
Static custom traffic plugin.

Provides a minimal sender/receiver that transmit simple payloads. Register via
`register()` and select kind="CUSTOM" on a traffic item so the generator uses
this plugin for script generation.
"""
from . import traffic as registry


def _static_receiver_script(port: int, protocol: str) -> str:
    proto = (protocol or "TCP").upper()
    if proto == "UDP":
        return f"""#!/usr/bin/env python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
print("[custom] UDP receiver on {port}")
try:
    while True:
        data, addr = s.recvfrom(8192)
        # discard
except KeyboardInterrupt:
    pass
"""
    # TCP default
    return f"""#!/usr/bin/env python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(5)
print("[custom] TCP receiver on {port}")
try:
    while True:
        conn, addr = s.accept()
        with conn:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
except KeyboardInterrupt:
    pass
"""


def _static_sender_script(host: str, port: int, rate_kbps: float, period_s: float, jitter_pct: float, content_type: str, protocol: str) -> str:
    proto = (protocol or "TCP").upper()
    return f"""#!/usr/bin/env python3
import socket, time, os, random
HOST = "{host}"; PORT = {port}
RATE_KBPS = float({rate_kbps})
PERIOD_S = float({period_s}) if {period_s} > 0 else 10.0
JITTER = float({jitter_pct})
PROTO = "{proto}"
print(f"[custom] {{PROTO}} sender -> {{HOST}}:{{PORT}} rate={{RATE_KBPS}}KB/s period={{PERIOD_S}}s")

def sleep_with_jitter(base: float):
    if base <= 0:
        return
    j = base * (JITTER / 100.0)
    time.sleep(max(0.0, random.uniform(base - j, base + j)))

def payload_bytes(n: int) -> bytes:
    # simple deterministic payload with header + random tail
    head = b"STATIC_CUSTOM_PAYLOAD\n"
    if n <= len(head):
        return head[:n]
    out = bytearray()
    while len(out) < n:
        out.extend(head)
        if len(out) < n:
            out.extend(os.urandom(min(256, n - len(out))))
    return bytes(out[:n])

def run_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bps = max(0.0, RATE_KBPS) * 1024.0
    ticks = 50
    per_tick = int(bps / ticks) if bps > 0 else 1
    per_tick = max(1, per_tick)
    tick_sleep = 1.0 / ticks
    end = time.time() + PERIOD_S
    while time.time() < end:
        try:
            s.sendto(payload_bytes(per_tick), (HOST, PORT))
        except Exception:
            pass
        sleep_with_jitter(tick_sleep)

def run_tcp():
    bps = max(0.0, RATE_KBPS) * 1024.0
    ticks = 20
    per_tick = int(bps / ticks) if bps > 0 else 1
    per_tick = max(1, per_tick)
    tick_sleep = 1.0 / ticks
    end = time.time() + PERIOD_S
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((HOST, PORT))
        while time.time() < end:
            try:
                s.sendall(payload_bytes(per_tick))
            except Exception:
                break
            sleep_with_jitter(tick_sleep)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

if PROTO == "UDP":
    run_udp()
else:
    run_tcp()
"""


def register() -> None:
    """Register the static custom traffic plugin with the global registry."""
    registry.register(_static_sender_script, _static_receiver_script)
