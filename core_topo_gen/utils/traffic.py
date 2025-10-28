from __future__ import annotations
import os
import stat
import random
from typing import Dict, List, Tuple, Optional
from ..plugins import traffic as custom_traffic
from ..plugins import static_profile as _static_profile
from ..types import NodeInfo, TrafficInfo


def _ip_only(cidr: str) -> str:
    return cidr.split("/")[0] if "/" in cidr else cidr


def _clean_traffic_dir(out_dir: str) -> None:
    """Remove previously generated traffic scripts from the output directory.

    For safety, only removes regular files whose names start with "traffic_".
    """
    try:
        for name in os.listdir(out_dir):
            path = os.path.join(out_dir, name)
            # remove files like traffic_<id>_rN.py or traffic_<id>_sN.py
            if os.path.isfile(path) and name.startswith("traffic_"):
                try:
                    os.remove(path)
                except Exception:
                    # best-effort cleanup; ignore failures
                    pass
    except FileNotFoundError:
        pass


def _tcp_receiver_script(port: int) -> str:
    return f"""#!/usr/bin/env python3
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(5)
print("[traffic] TCP receiver listening on {port}")
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


def _tcp_sender_script(host: str, port: int, rate_kbps: float, period_s: float, jitter_pct: float, pattern: str, content_type: str) -> str:
    # Implement pacing based on approximate bytes per tick and sleep intervals.
    # For TCP, open/close each period iteration to keep it simple and resilient.
    return f"""#!/usr/bin/env python3
import socket, time, os, random
host = "{host}"; port = {port}
rate_kbps = float({rate_kbps})
period_s = float({period_s})
jitter_pct = float({jitter_pct})
pattern = "{pattern}".lower() or "continuous"
content_type = "{content_type}".lower()
print(f"[traffic] TCP sender to {{host}}:{{port}} rate={{rate_kbps}}KB/s period={{period_s}}s jitter={{jitter_pct}}% pattern={{pattern}}")

# If content type isn't specified or is Random, pick one randomly including gibberish
if not content_type or (isinstance(content_type, str) and content_type.lower() == "random"):
    content_type = random.choices(["text", "photo", "audio", "video", "gibberish"], weights=[2, 1, 1, 1, 2])[0]

def sleep_with_jitter(base: float):
    if base <= 0:
        return
    j = base * (jitter_pct / 100.0)
    time.sleep(max(0.0, random.uniform(base - j, base + j)))

def send_period():
    # compute bytes per second
    bps = max(0.0, rate_kbps) * 1024.0
    if bps <= 0:
        # default to ~1KB/s if no rate provided
        bps = 1024.0
    # 20 ticks per second pacing
    ticks_per_sec = 20
    per_tick = int(bps / ticks_per_sec) if bps > 0 else 0
    if per_tick <= 0:
        per_tick = 1
    tick_sleep = 1.0 / ticks_per_sec
    t_end = time.time() + (period_s if period_s > 0 else 10.0)
    s = None
    # payload shaping depending on content_type
    def payload_bytes(n):
        if content_type in ("text", "txt", "log"):
            # use escaped CRLF so generated script keeps literals, not newlines
            line = ("GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: core-traffic\\r\\n\\r\\n").encode()
            out = bytearray()
            while len(out) < n:
                out.extend(line)
            return bytes(out[:n])
        if content_type in ("photo", "image", "jpeg", "jpg", "png"):
            # JPEG-like segment patterns (0xFF 0xD8 ... 0xFF 0xD9), fill with 0xFF and random
            out = bytearray()
            out.extend(b"\\xff\\xd8")
            while len(out) < max(4, n-2):
                out.append(0xff)
                out.append(random.randint(0x00, 0xFE))
            out.extend(b"\\xff\\xd9")
            return bytes(out[:n])
        if content_type in ("audio", "mp3", "aac"):
            # pseudo-frames ~ 1024 bytes
            frame = bytes(random.getrandbits(8) for _ in range(1024))
            out = (frame * ((n // 1024) + 1))[:n]
            return out
        if content_type in ("video", "h264", "mp4"):
            # NAL-like segments prefixed with 0x000001
            out = bytearray()
            chunk = max(256, min(8192, n // 4 or 256))
            while len(out) < n:
                out.extend(b"\\x00\\x00\\x01")
                out.extend(os.urandom(min(chunk, n - len(out))))
            return bytes(out[:n])
        if content_type in ("gibberish", "bytes", "junk", "rand", "random-bytes"):
            return os.urandom(n)
        # default: random bytes
        return os.urandom(n)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((host, port))

        if pattern == "poisson":
            # Poisson inter-arrival using exponential distribution around target bps
            avg_bytes = per_tick
            avg_interval = tick_sleep if per_tick > 0 else 0.05
            while time.time() < t_end:
                try:
                    if avg_bytes > 0:
                        size = max(1, int(random.expovariate(1.0 / avg_bytes)))
                        s.sendall(payload_bytes(size))
                except Exception:
                    break
                # exponential delay
                delay = random.expovariate(1.0 / max(1e-3, avg_interval))
                sleep_with_jitter(delay)
        elif pattern == "ramp":
            # ramp from 10% to 100% per_tick over the period
            start = time.time()
            while time.time() < t_end:
                elapsed = time.time() - start
                frac = min(1.0, max(0.1, elapsed / max(0.001, period_s)))
                size = max(1, int(per_tick * frac))
                try:
                    s.sendall(payload_bytes(size))
                except Exception:
                    break
                sleep_with_jitter(tick_sleep)
        else:
            while time.time() < t_end:
                if per_tick > 0:
                    try:
                        s.sendall(payload_bytes(per_tick))
                    except Exception:
                        break
                sleep_with_jitter(tick_sleep)
    except Exception:
        pass
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass

while True:
    if pattern in ("burst", "periodic"):
        send_period()
        # idle the same period length between bursts
        sleep_with_jitter(period_s if period_s > 0 else 10.0)
    else:
        # continuous: chain periods back-to-back
        send_period()
"""


def _udp_receiver_script(port: int) -> str:
    return f"""#!/usr/bin/env python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", {port}))
print("[traffic] UDP receiver listening on {port}")
try:
    while True:
        data, addr = s.recvfrom(8192)
except KeyboardInterrupt:
    pass
"""


def _udp_sender_script(host: str, port: int, rate_kbps: float, period_s: float, jitter_pct: float, pattern: str, content_type: str) -> str:
    return f"""#!/usr/bin/env python3
import socket, time, random, os
host = "{host}"; port = {port}
rate_kbps = float({rate_kbps})
period_s = float({period_s})
jitter_pct = float({jitter_pct})
pattern = "{pattern}".lower() or "continuous"
content_type = "{content_type}".lower()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print(f"[traffic] UDP sender to {{host}}:{{port}} rate={{rate_kbps}}KB/s period={{period_s}}s jitter={{jitter_pct}}% pattern={{pattern}}")

# If content type isn't specified or is 'random', pick one randomly including gibberish
if not content_type or (isinstance(content_type, str) and content_type.lower() == "random"):
    content_type = random.choices(["text", "photo", "audio", "video", "gibberish"], weights=[2, 1, 1, 1, 2])[0]

def sleep_with_jitter(base: float):
    if base <= 0:
        return
    j = base * (jitter_pct / 100.0)
    time.sleep(max(0.0, random.uniform(base - j, base + j)))

def send_period():
    bps = max(0.0, rate_kbps) * 1024.0
    if bps <= 0:
        # default to ~2.5KB/s (similar to previous 512B every 0.2s)
        bps = 2560.0
    ticks_per_sec = 50
    per_tick = int(bps / ticks_per_sec) if bps > 0 else 0
    if per_tick <= 0:
        per_tick = 1
    tick_sleep = 1.0 / ticks_per_sec
    t_end = time.time() + (period_s if period_s > 0 else 10.0)
    # payload shaping by content_type
    def payload_bytes(n):
        if content_type in ("text", "txt", "log"):
            line = ("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").encode()
            out = bytearray()
            while len(out) < n:
                out.extend(line)
            return bytes(out[:n])
        if content_type in ("photo", "image", "jpeg", "jpg", "png"):
            out = bytearray()
            out.extend(b"\xff\xd8")
            while len(out) < max(4, n-2):
                out.append(0xff)
                out.append(random.randint(0x00, 0xFE))
            out.extend(b"\xff\xd9")
            return bytes(out[:n])
        if content_type in ("audio", "mp3", "aac"):
            frame = bytes(random.getrandbits(8) for _ in range(256))
            out = (frame * ((n // 256) + 1))[:n]
            return out
        if content_type in ("video", "h264", "mp4"):
            out = bytearray()
            chunk = max(64, min(1400, n // 4 or 64))
            while len(out) < n:
                out.extend(b"\x00\x00\x01")
                out.extend(os.urandom(min(chunk, n - len(out))))
            return bytes(out[:n])
        if content_type in ("gibberish", "bytes", "junk", "rand", "random-bytes"):
            return os.urandom(n)
        return os.urandom(n)

    if pattern == "poisson":
        avg_bytes = per_tick
        avg_interval = tick_sleep if per_tick > 0 else 0.05
        while time.time() < t_end:
            try:
                if avg_bytes > 0:
                    size = max(1, int(random.expovariate(1.0 / avg_bytes)))
                    s.sendto(payload_bytes(size), (host, port))
            except Exception:
                pass
            delay = random.expovariate(1.0 / max(1e-3, avg_interval))
            sleep_with_jitter(delay)
    elif pattern == "ramp":
        start = time.time()
        while time.time() < t_end:
            elapsed = time.time() - start
            frac = min(1.0, max(0.1, elapsed / max(0.001, period_s)))
            size = max(1, int(per_tick * frac))
            try:
                s.sendto(payload_bytes(size), (host, port))
            except Exception:
                pass
            sleep_with_jitter(tick_sleep)
    else:
        while time.time() < t_end:
            if per_tick > 0:
                try:
                    s.sendto(payload_bytes(per_tick), (host, port))
                except Exception:
                    pass
            sleep_with_jitter(tick_sleep)

while True:
    if pattern in ("burst", "periodic"):
        send_period()
        sleep_with_jitter(period_s if period_s > 0 else 10.0)
    else:
        send_period()
"""


def _choose_kind(kinds: List[Tuple[str, float]]) -> str:
    total = sum(w for _, w in kinds)
    if total <= 0:
        return "TCP"
    r = random.random() * total
    acc = 0.0
    for k, w in kinds:
        acc += w
        if r <= acc:
            return k
    return kinds[-1][0]


def generate_traffic_scripts(hosts: List[NodeInfo], density: float, items: List[TrafficInfo], out_dir: str = "/tmp/traffic") -> Dict[int, List[str]]:
    """Generate simple TCP/UDP sender/receiver scripts for a subset of hosts.

    Returns a mapping of node_id -> list of script file paths (created locally).
    """
    result: Dict[int, List[str]] = {}
    flows: List[Dict[str, object]] = []
    # Determine if any item specifies an absolute count of flows
    count_items = [it for it in (items or []) if getattr(it, "abs_count", 0) and int(getattr(it, "abs_count", 0)) > 0]
    if not hosts:
        return result
    if density <= 0 and not count_items:
        return result

    os.makedirs(out_dir, exist_ok=True)
    # Clean out any existing generated traffic scripts before writing new ones
    _clean_traffic_dir(out_dir)

    # Build weighted kinds; expand 'Random' into TCP/UDP choice later
    weighted: List[Tuple[str, float]] = []
    for it in items or []:
        k = (it.kind or "").strip()
        if not k:
            continue
        if k.lower() == "random":
            # split weight evenly between TCP and UDP for selection
            w = max(0.0, float(it.factor))
            if w > 0:
                weighted.append(("TCP", w / 2.0))
                weighted.append(("UDP", w / 2.0))
        else:
            ku = k.upper()
            w = max(0.0, float(it.factor))
            if ku in ("TCP", "UDP", "CUSTOM"):
                weighted.append((ku, w))
            else:
                # Unknown kinds default to TCP for selection
                weighted.append(("TCP", w))
    if not weighted:
        weighted = [("TCP", 1.0)]

    # Maintain per-node indices for naming and per-node per-protocol RX offsets
    recv_idx_by_node: Dict[int, int] = {}
    send_idx_by_node: Dict[int, int] = {}
    rx_proto_idx: Dict[str, Dict[int, int]] = {"TCP": {}, "UDP": {}}

    # Helper to create a single flow given sender host, receiver node and item
    def _create_flow(host, rx_node, it, kind_override: Optional[str] = None):
        nonlocal recv_idx_by_node, send_idx_by_node, rx_proto_idx
        ik = (it.kind or "").strip()
        if not ik and not kind_override:
            return
        kind = kind_override or (_choose_kind(weighted) if ik.lower() == "random" else ik.upper())
        proto_key = kind if kind in ("TCP", "UDP") else "TCP"
        if proto_key not in rx_proto_idx:
            rx_proto_idx[proto_key] = {}
        base = 5000 if proto_key == "TCP" else 6000
        rx_node_id = rx_node.node_id
        # Compute per-node per-protocol receiver port index to avoid collisions
        proto_map = rx_proto_idx[proto_key]
        idx = proto_map.get(rx_node_id, 1)
        rx_port = base + (rx_node_id % 1000) + (idx - 1)
        proto_map[rx_node_id] = idx + 1
        # Receiver script
        r_index = recv_idx_by_node.get(rx_node_id, 1)
        recv_name = os.path.join(out_dir, f"traffic_{rx_node_id}_r{r_index}.py")
        if kind == "CUSTOM":
            _sender_fn, _receiver_fn = custom_traffic.get()
            if _sender_fn is None and _receiver_fn is None:
                try:
                    _static_profile.register()
                except Exception:
                    pass
                _sender_fn, _receiver_fn = custom_traffic.get()
            if _receiver_fn is not None:
                recv_content = _receiver_fn(rx_port, proto_key)
            else:
                recv_content = _tcp_receiver_script(rx_port) if proto_key == "TCP" else _udp_receiver_script(rx_port)
        else:
            recv_content = _tcp_receiver_script(rx_port) if proto_key == "TCP" else _udp_receiver_script(rx_port)
        with open(recv_name, "w", encoding="utf-8") as f:
            f.write(recv_content)
        os.chmod(recv_name, os.stat(recv_name).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        recv_idx_by_node[rx_node_id] = r_index + 1
        result.setdefault(rx_node_id, []).append(recv_name)

        # Sender
        dst_ip = _ip_only(rx_node.ip4)
        dst_port = rx_port
        s_index = send_idx_by_node.get(host.node_id, 1)
        send_name = os.path.join(out_dir, f"traffic_{host.node_id}_s{s_index}.py")
        rate_kbps = getattr(it, "rate_kbps", 0.0) or 0.0
        period_s = getattr(it, "period_s", 10.0) or 10.0
        jitter_pct = getattr(it, "jitter_pct", 0.0) or 0.0
        pattern = getattr(it, "pattern", "") or ""
        content_type = getattr(it, "content_type", "") or ""
        if (content_type or "").lower() == "random":
            pattern = random.choices(
                ["continuous", "periodic", "burst", "poisson", "ramp"],
                weights=[4, 2, 2, 1, 1]
            )[0]
            rate_kbps = max(16.0, min(1024.0, float(int(2 ** random.uniform(4, 10)))))
            period_s = round(random.uniform(0.2, 3.0), 2)
            jitter_pct = round(random.uniform(0.0, 30.0), 1)
        if kind == "CUSTOM":
            _sender_fn, _receiver_fn = custom_traffic.get()
            if _sender_fn is None and _receiver_fn is None:
                try:
                    _static_profile.register()
                except Exception:
                    pass
                _sender_fn, _receiver_fn = custom_traffic.get()
            if _sender_fn is not None:
                send_content = _sender_fn(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, content_type, proto_key)
            else:
                send_content = (
                    _tcp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                    if proto_key == "TCP"
                    else _udp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                )
        else:
            send_content = (
                _tcp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                if proto_key == "TCP"
                else _udp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
            )
        with open(send_name, "w", encoding="utf-8") as f:
            f.write(send_content)
        os.chmod(send_name, os.stat(send_name).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        send_idx_by_node[host.node_id] = s_index + 1
        result.setdefault(host.node_id, []).append(send_name)
        flows.append({
            "src_id": host.node_id,
            "dst_id": rx_node_id,
            "protocol": proto_key,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "pattern": pattern or "",
            "rate_kbps": rate_kbps,
            "period_s": period_s,
            "jitter_pct": jitter_pct,
            "content_type": content_type or "",
            "sender_script": send_name,
            "receiver_script": recv_name,
        })

    # 1) Generate flows for explicit-count items (abs_count)
    if count_items:
        # Round-robin sender/receiver selection across hosts
        H = len(hosts)
        if H == 0:
            return result
        # Deterministic ordering to avoid duplicate pairs when rerun
        rr_hosts = hosts.copy()
        # Don't shuffle rr_hosts: keep stable assignment
        for it in count_items:
            total = int(getattr(it, "abs_count", 0) or 0)
            if total <= 0:
                continue
            for i in range(total):
                sender = rr_hosts[i % H]
                # pick receiver as next host in the ring if possible, else self
                if H > 1:
                    rx = rr_hosts[(i + 1) % H]
                else:
                    rx = sender
                _create_flow(sender, rx, it)

    # 2) Generate flows for remaining items using density-based semantics
    # - density <= 0 handled above
    # - density >= 1 -> select all hosts
    # - otherwise round to nearest and clamp to [1, len(hosts)]
    import math
    if density >= 1:
        # density >= 1 means all hosts participate (legacy semantics)
        k = len(hosts)
    else:
        desired = len(hosts) * max(0.0, min(1.0, float(density)))
        k = max(1, min(len(hosts), int(round(desired))))
    selected = hosts.copy()
    random.shuffle(selected)
    selected = selected[:k]
    # Use only normal items for density-based generation
    normal_items = [it for it in (items or []) if not (getattr(it, "abs_count", 0) and int(getattr(it, "abs_count", 0)) > 0)]

    if density > 0 and normal_items:
        # For each selected host, create sender scripts for that host and receiver scripts on the chosen target
        items_to_use = normal_items
        for host in selected:
            others = [h for h in hosts if h.node_id != host.node_id]
            for it in items_to_use:
                ik = (it.kind or "").strip()
                if not ik:
                    continue
                kind = _choose_kind(weighted) if ik.lower() == "random" else ik.upper()

            # Underlying transport protocol: map to TCP/UDP
            proto_key = kind if kind in ("TCP", "UDP") else "TCP"
            # Ensure rx_proto_idx has an entry for the chosen protocol (defensive)
            if proto_key not in rx_proto_idx:
                rx_proto_idx[proto_key] = {}
            base = 5000 if proto_key == "TCP" else 6000

            target = random.choice(others) if others else None

            # Determine the receiver node: prefer target; if none, fall back to host
            rx_node = target if target is not None else host
            rx_node_id = rx_node.node_id

            # Compute per-node per-protocol receiver port index to avoid collisions
            proto_map = rx_proto_idx[proto_key]
            idx = proto_map.get(rx_node_id, 1)
            rx_port = base + (rx_node_id % 1000) + (idx - 1)
            proto_map[rx_node_id] = idx + 1

            # Receiver script named with the receiver node's id
            r_index = recv_idx_by_node.get(rx_node_id, 1)
            recv_name = os.path.join(out_dir, f"traffic_{rx_node_id}_r{r_index}.py")
            # If kind is CUSTOM and a plugin receiver exists, prefer it (auto-register static if none)
            if kind == "CUSTOM":
                _sender_fn, _receiver_fn = custom_traffic.get()
                if _sender_fn is None and _receiver_fn is None:
                    try:
                        _static_profile.register()
                    except Exception:
                        pass
                    _sender_fn, _receiver_fn = custom_traffic.get()
                if _receiver_fn is not None:
                    recv_content = _receiver_fn(rx_port, proto_key)
                else:
                    recv_content = _tcp_receiver_script(rx_port) if proto_key == "TCP" else _udp_receiver_script(rx_port)
            else:
                recv_content = _tcp_receiver_script(rx_port) if proto_key == "TCP" else _udp_receiver_script(rx_port)
            with open(recv_name, "w", encoding="utf-8") as f:
                f.write(recv_content)
            os.chmod(recv_name, os.stat(recv_name).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            recv_idx_by_node[rx_node_id] = r_index + 1
            # Track in result mapping under receiver node id
            result.setdefault(rx_node_id, []).append(recv_name)

            # Sender script from the current host to the receiver node/port
            # Always create a sender, even when target is None (self-traffic)
            dst_ip = _ip_only(rx_node.ip4)
            dst_port = rx_port
            s_index = send_idx_by_node.get(host.node_id, 1)
            send_name = os.path.join(out_dir, f"traffic_{host.node_id}_s{s_index}.py")
            # Use parsed rate/period/jitter/pattern when available
            rate_kbps = getattr(it, "rate_kbps", 0.0) or 0.0
            period_s = getattr(it, "period_s", 10.0) or 10.0
            jitter_pct = getattr(it, "jitter_pct", 0.0) or 0.0
            pattern = getattr(it, "pattern", "") or ""
            content_type = getattr(it, "content_type", "") or ""
            # If payload is Random, pick reasonable random values for pattern/rate/period/jitter
            if (content_type or "").lower() == "random":
                # Pattern weights favor continuous, then periodic/burst, with some poisson/ramp
                pattern = random.choices(
                    ["continuous", "periodic", "burst", "poisson", "ramp"],
                    weights=[4, 2, 2, 1, 1]
                )[0]
                # Rate between 16 and 1024 KB/s, skewed towards lower rates
                rate_kbps = max(16.0, min(1024.0, float(int(2 ** random.uniform(4, 10)))))
                # Base period between 0.2s and 3.0s
                period_s = round(random.uniform(0.2, 3.0), 2)
                # Jitter between 0 and 30%
                jitter_pct = round(random.uniform(0.0, 30.0), 1)
            # Use custom sender only when kind is CUSTOM (auto-register static if none)
            if kind == "CUSTOM":
                _sender_fn, _receiver_fn = custom_traffic.get()
                if _sender_fn is None and _receiver_fn is None:
                    try:
                        _static_profile.register()
                    except Exception:
                        pass
                    _sender_fn, _receiver_fn = custom_traffic.get()
                if _sender_fn is not None:
                    send_content = _sender_fn(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, content_type, proto_key)
                else:
                    send_content = (
                        _tcp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                        if proto_key == "TCP"
                        else _udp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                    )
            else:
                send_content = (
                    _tcp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                    if proto_key == "TCP"
                    else _udp_sender_script(dst_ip, dst_port, rate_kbps, period_s, jitter_pct, pattern, content_type)
                )
            with open(send_name, "w", encoding="utf-8") as f:
                f.write(send_content)
            os.chmod(send_name, os.stat(send_name).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            send_idx_by_node[host.node_id] = s_index + 1
            result.setdefault(host.node_id, []).append(send_name)

            # record a flow summary for reporting
            flows.append({
                "src_id": host.node_id,
                "dst_id": rx_node_id,
                # Record actual transport protocol used (TCP/UDP) for downstream tooling
                "protocol": proto_key,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "pattern": pattern or "",
                "rate_kbps": rate_kbps,
                "period_s": period_s,
                "jitter_pct": jitter_pct,
                "content_type": content_type or "",
                "sender_script": send_name,
                "receiver_script": recv_name,
            })

    # write a machine-readable summary to the out_dir for report generator
    try:
        import json
        with open(os.path.join(out_dir, "traffic_summary.json"), "w", encoding="utf-8") as jf:
            json.dump({"flows": flows}, jf, indent=2)
    except Exception:
        pass

    return result
