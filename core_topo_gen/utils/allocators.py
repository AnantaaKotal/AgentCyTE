from __future__ import annotations
import ipaddress
import random
from typing import Tuple, List, Dict, Set


class UniqueAllocator:
    def __init__(self, ip4_prefix: str):
        self.net = ipaddress.IPv4Network(ip4_prefix, strict=False)
        self.host_offset = 1
        self.mac_counter = 1

    def next_ip(self) -> Tuple[str, int]:
        if int(self.net.network_address) + self.host_offset >= int(self.net.broadcast_address):
            base = int(self.net.network_address) + self.net.num_addresses
            self.net = ipaddress.IPv4Network((ipaddress.IPv4Address(base), self.net.prefixlen))
            self.host_offset = 1
        ip_int = int(self.net.network_address) + self.host_offset
        self.host_offset += 1
        ip = str(ipaddress.IPv4Address(ip_int))
        return ip, self.net.prefixlen

    def next_mac(self) -> str:
        n = self.mac_counter
        self.mac_counter += 1
        b5 = [
            (n >> 32) & 0xFF,
            (n >> 24) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 8) & 0xFF,
            n & 0xFF,
        ]
        return "02:" + ":".join(f"{x:02x}" for x in b5)


class SubnetAllocator:
    """Allocate unique IPv4 subnets from a base network.

    Temporary policy: always return unique /24s.
    """

    def __init__(self, ip4_prefix: str):
        self.base = ipaddress.IPv4Network(ip4_prefix, strict=False)
        self._allocated: Set[Tuple[int, int]] = set()
        self._next_addr = int(self.base.network_address)

    def _force24(self) -> int:
        return 24

    def next_subnet(self, prefixlen: int) -> ipaddress.IPv4Network:
        prefixlen = self._force24()
        size = 1 << (32 - prefixlen)
        # Allocate sequentially across contiguous IPv4 space starting from base
        attempts = 0
        while attempts < (1 << 20):  # safety cap
            aligned = (self._next_addr + size - 1) // size * size
            key = (aligned, prefixlen)
            self._next_addr = aligned + size
            attempts += 1
            if key in self._allocated:
                continue
            net = ipaddress.IPv4Network((ipaddress.IPv4Address(aligned), prefixlen))
            self._allocated.add(key)
            return net
        raise RuntimeError("SubnetAllocator: ran out of attempts allocating unique /24s")

    def next_random_subnet(self, prefixlen: int, attempts: int = 256) -> ipaddress.IPv4Network:
        prefixlen = self._force24()
        size = 1 << (32 - prefixlen)
        start = int(self.base.network_address)
        end = start + self.base.num_addresses
        total_slots = self.base.num_addresses // size if self.base.num_addresses >= size else 0
        if total_slots > 0:
            for _ in range(max(8, attempts)):
                slot = random.randrange(0, total_slots)
                cand = start + slot * size
                key = (cand, prefixlen)
                if key in self._allocated:
                    continue
                net = ipaddress.IPv4Network((ipaddress.IPv4Address(cand), prefixlen))
                # ensure within base bounds
                if int(net.network_address) < start or int(net.broadcast_address) >= end:
                    continue
                self._allocated.add(key)
                return net
        # fallback to sequential unique
        return self.next_subnet(prefixlen)


class MultiPoolSubnetAllocator:
    """Allocate unique subnets across multiple pools.

    Temporary policy: always return unique /24s.
    """

    def __init__(self, pools: List[ipaddress.IPv4Network]):
        self.pools = pools[:]
        # randomize pool order for more variety
        random.shuffle(self.pools)
        self._allocated: Set[Tuple[int, int]] = set()
        self._next_addrs: Dict[int, int] = {int(p.network_address): int(p.network_address) for p in pools}

    def _force24(self) -> int:
        return 24

    def next_subnet(self, prefixlen: int) -> ipaddress.IPv4Network:
        prefixlen = self._force24()
        size = 1 << (32 - prefixlen)
        for i in range(len(self.pools)):
            pool = self.pools[i]
            start = int(pool.network_address)
            end = start + pool.num_addresses
            next_addr = self._next_addrs.get(start, start)
            scanned = 0
            max_slots = max(1, pool.num_addresses // size)
            while scanned <= max_slots:
                aligned = (next_addr + size - 1) // size * size
                if aligned + size > end:
                    aligned = start
                    next_addr = start
                key = (aligned, prefixlen)
                next_addr = aligned + size
                scanned += 1
                if key in self._allocated:
                    continue
                net = ipaddress.IPv4Network((ipaddress.IPv4Address(aligned), prefixlen))
                self._next_addrs[start] = next_addr
                self._allocated.add(key)
                # rotate pools for fairness
                self.pools = self.pools[i+1:] + self.pools[:i+1]
                return net
        raise RuntimeError("No available /24 subnets left across pools")

    def next_random_subnet(self, prefixlen: int, attempts: int = 256) -> ipaddress.IPv4Network:
        prefixlen = self._force24()
        size = 1 << (32 - prefixlen)
        for _ in range(max(8, attempts)):
            pool = random.choice(self.pools)
            start = int(pool.network_address)
            end = start + pool.num_addresses
            total_slots = pool.num_addresses // size if pool.num_addresses >= size else 0
            if total_slots <= 0:
                continue
            slot = random.randrange(0, total_slots)
            cand = start + slot * size
            key = (cand, prefixlen)
            if key in self._allocated:
                continue
            net = ipaddress.IPv4Network((ipaddress.IPv4Address(cand), prefixlen))
            if int(net.network_address) < start or int(net.broadcast_address) >= end:
                continue
            self._allocated.add(key)
            return net
        # fallback to sequential unique
        return self.next_subnet(prefixlen)


def _public_region_pools(region: str) -> List[ipaddress.IPv4Network]:
    r = (region or "all").lower()
    regions: Dict[str, List[str]] = {
        # These are illustrative samples; not exhaustive nor authoritative.
        "na": ["23.0.0.0/12", "63.0.0.0/12", "64.0.0.0/12", "98.0.0.0/12", "104.0.0.0/12", "184.0.0.0/12"],
        "eu": ["5.0.0.0/12", "31.0.0.0/12", "37.0.0.0/12", "77.0.0.0/12", "81.0.0.0/12", "141.0.0.0/12", "185.0.0.0/12"],
        "apac": ["14.0.0.0/12", "27.0.0.0/12", "36.0.0.0/12", "39.0.0.0/12", "42.0.0.0/12", "49.0.0.0/12", "58.0.0.0/12", "101.0.0.0/12", "103.0.0.0/12", "106.0.0.0/12"],
        "latam": ["177.0.0.0/12", "179.0.0.0/12", "186.0.0.0/12", "187.0.0.0/12", "189.0.0.0/12", "190.0.0.0/12", "201.0.0.0/12"],
        "africa": ["41.0.0.0/12", "105.0.0.0/12", "154.0.0.0/12", "196.0.0.0/12", "197.0.0.0/12"],
        "middle-east": ["31.0.0.0/12", "37.0.0.0/12", "46.0.0.0/12", "62.0.0.0/12"],
    }
    if r == "all" or r not in regions:
        all_blocks: List[str] = []
        for lst in regions.values():
            all_blocks.extend(lst)
        return [ipaddress.IPv4Network(p) for p in all_blocks]
    return [ipaddress.IPv4Network(p) for p in regions[r]]


def _default_pools(mode: str, region: str) -> List[ipaddress.IPv4Network]:
    mode = (mode or "private").lower()
    if mode == "public":
        return _public_region_pools(region)
    if mode == "mixed":
        return [ipaddress.IPv4Network(p) for p in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]] + _public_region_pools(region)
    # private
    return [ipaddress.IPv4Network(p) for p in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]


def make_subnet_allocator(ip_mode: str, base_prefix: str | None, region: str = "all") -> SubnetAllocator | MultiPoolSubnetAllocator:
    """Create a subnet allocator based on the requested mode.

    - private with base_prefix: sequential allocator within base
    - mixed/public: multi-pool allocator across default pools
    """
    mode = (ip_mode or "private").lower()
    pools = _default_pools(mode, region)
    # If a base prefix is provided, include it as a preferred pool for variety
    if base_prefix:
        try:
            base_pool = ipaddress.IPv4Network(base_prefix, strict=False)
            # prepend if not already present
            if all(int(p.network_address) != int(base_pool.network_address) or p.prefixlen != base_pool.prefixlen for p in pools):
                pools = [base_pool] + pools
        except Exception:
            pass
    return MultiPoolSubnetAllocator(pools)
