from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class AllocationPool:
    hosts_total: int
    role_counts: Dict[str, int]
    routers_planned: int  # final_router_count
    services_plan: Dict[str, int]
    routing_plan: Dict[str, int]
    r2r_policy: Dict[str, int] | None = None  # summary targets like target_degree, mode counts
    r2s_policy: Dict[str, int] | None = None  # switches-per-router target/mode (Exact/Uniform/etc)
    vulnerabilities_plan: Dict[str, int] | None = None  # vulnerability name/category -> planned count
    # Track dynamic consumption
    hosts_allocated: int = 0
    routers_allocated: int = 0
    services_assigned: Dict[str, int] = field(default_factory=dict)
    vulnerabilities_assigned: int = 0
    r2r_edges_created: int = 0
    switches_allocated: int = 0
    r2s_ratio_used: float | None = None  # persisted ratio actually applied
    notes: List[str] = field(default_factory=list)
    # Optional full preview blob (for deterministic previews / reporting only).
    full_preview: Dict[str, Any] | None = None

    def consume_hosts(self, n: int) -> bool:
        if self.hosts_allocated + n > self.hosts_total:
            return False
        self.hosts_allocated += n
        return True

    def consume_router(self) -> bool:
        if self.routers_allocated + 1 > self.routers_planned:
            return False
        self.routers_allocated += 1
        return True

    def record_service(self, name: str) -> None:
        self.services_assigned[name] = self.services_assigned.get(name, 0) + 1

    def consume_switches(self, n: int) -> None:
        # Switch allocation isn't pre-planned by count yet; just track.
        self.switches_allocated += n

    def record_vulnerability_assignment(self, count: int = 1) -> None:
        self.vulnerabilities_assigned += count

    def summarize(self) -> Dict[str, Any]:
        # Base summary reflects current consumption state. Enrich with planning details
        summary: Dict[str, Any] = {
            "hosts_total": self.hosts_total,
            "hosts_allocated": self.hosts_allocated,
            "routers_planned": self.routers_planned,
            "routers_allocated": self.routers_allocated,
            "role_counts": self.role_counts,
            "services_plan": self.services_plan,
            "services_assigned": self.services_assigned,
            "routing_plan": self.routing_plan,
            "r2r_policy": self.r2r_policy,
            "r2r_edges_created": self.r2r_edges_created,
            "switches_allocated": self.switches_allocated,
            "r2s_ratio_used": self.r2s_ratio_used,
            "r2s_policy": self.r2s_policy,
            "vulnerabilities_plan": self.vulnerabilities_plan,
            "vulnerabilities_assigned": self.vulnerabilities_assigned,
            "notes": self.notes,
            "full_preview_attached": bool(self.full_preview),
        }
        # Deterministic preview expansions (resolved randoms) – only when not yet allocated fully
        try:
            if self.hosts_allocated == 0 and self.role_counts:
                role_assignment_preview: list[str] = []
                for r, cnt in sorted(self.role_counts.items()):
                    role_assignment_preview.extend([r] * int(cnt))
                summary["role_assignment_preview"] = role_assignment_preview
        except Exception:
            pass
        try:
            if self.services_plan and not summary.get("services_plan_expanded"):
                summary["services_plan_expanded"] = dict(self.services_plan)
        except Exception:
            pass
        try:
            if self.routing_plan and not summary.get("routing_plan_expanded"):
                summary["routing_plan_expanded"] = dict(self.routing_plan)
        except Exception:
            pass
        try:
            if self.vulnerabilities_plan and not summary.get("vulnerabilities_plan_expanded"):
                summary["vulnerabilities_plan_expanded"] = dict(self.vulnerabilities_plan)
        except Exception:
            pass
        # Ensure r2s_policy key exists
        summary.setdefault("r2s_policy", self.r2s_policy)
        return summary
