
#!/usr/bin/env python3
"""
parse_scenarios.py
(Updated: adds missing `from pathlib import Path` import.)

Reads scenario XML files produced by your GUI, parses *all* XML content in a lossless
way, and additionally extracts structured summaries:

- nodes (with robust id/name/type inference)
- links (understands node1/node2, src/dst, from/to, source/target, child-node endpoints, etc.)
- services
- traffic flows
- segmentation/segments
- vulnerabilities
"""
import argparse
import json
import sys
import re
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from pathlib import Path

try:
    # Prefer lxml if available for better namespace handling and speed,
    # but fall back to stdlib if not present.
    from lxml import etree as ET
    LXML = True
except Exception:
    import xml.etree.ElementTree as ET  # type: ignore
    LXML = False

# ------------------------- Utilities -------------------------

ENDPOINT_ATTR_CANDIDATES = [
    ("node1", "node2"),
    ("end1", "end2"),
    ("src", "dst"),
    ("source", "target"),
    ("from", "to"),
    ("a", "b"),
    ("u", "v"),
]

NODE_TAG_CANDIDATES = {
    "node", "host", "router", "switch", "pc", "server", "workstation", "device", "vertex"
}

LINK_TAG_CANDIDATES = {
    "link", "connection", "edge", "pair", "pipe", "channel"
}

SERVICE_TAG_CANDIDATES = {
    "service", "application", "app", "daemon", "process"
}

TRAFFIC_TAG_CANDIDATES = {
    "traffic", "flow", "profile", "stream"
}

SEGMENT_TAG_CANDIDATES = {
    "segmentation", "segment", "zone", "vlan"
}

VULN_TAG_CANDIDATES = {
    "vulnerability", "vuln", "cve", "weakness"
}

ID_ATTR_NAMES = ["id", "uuid", "uid"]
NAME_ATTR_NAMES = ["name", "label", "title"]

CHILD_ID_NAMES = {"id", "uuid", "uid"}
CHILD_NAME_NAMES = {"name", "label", "title", "caption"}
CHILD_TYPE_NAMES = {"type", "kind", "role", "category", "class"}

def strip_ns(tag: str) -> str:
    """Return local tag name without namespace.

    Robust to lxml special nodes (e.g., Comment/PI) where ``.tag`` is not a string.
    """
    if tag is None:
        return ""
    # Some lxml node types (Comment, ProcessingInstruction) expose a callable/non-str tag.
    if not isinstance(tag, str):
        try:
            return str(tag)
        except Exception:
            return ""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag

def text_content(el) -> str:
    """Concatenate element text and tail strings (namespace-agnostic)."""
    parts = []
    t = (el.text or "").strip()
    if t:
        parts.append(t)
    tail = (el.tail or "").strip()
    if tail:
        parts.append(tail)
    return " ".join(parts)

def first(*vals):
    """Return first non-empty/non-None string among vals."""
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str):
            if v.strip():
                return v.strip()
        else:
            return v
    return None

def child_text_by_names(el, names: Iterable[str]) -> Optional[str]:
    names_l = {n.lower() for n in names}
    for ch in el:
        if strip_ns(ch.tag).lower() in names_l:
            txt = text_content(ch)
            if txt:
                return txt
            # Also check '@value' style
            val = ch.get("value")
            if val:
                return val
    return None

def get_any_attr(el, candidates: Iterable[str]) -> Optional[str]:
    for c in candidates:
        if c in el.attrib and str(el.attrib[c]).strip():
            return el.attrib[c].strip()
        # case-insensitive matching
        for k, v in el.attrib.items():
            if k.lower() == c.lower() and str(v).strip():
                return str(v).strip()
    return None

def attributes_dict(el) -> Dict[str, Any]:
    return {k: v for k, v in el.attrib.items()}

# ------------------------- Dataclasses -------------------------

@dataclass
class NodeInfo:
    id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    path: str = ""   # XPath-like location

@dataclass
class LinkInfo:
    src: Optional[str] = None
    dst: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

@dataclass
class ServiceInfo:
    name: Optional[str] = None
    type: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

@dataclass
class TrafficInfo:
    src: Optional[str] = None
    dst: Optional[str] = None
    pattern: Optional[str] = None
    proto: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

@dataclass
class SegmentInfo:
    name: Optional[str] = None
    id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

@dataclass
class VulnerabilityInfo:
    id: Optional[str] = None
    name: Optional[str] = None
    cve: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

# ------------------------- Lossless element dict -------------------------

def element_to_tree_dict(el) -> Dict[str, Any]:
    """Lossless-ish conversion of an element and children into a JSON-serializable dict."""
    d: Dict[str, Any] = {
        "tag": strip_ns(el.tag),
        "attributes": attributes_dict(el),
    }
    t = (el.text or "").strip()
    if t:
        d["text"] = t
    kids = [element_to_tree_dict(ch) for ch in list(el)]
    if kids:
        d["children"] = kids
    return d

# ------------------------- XPath-ish path helper -------------------------

def build_path(el) -> str:
    """Build a stable, simple xpath-like path for diagnostics."""
    names = []
    cur = el
    while cur is not None:
        parent = cur.getparent() if hasattr(cur, "getparent") else None
        tag = strip_ns(cur.tag)
        idx = ""
        if parent is not None:
            # index among same-tag siblings (1-based)
            sibs = [c for c in parent if strip_ns(c.tag) == tag]
            if len(sibs) > 1:
                for i, s in enumerate(sibs, 1):
                    if s is cur:
                        idx = f"[{i}]"
                        break
        names.append(f"{tag}{idx}")
        cur = parent
    return "/" + "/".join(reversed(names))

# ------------------------- Extraction logic -------------------------

def infer_node(el) -> Optional[NodeInfo]:
    tag = strip_ns(el.tag).lower()
    if tag not in NODE_TAG_CANDIDATES:
        return None

    attrs = attributes_dict(el)

    node_id = first(
        get_any_attr(el, ID_ATTR_NAMES),
        child_text_by_names(el, CHILD_ID_NAMES)
    )

    name = first(
        get_any_attr(el, NAME_ATTR_NAMES),
        child_text_by_names(el, CHILD_NAME_NAMES),
    )

    ntype = first(
        attrs.get("type"),
        attrs.get("kind"),
        attrs.get("role"),
        child_text_by_names(el, CHILD_TYPE_NAMES),
    )

    return NodeInfo(
        id=node_id,
        name=name,
        type=ntype or tag,
        attributes=attrs,
        path=build_path(el),
    )

def _endpoint_from_children(el, child_name: str) -> Optional[str]:
    for ch in el:
        ct = strip_ns(ch.tag).lower()
        if ct == child_name:
            # endpoint via attributes (id/name) or child text
            return first(
                get_any_attr(ch, ["id", "name", "ref"]),
                child_text_by_names(ch, {"id", "name", "ref"}),
                text_content(ch),
            )
    return None

def infer_link(el) -> Optional[LinkInfo]:
    tag = strip_ns(el.tag).lower()
    if tag not in LINK_TAG_CANDIDATES:
        # allow generic containers that still encode endpoints
        pass

    attrs = attributes_dict(el)

    # Try attribute pairs first
    src = dst = None
    for a, b in ENDPOINT_ATTR_CANDIDATES:
        src = get_any_attr(el, [a])
        dst = get_any_attr(el, [b])
        if src or dst:
            break

    # Try child endpoints (node1/node2, end1/end2, etc.)
    if not (src and dst):
        for a, b in ENDPOINT_ATTR_CANDIDATES:
            if not src:
                src = _endpoint_from_children(el, a)
            if not dst:
                dst = _endpoint_from_children(el, b)
            if src or dst:
                break

    # Generic "node" children like <node>n1</node><node>n2</node>
    if not (src and dst):
        nodes = []
        for ch in el:
            if strip_ns(ch.tag).lower() in {"node", "endpoint", "end"}:
                val = first(
                    get_any_attr(ch, ["id", "name", "ref"]),
                    child_text_by_names(ch, {"id", "name", "ref"}),
                    text_content(ch),
                )
                if val:
                    nodes.append(val)
        if len(nodes) >= 2:
            src, dst = nodes[0], nodes[1]

    if not (src or dst):
        return None

    return LinkInfo(
        src=src,
        dst=dst,
        attributes=attrs,
        path=build_path(el),
    )

def infer_service(el) -> Optional[ServiceInfo]:
    tag = strip_ns(el.tag).lower()
    if tag not in SERVICE_TAG_CANDIDATES:
        return None
    attrs = attributes_dict(el)
    name = first(get_any_attr(el, NAME_ATTR_NAMES), child_text_by_names(el, CHILD_NAME_NAMES))
    stype = first(attrs.get("type"), child_text_by_names(el, {"type"}))
    return ServiceInfo(
        name=name or tag,
        type=stype,
        attributes=attrs,
        path=build_path(el),
    )

def infer_traffic(el) -> Optional[TrafficInfo]:
    tag = strip_ns(el.tag).lower()
    if tag not in TRAFFIC_TAG_CANDIDATES:
        return None
    attrs = attributes_dict(el)
    src = first(get_any_attr(el, ["src", "from", "source", "node1", "end1"]),
                child_text_by_names(el, {"src", "from", "source", "node1", "end1"}))
    dst = first(get_any_attr(el, ["dst", "to", "target", "node2", "end2"]),
                child_text_by_names(el, {"dst", "to", "target", "node2", "end2"}))
    pattern = first(get_any_attr(el, ["pattern", "mode"]), child_text_by_names(el, {"pattern", "mode"}))
    proto = first(get_any_attr(el, ["protocol", "proto"]), child_text_by_names(el, {"protocol", "proto"}))
    return TrafficInfo(
        src=src,
        dst=dst,
        pattern=pattern,
        proto=proto,
        attributes=attrs,
        path=build_path(el),
    )

def infer_segment(el) -> Optional[SegmentInfo]:
    tag = strip_ns(el.tag).lower()
    if tag not in SEGMENT_TAG_CANDIDATES:
        return None
    attrs = attributes_dict(el)
    name = first(get_any_attr(el, NAME_ATTR_NAMES), child_text_by_names(el, CHILD_NAME_NAMES))
    sid = first(get_any_attr(el, ID_ATTR_NAMES), child_text_by_names(el, CHILD_ID_NAMES))
    return SegmentInfo(
        name=name or tag,
        id=sid,
        attributes=attrs,
        path=build_path(el),
    )

def infer_vuln(el) -> Optional[VulnerabilityInfo]:
    tag = strip_ns(el.tag).lower()
    if tag not in VULN_TAG_CANDIDATES:
        return None
    attrs = attributes_dict(el)
    vid = first(get_any_attr(el, ID_ATTR_NAMES), child_text_by_names(el, CHILD_ID_NAMES))
    name = first(get_any_attr(el, NAME_ATTR_NAMES), child_text_by_names(el, CHILD_NAME_NAMES))
    cve = first(get_any_attr(el, ["cve"]), child_text_by_names(el, {"cve"}))
    return VulnerabilityInfo(
        id=vid,
        name=name or tag,
        cve=cve,
        attributes=attrs,
        path=build_path(el),
    )

def walk_all(el):
    stack = [el]
    while stack:
        cur = stack.pop()
        yield cur
        kids = list(cur)
        kids.reverse()
        stack.extend(kids)

def parse_one_tree(root_el) -> Dict[str, Any]:
    """
    Produce a dict with:
    - raw: lossless tree
    - summary: counts
    - nodes, links, services, traffic, segments, vulnerabilities
    """
    nodes: List[NodeInfo] = []
    links: List[LinkInfo] = []
    services: List[ServiceInfo] = []
    traffic: List[TrafficInfo] = []
    segments: List[SegmentInfo] = []
    vulns: List[VulnerabilityInfo] = []

    # Extract everything across the whole tree
    for el in walk_all(root_el):
        n = infer_node(el)
        if n: nodes.append(n)

        l = infer_link(el)
        if l: links.append(l)

        s = infer_service(el)
        if s: services.append(s)

        tr = infer_traffic(el)
        if tr: traffic.append(tr)

        sg = infer_segment(el)
        if sg: segments.append(sg)

        vu = infer_vuln(el)
        if vu: vulns.append(vu)

    # Build lossless dict
    raw_dict = element_to_tree_dict(root_el)

    return {
        "root_tag": strip_ns(root_el.tag),
        "raw": raw_dict,
        "summary": {
            "node_count": len(nodes),
            "link_count": len(links),
            "service_count": len(services),
            "traffic_count": len(traffic),
            "segment_count": len(segments),
            "vuln_count": len(vulns),
        },
        "nodes": [asdict(n) for n in nodes],
        "links": [asdict(l) for l in links],
        "services": [asdict(s) for s in services],
        "traffic": [asdict(t) for t in traffic],
        "segments": [asdict(s) for s in segments],
        "vulnerabilities": [asdict(v) for v in vulns],
    }

def parse_file(path: Union[str, Path]) -> Dict[str, Any]:
    if LXML:
        parser = ET.XMLParser(remove_blank_text=True)
        tree = ET.parse(str(path), parser)  # type: ignore
        root = tree.getroot()
    else:
        tree = ET.parse(str(path))  # type: ignore
        root = tree.getroot()
    return parse_one_tree(root)

# ------------------------- CLI -------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse scenario XML and extract all data + summaries.")
    ap.add_argument("inputs", nargs="+", help="XML file(s) to parse")
    ap.add_argument("-o", "--out", help="Write combined JSON to this file")
    ap.add_argument("--report", action="store_true", help="Print a human-readable report")
    args = ap.parse_args(argv)

    results = []
    for inp in args.inputs:
        try:
            data = parse_file(inp)
            results.append({"file": inp, "data": data})
        except Exception as e:
            results.append({"file": inp, "error": str(e)})

    # Write JSON if requested
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Wrote JSON: {args.out}")

    # Print report if requested
    if args.report:
        for r in results:
            print("="*80)
            print(f"FILE: {r['file']}")
            if "error" in r:
                print("ERROR:", r["error"])
                continue
            d = r["data"]
            s = d["summary"]
            print(f"Root tag: {d['root_tag']}")
            print(f"Counts: nodes={s['node_count']} links={s['link_count']} services={s['service_count']} traffic={s['traffic_count']} segments={s['segment_count']} vulns={s['vuln_count']}")
            # Show a few examples
            def show_some(label, items, keys):
                print(f"\n{label}: ({len(items)})")
                for j, it in enumerate(items[:5], 1):
                    preview = ", ".join([f"{k}={it.get(k)}" for k in keys])
                    print(f"  - {preview}  @{it.get('path')}")
            show_some("Nodes", d["nodes"], ["id","name","type"])
            show_some("Links", d["links"], ["src","dst"])
            show_some("Services", d["services"], ["name","type"])
            show_some("Traffic", d["traffic"], ["src","dst","pattern","proto"])
            show_some("Segments", d["segments"], ["id","name"])
            show_some("Vulnerabilities", d["vulnerabilities"], ["id","name","cve"])
        print("="*80)

    # If neither out nor report, pretty-print to stdout for quick inspection
    if not args.out and not args.report:
        print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
