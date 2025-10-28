"""Generate a corpus of scenario XML files conforming to validation/scenarios.xsd.

Creates 100 files under outputs/schema-samples/sample_<n>.xml exercising:
- Different mixes of sections
- Weight vs Count rows
- Routing connectivity attributes (r2r_mode / r2r_edges)
- R2S aggregation modes with host grouping bounds
- Optional planning metadata attributes

Run:
  python scripts/gen_schema_samples.py
"""
from __future__ import annotations
import os
import random
import datetime as dt
from pathlib import Path
from typing import List, Tuple

R2R_MODES = ["Uniform", "NonUniform", "Exact", "Min", ""]
R2S_MODES = ["Exact", "NonUniform", "aggregate", "ratio", ""]
TRAFFIC_PATTERNS = ["continuous", "burst", "periodic", "poisson", "ramp"]
TRAFFIC_PAYLOAD_TYPES = ["Random", "text", "photo", "audio", "video", "gibberish"]
TRAFFIC_KINDS = ["Random", "TCP", "UDP", "CUSTOM"]
VULN_KINDS = ["Random", "Type/Vector", "Specific"]
SEG_KINDS = ["Random", "Firewall", "NAT", "CUSTOM"]


def rand_hosts_meta(rng: random.Random) -> Tuple[int, int, int, int]:
    base = rng.randint(0, 80)
    add = rng.randint(0, 20)
    weights = rng.randint(0, 3)
    counts = rng.randint(0, 3)
    return base, add, weights, counts


def _normalize(pairs: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
    if not pairs:
        return []
    total = sum(v for _n, v in pairs) or 1.0
    return [(n, round(v / total, 6)) for n, v in pairs]


def build_section_node_info(rng: random.Random):
    base, add, weight_rows, count_rows = rand_hosts_meta(rng)
    weight_pairs: List[Tuple[str, float]] = []
    for i in range(weight_rows):
        weight_pairs.append((f"Role{i+1}", round(rng.uniform(0.1, 1.0), 6)))
    weight_pairs = _normalize(weight_pairs)
    items: List[str] = [f'<item selected="{role}" factor="{factor}"/>' for role, factor in weight_pairs]
    for i in range(count_rows):
        items.append(f'<item selected="RoleC{i+1}" v_metric="Count" v_count="{rng.randint(1,8)}"/>')
    weight_sum = round(sum(f for _r, f in weight_pairs), 6)
    attrs = (
        f' name="Node Information" base_nodes="{base}" additive_nodes="{add}" combined_nodes="{base + add}"'
        f' weight_rows="{weight_rows}" count_rows="{count_rows}" weight_sum="{weight_sum}"'
    )
    return f'<section{attrs}>{"".join(items)}</section>'

def build_section_routing(rng: random.Random):
    density = round(rng.uniform(0, 0.9), 3)
    rows = rng.randint(1, 3)
    items: List[str] = []
    explicit_total = 0
    derived = 0
    weight_rows = 0
    count_rows = 0
    weight_specs: List[Tuple[int, float, str]] = []  # (idx, factor_raw, xml_attrs)
    for i in range(rows):
        mode_r2r = rng.choice(R2R_MODES)
        mode_r2s = rng.choice(R2S_MODES)
        r2r_edges = rng.randint(0, 4) if mode_r2r == 'Exact' else 0
        r2s_edges = rng.randint(0, 4) if mode_r2s == 'Exact' else rng.randint(0, 8)
        hmin = hmax = ''
        if mode_r2s == 'NonUniform':
            lo = rng.randint(2, 4)
            hi = rng.randint(lo, max(lo, lo + 4))
            hmin = f'r2s_hosts_min="{lo}"'
            hmax = f'r2s_hosts_max="{hi}"'
        attrs = []
        if mode_r2r:
            attrs.append(f'r2r_mode="{mode_r2r}"')
        if mode_r2r == 'Exact':
            attrs.append(f'r2r_edges="{r2r_edges}"')
        if mode_r2s:
            attrs.append(f'r2s_mode="{mode_r2s}"')
            if mode_r2s == 'Exact' or mode_r2s in ('aggregate', 'ratio'):
                attrs.append(f'r2s_edges="{r2s_edges}"')
        if hmin:
            attrs.append(hmin)
        if hmax:
            attrs.append(hmax)
        attr_str = ' '.join(attrs)
        if rng.random() < 0.5:
            factor = round(rng.uniform(0.1, 1.0), 6)
            weight_rows += 1
            weight_specs.append((i, factor, attr_str))
            items.append(f'__PLACEHOLDER_WEIGHT_{i}__')
        else:
            cnt = rng.randint(1, 6)
            count_rows += 1
            explicit_total += cnt
            items.append(f'<item selected="Proto{i+1}" v_metric="Count" v_count="{cnt}" {attr_str}/>' )
    weight_sum = 0.0
    if weight_specs:
        total_raw = sum(f for _i, f, _a in weight_specs) or 1.0
        norm_map = {idx: round(f / total_raw, 6) for idx, f, _a in weight_specs}
        weight_sum = round(sum(norm_map.values()), 6)
        new_items: List[str] = []
        for token in items:
            if token.startswith('__PLACEHOLDER_WEIGHT_'):
                try:
                    idx = int(token.rsplit('_', 1)[-1])
                except ValueError:
                    # Skip malformed placeholder
                    continue
                for spec_idx, _f_raw, attr_str in weight_specs:
                    if spec_idx == idx:
                        new_items.append(f'<item selected="Proto{idx+1}" factor="{norm_map[idx]}" {attr_str}/>' )
                        break
            else:
                new_items.append(token)
        items = new_items
    if weight_rows > 0:
        derived = rng.randint(0, 10)
    total_planned = explicit_total + derived
    attrs = (
        f' name="Routing" density="{density}" explicit_count="{explicit_total}" derived_count="{derived}"'
        f' total_planned="{total_planned}" weight_rows="{weight_rows}" count_rows="{count_rows}" weight_sum="{weight_sum}"'
    )
    return f'<section{attrs}>{"".join(items)}</section>'

def build_section_simple(name: str, rng: random.Random):
    density = round(rng.uniform(0, 1), 3)
    items: List[str] = []
    rows = rng.randint(0, 2)
    weight_rows = 0
    count_rows = 0
    explicit = 0
    weight_specs: List[Tuple[int, float]] = []
    for i in range(rows):
        if rng.random() < 0.5:
            factor = round(rng.uniform(0.1, 1.0), 6)
            weight_specs.append((i, factor))
            weight_rows += 1
        else:
            cnt = rng.randint(1, 5)
            items.append(f'<item selected="{name}Item{i+1}" v_metric="Count" v_count="{cnt}"/>')
            count_rows += 1
            explicit += cnt
    weight_sum = 0.0
    if weight_specs:
        total = sum(f for _i, f in weight_specs) or 1.0
        for i, f in weight_specs:
            norm = round(f / total, 6)
            weight_sum += norm
            helper_attr = ''
            if name == 'Vulnerabilities':
                helper_attr = f' vuln_kind="{random.choice(VULN_KINDS)}"'
            elif name == 'Segmentation':
                helper_attr = f' segmentation_kind="{random.choice(SEG_KINDS)}"'
            items.append(f'<item selected="{name}Item{i+1}" factor="{norm}"{helper_attr}/>' )
        weight_sum = round(weight_sum, 6)
    derived = rng.randint(0, 5) if weight_rows > 0 else 0
    total = explicit + derived
    meta = (
        f' weight_rows="{weight_rows}" count_rows="{count_rows}" weight_sum="{weight_sum}"'
        f' explicit_count="{explicit}" derived_count="{derived}" total_planned="{total}"'
    )
    return f'<section name="{name}" density="{density}"{meta}>{"".join(items)}</section>'

def build_section_vulnerabilities(rng: random.Random):
    """Build Vulnerabilities section with richer use of vuln_kind enumeration.

    Generates a mix of weight and count rows demonstrating:
      - Random (no extra attributes)
      - Type/Vector (adds v_type / v_vector attributes)
      - Specific (adds v_name / optional v_path; count rows may include v_count)
    All weight rows are normalized to sum to 1.0 if present.
    """
    density = round(rng.uniform(0, 1), 3)
    rows = rng.randint(0, 3)
    weight_rows = 0
    count_rows = 0
    explicit = 0
    weight_specs: List[Tuple[int, float, str]] = []  # (idx, raw_factor, vuln_kind)
    items: List[str] = []
    for i in range(rows):
        is_weight = rng.random() < 0.5
        if is_weight:
            vk = rng.choice(VULN_KINDS)
            factor = round(rng.uniform(0.1, 1.0), 6)
            weight_specs.append((i, factor, vk))
            weight_rows += 1
        else:
            # count row favors Specific vuln to illustrate explicit counts
            vk = rng.choice(["Specific", "Random"]) if rng.random() < 0.7 else "Type/Vector"
            vcount = rng.randint(1, 5)
            explicit += vcount
            count_rows += 1
            if vk == "Specific":
                vname = f"CVE-2024-{rng.randint(1000,9999)}"
                vpath = f"/opt/vulns/{vname}.sh"
                items.append(f'<item selected="Specific" vuln_kind="Specific" v_name="{vname}" v_path="{vpath}" v_metric="Count" v_count="{vcount}"/>')
            elif vk == "Type/Vector":
                vtype = rng.choice(["os", "service", "app"])  # illustrative
                vvector = rng.choice(["network", "local", "remote"])
                items.append(f'<item selected="Type/Vector" vuln_kind="Type/Vector" v_type="{vtype}" v_vector="{vvector}" v_metric="Count" v_count="{vcount}"/>')
            else:  # Random
                items.append(f'<item selected="Random" vuln_kind="Random" v_metric="Count" v_count="{vcount}"/>')
    weight_sum = 0.0
    if weight_specs:
        total = sum(f for _i, f, _vk in weight_specs) or 1.0
        for i, f, vk in weight_specs:
            norm = round(f / total, 6)
            weight_sum += norm
            if vk == "Specific":
                vname = f"CVE-2025-{rng.randint(1000,9999)}"
                vpath = f"/opt/vulns/{vname}.sh"
                items.append(f'<item selected="Specific" factor="{norm}" vuln_kind="Specific" v_name="{vname}" v_path="{vpath}"/>')
            elif vk == "Type/Vector":
                vtype = rng.choice(["os", "service", "app"])  # categories
                vvector = rng.choice(["network", "local", "remote"])
                items.append(f'<item selected="Type/Vector" factor="{norm}" vuln_kind="Type/Vector" v_type="{vtype}" v_vector="{vvector}"/>')
            else:  # Random
                items.append(f'<item selected="Random" factor="{norm}" vuln_kind="Random"/>')
        weight_sum = round(weight_sum, 6)
    derived = rng.randint(0, 5) if weight_rows > 0 else 0
    total_planned = explicit + derived
    meta = (
        f' weight_rows="{weight_rows}" count_rows="{count_rows}" weight_sum="{weight_sum}"'
        f' explicit_count="{explicit}" derived_count="{derived}" total_planned="{total_planned}"'
    )
    return f'<section name="Vulnerabilities" density="{density}"{meta}>{"".join(items)}</section>'

def build_section_traffic(rng: random.Random):
    density = round(rng.uniform(0, 1), 3)
    rows = rng.randint(0, 3)
    items: List[str] = []
    weight_specs: List[Tuple[int, float, str]] = []
    for i in range(rows):
        pat = rng.choice(TRAFFIC_PATTERNS)
        factor = round(rng.uniform(0.1, 1.0), 6)
        weight_specs.append((i, factor, pat))
    if weight_specs:
        total = sum(f for _i, f, _p in weight_specs) or 1.0
        for i, f, pat in weight_specs:
            norm = round(f / total, 6)
            payload = random.choice(TRAFFIC_PAYLOAD_TYPES)
            tkind = random.choice(TRAFFIC_KINDS)
            rate = random.randint(0, 512)
            period = random.randint(1, 30)
            jitter = random.randint(0, 50)
            content_attr = ''
            # For non-random media categories we can optionally include a representative content hint (only for photo/video)
            if payload in ('photo','video') and random.random() < 0.3:
                content_attr = ' content="/opt/media/sample.bin"'
            items.append(
                f'<item selected="Generic" factor="{norm}" pattern="{pat}" rate_kbps="{rate}" '
                f'period_s="{period}" jitter_pct="{jitter}" traffic_kind="{tkind}" '
                f'content_type="{payload}"{content_attr}/>'
            )
    return f'<section name="Traffic" density="{density}">{"".join(items)}</section>'

def build_section_notes():
    return '<section name="Notes"><notes/></section>'

def build_scenario(idx: int, rng: random.Random):
    scen_name = f"Scenario {idx}"
    node_info = build_section_node_info(rng)
    routing = build_section_routing(rng)
    services = build_section_simple('Services', rng)
    vulns = build_section_vulnerabilities(rng)
    segmentation = build_section_simple('Segmentation', rng)
    traffic = build_section_traffic(rng)
    notes = build_section_notes()
    total_nodes = rng.randint(0, 200)
    scen_total_attr = f' scenario_total_nodes="{total_nodes}"'
    return f"""
  <Scenario name="{scen_name}"{scen_total_attr}>
    <ScenarioEditor>
      <BaseScenario filepath=""/>
      {node_info}
      {routing}
      {services}
      {traffic}
      {vulns}
      {segmentation}
      {notes}
    </ScenarioEditor>
  </Scenario>
""".strip()

def main():
    out_dir = Path('outputs/schema-samples')
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(90210)
    scenarios: List[str] = []
    for i in range(1, 101):
        scenarios.append(build_scenario(i, rng))
    root_doc = '<Scenarios>\n' + "\n".join(scenarios) + '\n</Scenarios>\n'
    # Also write individual files for convenience & test consumption
    for i, scen in enumerate(scenarios, start=1):
        content = f"<Scenarios>\n{scen}\n</Scenarios>\n"
        (out_dir / f'sample_{i:03d}.xml').write_text(content)
    (out_dir / 'all_scenarios.xml').write_text(root_doc)
    print(f"Wrote {len(scenarios)} individual XML files + aggregate to {out_dir}")

if __name__ == '__main__':
    main()
