## Scenario XML Schema (Application-Level)

This document summarizes the structure of the scenario editor XML consumed and produced by the Web UI / CLI. It complements `validation/scenarios.xsd` (machine‑readable) and focuses on semantics and authoring guidance.

### Root Elements

Two root forms are accepted:

1. `<Scenarios>` (preferred) containing one or more `<Scenario>` elements.
2. A lone `<ScenarioEditor>` root (legacy / single-scenario quick files).

### `<Scenario>` Attributes

| Attribute | Type | Purpose |
|-----------|------|---------|
| `name` | string (required) | Scenario display / selection name. |
| `scenario_total_nodes` | non-negative int (optional) | Aggregate planned nodes (hosts + routers + vulnerability explicit targets + future additive categories). Written by UI; not required for parsing. |
| `density_count` | non-negative int (optional) | Alias for base host pool (legacy). Prefer section-level attributes instead. |

### `<ScenarioEditor>`
Wraps a base scenario reference and a sequence of planning sections.

Child elements:
* `<BaseScenario filepath=""/>` (filepath may be empty or an absolute/relative path to a CORE session XML used as a base layout).
* `<section ...>` repeated for each planning domain.

### `<section>` Attributes

All sections share a common element name `<section>` and are distinguished by `name`:
`Node Information | Routing | Services | Traffic | Events | Vulnerabilities | Segmentation | Notes`

Common / legacy attributes:
| Attribute | Applies | Meaning |
|-----------|--------|---------|
| `name` | all (required) | Section discriminator. |
| `total_nodes` | Node Information (legacy) | Deprecated; historical base host pool field. Retained for backward compatibility. |
| `density` | Node Information (unused), Routing, Services, Traffic, Vulnerabilities, Segmentation | Fraction or absolute ( >1.0 ) count meaning depends on section (see README). |

Additive planning metadata (optional – written by UI for round‑trip):
| Attribute | Section(s) | Meaning |
|-----------|------------|---------|
| `base_nodes` | Node Information | Base (density) host pool before proportional distribution. |
| `additive_nodes` | Node Information | Sum of host Count rows. |
| `combined_nodes` | Node Information | `base_nodes + additive_nodes`. |
| `weight_rows` | Node Info, Routing, Vulnerabilities, Services, Traffic, Segmentation | Count of Weight (factor) rows. |
| `count_rows` | Same as above | Count of Count (absolute) rows. |
| `weight_sum` | Same as above | Raw sum of weight factors (pre-normalization). |
| `explicit_count` | Routing, Vulnerabilities (+ future) | Sum of absolute row counts. |
| `derived_count` | Routing, Vulnerabilities | Density-derived contribution. |
| `total_planned` | Routing, Vulnerabilities | `explicit_count + derived_count`. |

### `<section name="Notes">`

May contain a single `<notes/>` element (empty or with textual content as element text). No `<item>` children here.

### `<item>` Rows

Each planning row across most sections is represented as `<item/>` with a superset of attributes (XSD 1.0 limitation). Unused attributes for a section are ignored.

Core multi-section attributes:
| Attribute | Meaning |
|-----------|---------|
| `selected` | Role/protocol/type name, depends on section. |
| `factor` | Weight (non-normalized) for proportional allocation (Weight rows). |
| `v_metric` | Either `Weight` or `Count`. When `Count`, `v_count` becomes an additive absolute amount. |
| `v_count` | Absolute amount (hosts, routers, vulnerabilities, etc.) depending on section context when `v_metric="Count"`. |

Routing-specific connectivity aggregation attributes:
| Attribute | Meaning |
|-----------|---------|
| `r2r_mode` | Router-to-router (R2R) connectivity style (`Uniform | NonUniform | Exact | Min`). Fallback: global mesh style. |
| `r2r_edges` | Degree/edge target when `r2r_mode="Exact"` (per-router degree goal). |
| `r2s_mode` | Router-to-switch (R2S) host aggregation mode (`Exact | NonUniform | aggregate | ratio`). Planner currently distinguishes special Exact=1 semantics, non-exact grouped modes, and generic ratio. |
| `r2s_edges` | Target switches (Exact) or approximate hosts-per-switch (aggregate/ratio) depending on mode. |
| `r2s_hosts_min` | Lower bound for hosts per generated switch (NonUniform grouping preview & builder). |
| `r2s_hosts_max` | Upper bound for hosts per generated switch. |

Traffic attributes (subset used by planner / future extensions):
| Attribute | Meaning |
|-----------|---------|
| `pattern` | Traffic pattern (`continuous|periodic|burst|poisson|ramp`). |
| `rate_kbps` | Rate in kilobytes per second (>=0). |
| `period_s` | Period (seconds). |
| `jitter_pct` | Jitter percentage (0–100). |

Vulnerabilities attributes (mode-dependent):
| Attribute | Applies when |
|-----------|-------------|
| `v_type`, `v_vector` | `selected="Type/Vector"` |
| `v_name`, `v_path` | `selected="Specific"` |

Events attributes:
| Attribute | Meaning |
|-----------|---------|
| `script_path` | Path to event script (informational – currently not executed automatically). |

Segmentation items currently use only `selected`, `factor`, and optional Count semantics via `v_metric`/`v_count` (future extension for explicit slot counts).

### Example (Minimal Single Scenario)

```xml
<Scenarios>
  <Scenario name="Scenario 1" scenario_total_nodes="56">
    <ScenarioEditor>
      <BaseScenario filepath=""/>
      <section name="Node Information" base_nodes="50" additive_nodes="2" combined_nodes="52" weight_rows="1" count_rows="2" weight_sum="1.000">
        <item selected="Random" factor="1.000"/>
        <item selected="Random" v_metric="Count" v_count="1"/>
        <item selected="Random" v_metric="Count" v_count="1"/>
      </section>
      <section name="Routing" density="0.050" explicit_count="4" derived_count="0" total_planned="4" weight_rows="0" count_rows="1" weight_sum="0.000">
        <item selected="RIP" v_metric="Count" v_count="4" r2r_mode="NonUniform" r2s_mode="NonUniform" r2s_hosts_min="3" r2s_hosts_max="3" />
      </section>
      <section name="Services" density="0.500" />
      <section name="Traffic" density="0.500" />
      <section name="Events" density="0.500" />
      <section name="Vulnerabilities" density="0.500" />
      <section name="Segmentation" density="0.500" />
      <section name="Notes">
        <notes/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
```

### Validation

Use the provided XSD for structural validation:

```bash
python - <<'PY'
import lxml.etree as ET
schema = ET.XMLSchema(file='validation/scenarios.xsd')
doc = ET.parse('sample.xml')
schema.assertValid(doc)
print('OK')
PY
```

### Backward Compatibility

Older XML missing new attributes remains valid. The parser derives missing planning values heuristically; explicit attributes win when present.

### Forward Compatibility Guidance

If you add new per-item planning knobs, prefer optional attributes on `<item>` (keeps XSD adjustments localized). Document semantic constraints (e.g., value ranges, interactions with modes) in this file and extend `validation/scenarios.xsd` accordingly.

### Change Log (Schema Related)

| Date | Change |
|------|--------|
| 2025-09-30 | Added routing connectivity attributes (r2r_mode, r2r_edges, r2s_mode, r2s_edges, r2s_hosts_min, r2s_hosts_max) and planning metadata attributes to XSD; published this schema summary. |

---
For deeper semantics (e.g., determinism guarantees, grouping preview) see `README.md` sections on Full Preview and Router Connectivity & Switch Aggregation.
