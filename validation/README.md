# CORE TopoGen Scenario XML Schemas

This folder contains schemas for XML used by this project.

- `core-xml-syntax/corexml_codebased.xsd` — upstream CORE session XML schema (used when validating CORE-native session XML).
- `scenarios.xsd` — schema for the TopoGen "Scenarios" editor XML (the application-level format built/parsed by `webapp/app_backend.py`).

## Validate Scenario XML

You can validate a generated `scenarios.xml` with `xmllint`:

```bash
xmllint --noout --schema validation/scenarios.xsd outputs/scenarios-YYYYMMDD-HHMMSS/scenarios.xml
```

The root element of the editor XML is `<Scenarios>` containing one or more `<Scenario>` elements. The editor also supports a single `<ScenarioEditor>` as the root for some tools; the XSD includes a global `ScenarioEditor` element to allow validating such documents as well.

Notes:
- Some constraints are semantic (e.g., certain attributes only used for specific sections). In XSD 1.0 these are modeled as optional attributes and are documented in the schema comments.
- Density is constrained to 0..1, item `factor` is constrained to 0..1, and typical numeric attributes are non-negative.

### Enumerated Helper Attributes (Added)

To aid downstream tooling, several optional helper attributes were introduced (all optional; absence means legacy behavior):

Traffic Section:
- `traffic_kind`: One of `Random`, `TCP`, `UDP`, `CUSTOM`. When present it SHOULD be consistent with (or a refinement of) the existing `selected` attribute. Use `CUSTOM` when a plugin or external script defines behavior beyond built‑in generators.

Vulnerabilities Section:
- `vuln_kind`: One of `Random`, `Type/Vector`, `Specific`.
	- Use `Specific` when concrete identifiers like `v_name` or `v_path` are set.
	- Use `Type/Vector` when selection is categorical via `v_type` / `v_vector` but not a single explicit vuln artifact.
	- `Random` indicates stochastic selection at runtime.

Segmentation Section:
- `segmentation_kind`: One of `Random`, `Firewall`, `NAT`, `CUSTOM` to signal rule generation strategy. `CUSTOM` may correspond to bespoke rule bundles or external policy engines.

These attributes are purely descriptive for schema-level validation and do not alter existing required semantics; runtime components may leverage them for clearer reporting or stricter linting.
