# CORE Topology Generator API

This guide documents the HTTP surface exposed by the CORE Topology Generator web backend (`webapp/app_backend.py`) and the CLI entry point (`core_topo_gen.cli`). Use it to script scenario management, trigger runs, download artifacts, and integrate with external systems.

## Base Environment

- **Default base URL:** `http://localhost:9090`
- **Entry modules:**
	- Web server: `python webapp/app_backend.py`
	- CLI: `core-python -m core_topo_gen.cli` (fall back to `python -m core_topo_gen.cli` if `core-python` is unavailable)
- **Artifacts:**
	- Scenario XML snapshots: `outputs/scenarios-<timestamp>/`
	- Run history index: `outputs/run_history.json`
	- Reports: `./reports/scenario_report_<timestamp>.md`

## Authentication

The web UI uses cookie sessions. Script clients must authenticate once and reuse the cookie for subsequent requests.

1. `POST /login`
	 - Form fields: `username`, `password`
	 - Success: HTTP 302 redirect to `/` with a `session` cookie.
	 - Failure: HTTP 200 with an error message rendered in HTML.
2. `POST /logout`
	 - Clears the session and redirects to `/`.

**First run:** The app may create a default admin user. Refer to the README for the bootstrap credentials and rotate them immediately.

## Request & Response Conventions

- JSON payloads and responses are UTF-8 encoded.
- Unless noted, endpoints return `{ "ok": boolean, ... }` or redirect to HTML views.
- File parameters must be provided using `multipart/form-data`.
- Absolute paths are recommended (`os.path.abspath`). When a relative path is supplied, the server resolves it against the repo root where possible.
- Safe-delete operations only touch files under `uploads/` or `outputs/`; reports in `./reports/` are preserved.
- Planning preview results are cached in `outputs/plan_cache.json`, keyed by `(xml_hash, scenario, seed)`. Override the location with `TOPO_PLAN_CACHE_PATH`.

## Endpoint Groups

- [Health](#health)
- [Scenario Lifecycle](#scenario-lifecycle)
- [Planning Preview](#planning-preview)
- [Run Execution & Reports](#run-execution--reports)
- [Script Inspection](#script-inspection)
- [Docker Helpers](#docker-helpers)
- [CORE Session Management](#core-session-management)
- [Data Sources & Vulnerability Catalog](#data-sources--vulnerability-catalog)
- [Diagnostics & Maintenance](#diagnostics--maintenance)
- [User Administration](#user-administration)

### Health

`GET /healthz`

- Returns plain-text `OK` when the server is running.

### Scenario Lifecycle

`POST /load_xml`
: Multipart upload (`scenarios_xml` `.xml` file). Loads the file into the editor state and renders the main page.

`POST /save_xml`
: Form field `scenarios_json` (stringified JSON). Persists the editor payload to `outputs/scenarios-<timestamp>/scenarios.xml` and re-renders the editor. The saved XML includes additive planning attributes (`base_nodes`, `combined_nodes`, `explicit_count`, etc.) for lossless round-tripping.

`POST /save_xml_api`
: JSON body `{ "scenarios": [...], "active_index"?: int }`. Returns `{ "ok": true, "result_path": ".../scenarios.xml" }` on success or `{ "ok": false, "error": "..." }` with HTTP 400/500 on failure.

`GET /api/host_interfaces`
: Returns `{ "interfaces": [...] }` describing host NICs (`name`, `mac`, `ipv4`, `ipv6`, `mtu`, `speed`, `flags`, `is_up`). Requires `psutil`; if unavailable, returns an empty list with a warning in logs.

`POST /upload_base`
: Multipart upload (`base_xml`). Attaches a CORE base topology XML to the active scenario. Redirects to `/`.

`POST /remove_base`
: Optional `scenarios_json` to retain other edits while clearing the base topology. Renders the updated editor view.

`GET /base_details`
: Query `path=<abs_xml_path>`. Renders an HTML summary validating the CORE XML.

### Planning Preview

`POST /api/plan/preview_full`

Generates a deterministic planning preview without starting a CORE session.

**Request JSON**

```json
{
	"xml_path": "/abs/path/to/scenarios.xml",
	"scenario": "Scenario Name",        // optional
	"seed": 12345                        // optional; random when omitted (returned in response)
}
```

**Response JSON**

```json
{
	"ok": true,
	"full_preview": {
		"routers": [...],
		"hosts": [...],
		"switches": [...],
		"services_preview": {...},
		"vulnerabilities_preview": {...},
		"segmentation_preview": {...},
		"traffic_preview": {...},
		"seed": 12345,
		"seed_generated": false
	},
	"plan": {
		"role_counts": {"Workstation": 12, ...},
		"routers_planned": 3,
		"service_plan": {...},
		"vulnerability_plan": {...},
		"segmentation_plan": {...},
		"traffic_plan": {...}
	},
	"breakdowns": {
		"node": {...},
		"router": {...},
		"services": {...},
		"vulnerabilities": {...},
		"segmentation": {...},
		"traffic": {...}
	}
}
```

**Notes**

- `seed` is echoed or generated automatically. Store it to reproduce the same topology.
- `r2s_policy_preview.per_router_bounds` includes min/max bounds when NonUniform host grouping is requested via XML attributes (`r2s_hosts_min`/`r2s_hosts_max`).
- Exact aggregation (`r2s_mode=Exact` and `r2s_edges=1`) collapses hosts behind a single switch and ignores bounds.
- Preview responses are cached; purge `outputs/plan_cache.json` to invalidate.

### Run Execution & Reports

`POST /run_cli`
: Form field `xml_path` (absolute path). Runs the CLI synchronously with forwarded args `--xml`, `--host`, `--port`, `--verbose` (values derived from the saved XML when available). Returns the main page with logs. Side effects:

- Markdown report written to `./reports/`
- JSON summary (`scenario_report_<timestamp>.json`) next to the report with counts and metadata
- Router aggregation metrics appended when routers are generated
- Pre/post CORE session XML captured under `outputs/core-sessions/` when available
- Run history appended to `outputs/run_history.json`

`POST /run_cli_async`
: Same args as synchronous run. Returns `{ "run_id": "<uuid>" }` immediately and writes logs to `outputs/scenarios-<timestamp>/cli-<run_id>.log`.

`GET /run_status/<run_id>`
: Polling endpoint returning:

```json
{
	"done": false,
	"returncode": null,
	"report_path": null,
	"xml_path": null,
	"log_path": "outputs/.../cli-<run_id>.log",
	"scenario_xml_path": "outputs/.../scenarios.xml",
	"pre_xml_path": null,
	"full_scenario_path": null
}
```

`GET /stream/<run_id>`
: Server-Sent Events (SSE) endpoint streaming live CLI log lines for async runs.

`POST /cancel_run/<run_id>`
: Attempts to terminate a running async job.

`GET /reports`
: Renders the Reports UI.

`GET /reports_data`
: Returns `{ "history": [...], "scenarios": [...] }`, combining run metadata and known scenario files. Each history entry includes `timestamp`, `mode`, `returncode`, `scenario_xml_path`, `report_path`, `pre_xml_path`, `post_xml_path`, `full_scenario_path`, `run_id`, and parsed `scenario_names`.

`GET /download_report?path=<path>`
: Streams a report or artifact file. Accepts absolute or repo-relative paths.

`POST /reports/delete`
: JSON body `{ "run_ids": ["..."] }`. Removes matching run history entries and deletes their artifacts under `outputs/`. Reports in `./reports/` remain untouched. Responds with `{ "deleted": <count> }`.

`POST /purge_history_for_scenario`
: JSON body `{ "name": "Scenario" }`. Removes all history entries tied to the scenario name and deletes associated artifacts under `outputs/`. Returns `{ "removed": <count>, "error"?: string }`.

**Report path detection:** The backend parses the CLI log line `Scenario report written to ...`. If missing, it falls back to the most recent `./reports/scenario_report_*.md`.

### Script Inspection

`GET /api/open_scripts`
: Query params `kind=traffic|segmentation` (default `traffic`), `scope=runtime|preview` (default `runtime`). Returns `{ "ok": true, "kind": "traffic", "scope": "runtime", "path": "/tmp/traffic", "files": [...] }`.

`GET /api/open_script_file`
: Same parameters, plus `file=<filename>`. Returns `{ "content": "...", "truncated": false }` with up to 8KB per request.

`GET /api/download_scripts`
: Same parameters, responds with a ZIP archive containing the filtered scripts.

### Docker Helpers

`GET /docker/status`
: Enumerates tracked Docker assignments with compose status:

```json
{
	"items": [{
		"name": "node1",
		"compose": "docker-compose.yml",
		"exists": true,
		"pulled": false,
		"container_exists": false,
		"running": false
	}],
	"timestamp": 1733422330
}
```

`POST /docker/cleanup`
: Optional JSON body `{ "names": ["node1"] }`. Stops and removes containers via `docker stop` / `docker rm`, returning `{ "ok": true, "results": [{ "name": "node1", "stopped": true, "removed": true }] }`.

### CORE Session Management

`GET /core`
: Renders the CORE session dashboard.

`GET /core/data`
: Returns `{ "sessions": [...], "xmls": [...] }`. Sessions include gRPC metadata (id, state, node count, backing XML). XML entries list discovered CORE files and their validation status.

`POST /core/upload`
: Multipart field `xml_file`. Saves validated CORE XML under `uploads/core/`.

`POST /core/start`
: Form field `path=<abs_xml_path>`. Starts a new CORE session using the provided XML.

`POST /core/stop`
: Form field `session_id=<int>`.

`POST /core/delete`
: Form fields:
	- `session_id` (optional) to delete a running CORE session
	- `path` (optional) to remove a CORE XML under `uploads/` or `outputs/`

`GET /core/details`
: Query parameters `path=<abs_xml_path>` and/or `session_id=<int>`. Renders validation results. When only `session_id` is provided, the server exports the current session XML for inspection.

`POST /core/save_xml`
: Form field `session_id=<int>`. Saves the running session’s XML into `outputs/core-sessions/` and streams it back as a download.

`POST /core/start_session`
: Form field `session_id=<int>` to start an existing session.

`GET /core/session/<sid>`
: Convenience view for a single session.

`POST /test_core`
: Form or JSON body with `host` (string) and `port` (int). Returns `{ "ok": true }` when gRPC connectivity succeeds.

### Data Sources & Vulnerability Catalog

`GET /data_sources`
: Renders the data sources administration page.

`POST /data_sources/upload`
: Multipart field `csv_file`. Adds a new data source.

`POST /data_sources/toggle/<sid>`
: Enables or disables a data source.

`POST /data_sources/delete/<sid>`
: Removes a data source.

`POST /data_sources/refresh/<sid>`
: Refreshes a source (implementation-specific).

`GET /data_sources/download/<sid>`
: Downloads a single source as CSV.

`GET /data_sources/export_all`
: Downloads all sources in a ZIP or bundled CSV.

`GET /data_sources/edit/<sid>`
: Renders the inline CSV editor.

`POST /data_sources/save/<sid>`
: JSON body `{ "rows": [["Header", "Value"], ...] }`. Normalizes and saves the CSV, then redirects back to the editor. Malformed payloads return HTTP 400.

`GET /vuln_catalog`
: Renders the vulnerability catalog view.

`POST /vuln_compose/status`
: JSON `{ "items": [{ "Name": "Node1", "Path": "...", "compose"?: "docker-compose.yml" }] }`. Returns `{ "items": [...], "log": [...] }` with compose availability and Docker pull state.

`POST /vuln_compose/download`
: Same payload. Supports GitHub URLs (cloned via `git`) and direct download paths. Responds with `{ "items": [...], "log": [...] }` summarizing results.

`POST /vuln_compose/pull`
: Performs `docker compose pull` for each item. Requires Docker CLI access.

`POST /vuln_compose/remove`
: Runs `docker compose down --volumes --remove-orphans`, removes images, and deletes downloaded directories under `outputs/`.

### Diagnostics & Maintenance

`GET /diag/modules`
: Returns imported module metadata to help troubleshoot environment issues.

`POST /admin/cleanup_pycore`
: Removes stale `/tmp/pycore.*` directories. Response `{ "ok": true, "removed": [...], "kept": [...], "active_session_ids": [...] }`.

### User Administration

`GET /users`
: Admin-only view listing users.

`POST /users`
: Form fields `username`, `password`, `role` (`user`|`admin`, default `user`). Fails with a flash error if the username already exists.

`POST /users/delete/<username>`
: Removes the specified user (admin only).

`POST /users/password/<username>`
: Admin resets another user’s password. Form field `password` (new value).

`GET /me/password`
: Renders self-service password form.

`POST /me/password`
: Form fields `current_password`, `password`. Allows users to update their own credential.

## CLI Reference (`core_topo_gen.cli`)

Invoke from the repo root to ensure generated reports land in `./reports/`:

```bash
core-python -m core_topo_gen.cli --xml /abs/path/scenarios.xml --verbose
```

### Core Arguments

- `--xml` (required): Scenario XML path.
- `--scenario`: Scenario name (defaults to the first in the file).
- `--host`, `--port`: CORE gRPC endpoint (defaults `127.0.0.1:50051`).
- `--prefix`: IPv4 prefix for auto-assigned addresses (default `10.0.0.0/24`).
- `--ip-mode`: `private | mixed | public` (default `private`).
- `--ip-region`: `all | na | eu | apac | latam | africa | middle-east` (default `all`).
- `--max-nodes`: Hard cap on node creation.
- `--verbose`: Enables debug logging.
- `--seed`: RNG seed for deterministic randomness.
- `--layout-density`: `compact | normal | spacious` (default `normal`).
- `--router-mesh-style`: `full | ring | tree` (fallback when routing items omit `r2r_mode`).

### Traffic Overrides

- `--traffic-pattern`: `continuous | burst | periodic | poisson | ramp`
- `--traffic-rate`: Float KB/s
- `--traffic-period`: Float seconds
- `--traffic-jitter`: Float percentage (0–100)
- `--traffic-content`: `text | photo | audio | video`

### Segmentation & Allow Rules

- `--allow-src-subnet-prob`: Float 0–1 (default 0.3)
- `--allow-dst-subnet-prob`: Float 0–1 (default 0.3)
- `--nat-mode`: `SNAT | MASQUERADE` (default `SNAT`)
- `--dnat-prob`: Float 0–1 (default 0.0)
- `--seg-include-hosts`: Include hosts when deriving segmentation rules.
- `--seg-allow-docker-ports`: Ensure host INPUT chains allow docker-compose ports when default deny is applied.

### Planning Metadata Integration

- CLI automatically parses additive planning metadata via `parse_planning_metadata`. Detected values are merged into scenario metadata with a `plan_` prefix and appear in reports under **Planning Metadata (from XML)**.
- CORE host/port defaults are overridden by `core.host` and `core.port` saved in the editor payload when present.
- Extend the web backend if additional CLI flags must be surfaced to the UI.

## Routing Connectivity Example

```xml
<section name="Routing" density="0.5">
	<!-- Balanced degree distribution among density-derived routers -->
	<item selected="OSPF" factor="1" r2r_mode="Uniform" />
	<!-- Two absolute routers with NonUniform aggregation targeting five hosts per switch -->
	<item selected="BGP" v_metric="Count" v_count="2" r2r_mode="NonUniform"
				r2s_mode="aggregate" r2s_edges="5" />
</section>
```

- Density `0.5` over 12 base hosts yields 6 density routers.
- Two `Count` routers bring the total to `min(total_hosts, 6 + 2)`.
- NonUniform aggregation introduces additional layer-2 switches sized to approximately five hosts each.

## Planning Metadata Quick Reference

The web UI writes additive planning attributes onto section tags to support round-tripping and external tooling.

### Node Information Section

- `base_nodes`: Density-derived hosts.
- `additive_nodes`: Hosts from Count rows.
- `combined_nodes`: Total planned hosts (`base_nodes + additive_nodes`).
- `weight_rows` / `count_rows`: Row counts by type.
- `weight_sum`: Sum of weight factors.

### Routing & Vulnerabilities Sections

- `explicit_count`: Count-based entries with absolute values.
- `derived_count`: Density-derived totals.
- `total_planned`: `explicit_count + derived_count`.
- `weight_rows`, `count_rows`, `weight_sum`: Analogous to Node Information.

### Parsing Helper

```python
from core_topo_gen.parsers.planning_metadata import parse_planning_metadata

meta = parse_planning_metadata("outputs/scenarios-123/scenarios.xml", "Scenario 1")
print(meta["node_info"]["combined_nodes"])
```

- The legacy `core_topo_gen.parsers.xml_parser` module was removed in 2025-10; import section-specific parsers instead.
- When attributes are absent (legacy XML), parsing gracefully recomputes approximate values.

### Experimental Sections (Services / Traffic / Segmentation)

- Currently expose structural placeholders (`explicit_count`, `weight_rows`, `count_rows`, `weight_sum`).
- Derived totals may be added in future releases as semantics mature.

