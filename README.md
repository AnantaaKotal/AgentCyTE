# CORE TopoGen

Generate reproducible CORE network topologies from scenario XML files using a rich Web GUI or a command-line interface.

## Table of contents
- [Highlights](#highlights)
- [Screenshots](docs/screenshots.md)
- [Quick start](#quick-start)
	- [Prerequisites](#prerequisites)
	- [Install dependencies](#install-dependencies)
	- [Launch the Web UI](#launch-the-web-ui)
	- [Run the CLI](#run-the-cli)
- [Full Preview workflow](#full-preview-workflow)
- [Feature deep dive](#feature-deep-dive)
	- [Planning semantics](#planning-semantics)
	- [Router connectivity & aggregation](#router-connectivity--aggregation)
	- [Traffic, segmentation, and services](#traffic-segmentation-and-services)
	- [Reports & artifacts](#reports--artifacts)
- [Architecture overview](#architecture-overview)
- [Troubleshooting](#troubleshooting)
- [Additional documentation](#additional-documentation)
- [Contributing](#contributing)

## Highlights
- **Single-source planning** – edit scenarios in the browser or any XML editor and reproduce results with the CLI.
- **Deterministic previews** – optional RNG seed locks in host expansion, router placement, connectivity, services, segmentation, and vulnerability assignment.
- **Live log dock** – stream run output, filter by level or text/regex, and toggle auto-follow for long runs.
- **Rich topology policies** – per-routing-item R2R meshes, R2S aggregation, host grouping bounds, and switch re-homing.
- **Artifacts on disk** – traffic scripts, segmentation rules, docker-compose definitions, Markdown reports, and JSON summaries are written to predictable locations for inspection.
- **Hardware-in-the-Loop friendly** – manage HITL attachments directly in the editor; options are constrained to existing routers/switches or provisioning a new router to keep topologies deterministic.

## Screenshots

View the WebUI images gallery [`docs/screenshots.md`](docs/screenshots.md).

## Quick start

### Prerequisites
- Python 3.10+ (3.11 recommended)
- [CORE](https://www.nrl.navy.mil/Our-Work/Areas-of-Research/CORE/) 9.2 or newer with `core-daemon` running
- Docker (optional) for nginx/envoy reverse proxy or vulnerability compose targets

### Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Launch the Web UI
```bash
python main.py
```
- Visits `http://127.0.0.1:9090` by default (reverse proxy `nginx` compose targets `https://localhost`).
- First launch seeds an `coreadmin / coreadmin` account; change it immediately under **Profile → Change Password**.
- Configure TLS reverse proxies with `make host-web`, `make host-web-nginx`, or `make host-web PROXY=envoy`. The helper script `scripts/dev_gen_certs.sh` issues self-signed certificates with SAN support.
- HITL editor note: the “Attach to” dropdown now offers `Existing Router`, `Existing Switch`, or `New Router`. The legacy `New Switch` choice was removed to prevent hidden switch fan-out; saved scenarios using it are normalized to `Existing Router` during load.

### Run the CLI
```bash
python -m core_topo_gen.cli --xml path/to/scenario.xml --seed 42 --verbose
```
Popular options:
- `--scenario NAME` pick a specific scenario entry
- `--host / --port` override the CORE gRPC endpoint (defaults `127.0.0.1:50051`)
- `--layout-density {compact|normal|spacious}` adjust map spacing
- `--seg-include-hosts`, `--seg-allow-docker-ports`, `--nat-mode`, `--dnat-prob` fine-tune segmentation
- `--traffic-pattern`, `--traffic-rate`, `--traffic-content` override traffic defaults

## Full Preview workflow
1. **Save XML** – The editor auto-saves, but hitting “Save XML” ensures consistent previews.
2. **(Optional) Set seed** – Enter an integer seed to get deterministic topology output.
3. **Generate Full Preview** – Shows router/host counts, R2R/R2S policies, segmentation, services, traffic, and vulnerability assignments before any CORE call.
4. **Review structured sections** – Toggle between structured cards and raw JSON; history stores the last 25 previews in local storage.
5. **Run (Seed)** – Launches the CLI asynchronously, streams logs into the dock, and writes a Markdown report to `./reports/`.

## Feature deep dive

### Planning semantics
- Host planning honours **Base Hosts** (density) and **Count** rows; metadata is written into XML (`base_nodes`, `additive_nodes`, `combined_nodes`, etc.) for round-trip fidelity.
- Router and vulnerability planning capture derived vs explicit counts via `explicit_count`, `derived_count`, and `total_planned`.
- Scenario-level `scenario_total_nodes` summarises planned hosts, routers, and vulnerability targets.
- Parser helpers expose metadata programmatically: `core_topo_gen.parsers.planning_metadata.parse_planning_metadata()`.
- Hardware-in-the-Loop plans persist per-scenario preferences (enabled state, interface list, attachment choice). Attachments normalize to `existing_router`, `existing_switch`, or `new_router`; legacy `new_switch` values are coerced to `existing_router` so previews remain deterministic and switch overlays aren’t synthesized implicitly.

### Router connectivity & aggregation
- Per-routing-item `r2r_mode` supports `Exact`, `Uniform`, `NonUniform`, `Min`, `Max`, and legacy meshes tied to `--router-mesh-style`.
- R2S policies (`r2s_mode`, `r2s_edges`, optional `r2s_hosts_min/max`) regroup hosts behind dedicated switches, with “Exact=1” aggregating all hosts per router into a single switch.
- Preview JSON and runtime stats capture router degrees, aggregation counts, and Gini coefficients for quick balance checks.

### Traffic, segmentation, and services
- Traffic scripts land in `/tmp/traffic` (with companion services) and respect overrides for pattern, rate, jitter, and content hints.
- Segmentation scripts land in `/tmp/segmentation` alongside a `segmentation_summary.json`; NAT mode, DNAT probability, host inclusion, and docker port allowances are configurable.
- Docker vulnerabilities attach per-node docker-compose files in `/tmp/vulns`, with metadata embedded into CORE nodes.
- Custom traffic plugins can register via `core_topo_gen.plugins.traffic.register()` for bespoke sender/receiver code.

### Reports & artifacts
- Markdown reports (`./reports/scenario_report_<timestamp>.md`) enumerate topology stats, planning metadata, segmentation results, and runtime artefacts. Each run also emits a JSON summary alongside the Markdown file (`scenario_report_<timestamp>.json`) plus per-run connectivity CSVs when router degree data is available.
- Run history is persisted in `outputs/run_history.json` for the Reports page.
- Safe deletion keeps reports while purging associated outputs under `outputs/` when scenarios are removed via the GUI.

## Architecture overview
| Folder | Purpose |
| --- | --- |
| `core_topo_gen/cli.py` | CLI entry point; orchestrates parsing, planning, building, and report generation |
| `core_topo_gen/parsers/` | Modular XML parsers per scenario section (node info, routing, traffic, services, vulnerabilities, segmentation) |
| `core_topo_gen/builders/topology.py` | Builds star, multi-switch, and segmented topologies using CORE gRPC APIs |
| `core_topo_gen/utils/` | Supporting allocators, report writers, traffic/segmentation/service helpers |
| `webapp/` | Flask Web UI, templates, SSE log streaming, history persistence |
| `webapp/templates/partials/dock.html` | Persistent logs/XML dock with follow toggle and filters |
| `tests/` | Pytest suite covering planning semantics, policy enforcement, preview parity, and CLI behaviours |
| `docs/` | Additional documentation assets (screenshots, notes) |

## Troubleshooting
- **`core-python` not found`** – set `WEBUI_PY` before `make host-web` or rely on `python3`; the backend falls back to `sys.executable` if needed.
- **Empty TLS cert folder (`nginx/certs`)** – run `scripts/dev_gen_certs.sh` or `make dev-certs` before composing nginx.
- **`core-daemon` unreachable`** – verify daemon status and host/port; GUI run modal will surface connection issues immediately.
- **Docker vulnerabilities skipped** – ensure images are downloaded/pulled via the Vulnerabilities catalog and Docker is available to the host.
- **Log dock won’t auto-scroll** – click the “Follow Off/On” toggle to re-enable auto-follow.

## Additional documentation
- [API.md](./API.md) – REST endpoints exposed by the Web UI backend
- [SCENARIO_XML_SCHEMA.md](./SCENARIO_XML_SCHEMA.md) – Schema walkthrough and examples

## Contributing
Pull requests and issue reports are welcome! Please run the relevant pytest targets (`pytest -q`) before submitting changes and keep documentation up to date when behaviour changes.