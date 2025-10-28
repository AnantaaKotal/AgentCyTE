import json, os, sys, importlib, pytest, pathlib, subprocess, re
from flask import Flask

# This test will simulate calling the orchestrator directly (Web uses same code) and compare with CLI preview.
# It skips if core.api.grpc not available (CLI import dependency).

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE_XML = str(REPO_ROOT / 'sample.xml')
CLI = [sys.executable, '-m', 'core_topo_gen.cli']

@pytest.mark.skipif(not os.path.exists(SAMPLE_XML), reason='sample.xml missing')
def test_web_cli_preview_router_count_parity():
    try:
        spec = importlib.util.find_spec('core.api.grpc')
    except ValueError:
        spec = None
    if spec is None or getattr(spec, 'loader', None) is None:
        pytest.skip('core.api.grpc not installed; skipping parity test')
    # CLI preview-full
    proc = subprocess.run(CLI + ['--xml', SAMPLE_XML, '--preview-full', '--scenario', 'Scenario 1'], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    m = re.findall(r'\{[\s\S]+\}', proc.stdout)
    assert m, 'No JSON in CLI output'
    cli_data = json.loads(m[-1])
    cli_routers = cli_data.get('plan', {}).get('routers_planned') or cli_data.get('orchestrator_plan', {}).get('routers_planned')
    # Direct orchestrator call
    from core_topo_gen.planning.orchestrator import compute_full_plan
    orch = compute_full_plan(SAMPLE_XML, scenario='Scenario 1', seed=42, include_breakdowns=True)
    assert cli_routers == orch['routers_planned'], f"router count mismatch cli={cli_routers} orch={orch['routers_planned']}"
