import json, os, subprocess, sys, tempfile, re, pathlib, importlib, pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = [sys.executable, '-m', 'core_topo_gen.cli']

SAMPLE_XML = str(REPO_ROOT / 'sample.xml')

# Basic parity: CLI preview-full orchestrator_plan vs web (simulated) orchestrator compute_full_plan call.

def test_cli_orchestrator_preview_contains_router_plan():
    # Run CLI preview-full to get JSON
    # Skip gracefully if CORE gRPC dependency not installed in test environment
    try:
        spec = importlib.util.find_spec('core.api.grpc')
    except ValueError:
        spec = None
    if spec is None or getattr(spec, 'loader', None) is None:
        pytest.skip('core.api.grpc not fully available; skipping CLI orchestrator parity test')
    proc = subprocess.run(CLI + ['--xml', SAMPLE_XML, '--preview-full', '--scenario', 'Scenario 1'], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.strip()
    # Find JSON (may have logging); last { ... } block
    m = re.findall(r'\{[\s\S]+\}', out)
    assert m, f'No JSON object found in stdout: {out[:200]}'
    data = json.loads(m[-1])
    orch = data.get('orchestrator_plan')
    assert orch, 'orchestrator_plan missing in CLI preview-full output'
    assert 'routers_planned' in orch, 'routers_planned missing'
    assert isinstance(orch['routers_planned'], int)
    router_bd = orch.get('breakdowns', {}).get('router')
    assert router_bd and 'has_weight_based_items' in router_bd, 'router breakdown missing expected key'

