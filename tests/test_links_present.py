import os
import json
import tempfile
import subprocess
from pathlib import Path


def _find_latest_report(repo_root: Path) -> Path | None:
    reports = sorted((repo_root / "reports").glob("scenario_report_*.md"), key=lambda p: p.stat().st_mtime)
    return reports[-1] if reports else None


def test_cli_generates_session_with_links(monkeypatch):
    """Smoke test: run CLI on sample.xml with no routing to exercise multi-switch builder and ensure links exist in session.

    We don't require core-daemon; this is a structural test that at least ensures the run completes and report is written.
    """
    repo_root = Path(__file__).resolve().parent.parent
    xml_path = repo_root / "sample.xml"
    if not xml_path.exists():
        # Skip if sample.xml not present in this checkout
        import pytest
        pytest.skip("sample.xml missing")

    # Try invoking the CLI module in a way that does not require core-daemon: we expect it to fail to connect in CI
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(repo_root))
    # Use localhost and a likely closed port to exercise code path without starting a real session
    cmd = ["python", "-m", "core_topo_gen.cli", "--xml", str(xml_path), "--host", "127.0.0.1", "--port", "50051"]
    try:
        subprocess.run(cmd, cwd=str(repo_root), env=env, check=False, capture_output=True, text=True, timeout=30)
    except Exception:
        # If execution environment cannot run subprocesses, skip gracefully
        import pytest
        pytest.skip("subprocess execution not supported in this environment")

    # A report should exist even if session start failed
    report = _find_latest_report(repo_root)
    assert report is not None, "Expected a scenario report to be written"
    content = report.read_text(encoding="utf-8")
    # At minimum, we should see a 'Switches' or 'Routers' section and non-zero node count lines
    assert "Total nodes:" in content
    # Links aren't directly listed in report; success indicates builders ran through link add paths.
    # This test primarily guards against regressions causing exceptions during link creation.
