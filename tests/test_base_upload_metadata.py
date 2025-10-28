from pathlib import Path

from webapp import app_backend


def test_attach_base_upload_sets_display_name():
    sample_path = Path(__file__).resolve().parents[1] / "sample.xml"
    assert sample_path.exists(), "sample.xml fixture missing"
    payload = {
        "scenarios": [
            {
                "base": {
                    "filepath": str(sample_path),
                }
            }
        ]
    }

    app_backend._attach_base_upload(payload)

    meta = payload.get("base_upload")
    assert meta, "base_upload metadata should be attached"
    assert meta.get("path") == str(sample_path)
    assert meta.get("display_name") == "sample.xml"

    scen_base = payload["scenarios"][0].get("base", {})
    assert scen_base.get("display_name") == "sample.xml"


def test_base_upload_state_roundtrip(tmp_path, monkeypatch):
    base_xml = tmp_path / "base.xml"
    base_xml.write_text("<xml />")

    def fake_outputs_dir():
        output_dir = tmp_path / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        return str(output_dir)

    monkeypatch.setattr(app_backend, "_outputs_dir", fake_outputs_dir)
    monkeypatch.setattr(app_backend, "_validate_core_xml", lambda path: (True, []))

    app_backend._save_base_upload_state({
        "path": str(base_xml),
        "display_name": "base.xml",
        "valid": True,
    })

    payload = {"scenarios": [{"base": {}}]}
    app_backend._hydrate_base_upload_from_disk(payload)

    meta = payload.get("base_upload")
    assert meta, "base_upload metadata should hydrate from disk"
    assert meta.get("path") == str(base_xml)
    assert meta.get("display_name") == "base.xml"
    assert meta.get("exists") is True
    assert meta.get("valid") is True

    base_section = payload["scenarios"][0].get("base", {})
    assert base_section.get("filepath") == str(base_xml)
    assert base_section.get("display_name") == "base.xml"

    state_path = Path(app_backend._base_upload_state_path())
    assert state_path.exists(), "state file should be written"

    app_backend._clear_base_upload_state()
    assert not state_path.exists(), "state file should be cleared after removal"
