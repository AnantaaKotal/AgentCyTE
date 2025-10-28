import json, os
from webapp.app_backend import app


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


def test_density_count_persists_roundtrip(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)
    from webapp import app_backend as backend

    def fake_outputs_dir():
        return str(tmp_path / 'outputs')

    monkeypatch.setattr(backend, '_outputs_dir', fake_outputs_dir)
    os.makedirs(fake_outputs_dir(), exist_ok=True)

    payload = {
        "scenarios": [
            {
                "name": "ScenarioPersist",
                "density_count": 17,
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                    "Routing": {"density": 0.5, "items": []},
                    "Services": {"density": 0.0, "items": []},
                    "Traffic": {"density": 0.0, "items": []},
                    "Events": {"density": 0.0, "items": []},
                    "Vulnerabilities": {"density": 0.0, "items": []},
                    "Segmentation": {"density": 0.0, "items": []}
                },
                "notes": ""
            }
        ]
    }

    # Save
    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json', headers={'Accept':'application/json'})
    assert resp.status_code == 200
    out = resp.get_json()
    xml_path = out['result_path']
    assert os.path.exists(xml_path)

    # Read back raw XML and confirm scenario-level density_count attribute
    with open(xml_path, 'r', encoding='utf-8') as f:
        txt = f.read()
    assert 'ScenarioPersist' in txt
    assert 'density_count="17"' in txt

    # Parse using core_topo_gen parser
    from core_topo_gen.parsers.node_info import parse_node_info
    density_base, weight_items, count_items, services = parse_node_info(xml_path, 'ScenarioPersist')
    assert density_base == 17
    assert weight_items == []
    assert count_items == []
    assert services == []


def test_default_density_count_is_10_when_absent(tmp_path, monkeypatch):
    client = app.test_client()
    _login(client)
    from webapp import app_backend as backend

    def fake_outputs_dir():
        return str(tmp_path / 'outputs')

    monkeypatch.setattr(backend, '_outputs_dir', fake_outputs_dir)
    os.makedirs(fake_outputs_dir(), exist_ok=True)

    payload = {
        "scenarios": [
            {
                "name": "ScenarioDefault",
                "base": {"filepath": ""},
                "sections": {
                    "Node Information": {"density": 0, "items": []},
                },
            }
        ]
    }

    resp = client.post('/save_xml_api', data=json.dumps(payload), content_type='application/json', headers={'Accept':'application/json'})
    assert resp.status_code == 200
    out = resp.get_json()
    xml_path = out['result_path']
    assert os.path.exists(xml_path)

    from core_topo_gen.parsers.node_info import parse_node_info
    density_base, *_ = parse_node_info(xml_path, 'ScenarioDefault')
    # No scenario-level or section-level density_count provided -> parser should fall back to default 10
    assert density_base == 10
