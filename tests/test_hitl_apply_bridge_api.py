import json
from typing import Dict

import pytest

from webapp import app_backend as backend

app = backend.app
app.config.setdefault('TESTING', True)


def _login(client):
    resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert resp.status_code in (302, 303)


class _FakeClient:
    def __init__(self, nodes: Dict[str, "_FakeNode"]):
        self._nodes = nodes

    def nodes(self, name: str):  # pragma: no cover - simple delegation
        return self._nodes[name]


class _FakeNode:
    def __init__(self, qemu_map: Dict[int, "_FakeQemu"]):
        self._qemu_map = qemu_map

    def qemu(self, vmid: int):  # pragma: no cover - simple delegation
        return self._qemu_map[vmid]


class _FakeQemu:
    def __init__(self, config_map: Dict[str, str], tracker):
        self._config_map = config_map
        self._tracker = tracker
        self.config = self

    def get(self):
        return dict(self._config_map)

    def post(self, **updates):
        self._tracker.append(updates)
        self._config_map.update(updates)


@pytest.fixture()
def client():
    client = app.test_client()
    _login(client)
    return client


def test_hitl_apply_bridge_updates_core_and_external(client, monkeypatch):
    posts_core = []
    posts_external = []

    fake_client = _FakeClient({
        'pve1': _FakeNode({
            101: _FakeQemu({'net0': 'virtio=de:ad:be:ef:00:01,bridge=vmbr-old'}, posts_core),
            202: _FakeQemu({'net1': 'virtio=de:ad:be:ef:02:01,firewall=1'}, posts_external),
        })
    })

    bridge_calls = []

    def fake_connect(secret_id: str):
        assert secret_id == 'secret-1'
        return fake_client, {'url': 'https://pve1.local', 'username': 'root@pam'}

    def fake_ensure(client_obj, node: str, bridge_name: str, *, comment: str | None = None):
        bridge_calls.append((node, bridge_name, comment))
        return {
            'created': False,
            'already_exists': True,
            'reload_invoked': False,
            'reload_ok': True,
            'reload_error': None,
        }

    monkeypatch.setattr(backend, '_connect_proxmox_from_secret', fake_connect)
    monkeypatch.setattr(backend, '_ensure_proxmox_bridge', fake_ensure)

    payload = {
        'bridge_name': 'Vmbr-New 42',
        'scenario_name': 'Scenario Demo',
        'scenario_index': 0,
        'bridge_owner': 'Alice',
        'hitl': {
            'proxmox': {'secret_id': 'secret-1'},
            'core': {
                'vm_key': 'pve1::101',
                'vm_name': 'CORE VM',
            },
            'interfaces': [
                {
                    'name': 'Link 1',
                    'attachment': 'proxmox_vm',
                    'proxmox_target': {
                        'node': 'pve1',
                        'vmid': 101,
                        'interface_id': 'net0',
                    },
                    'external_vm': {
                        'vm_key': 'pve1::202',
                        'vm_name': 'External VM',
                        'interface_id': 'net1',
                    },
                }
            ],
        },
    }

    resp = client.post('/api/hitl/apply_bridge', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['bridge_name'] == 'vmbr-new-4'
    assert data['changed_interfaces'] == 2
    assert data['assignments'] == 1
    assert len(posts_core) == 1 and 'net0' in posts_core[0]
    assert len(posts_external) == 1 and 'net1' in posts_external[0]
    core_config = backend._parse_proxmox_net_config(posts_core[0]['net0'])
    external_config = backend._parse_proxmox_net_config(posts_external[0]['net1'])
    assert core_config['bridge'] == 'vmbr-new-4'
    assert external_config['bridge'] == 'vmbr-new-4'
    assert bridge_calls == [
        ('pve1', 'vmbr-new-4', 'core-topo-gen HITL bridge scenario=Scenario Demo owner=Alice')
    ]
    observed_updates = {
        (item['node'], item['vmid'], tuple(sorted(item.get('interfaces', []))))
        for item in data['updated_vms']
    }
    assert observed_updates == {
        ('pve1', 101, ('net0',)),
        ('pve1', 202, ('net1',)),
    }


def test_hitl_apply_bridge_rejects_mismatched_external_node(client, monkeypatch):
    def fake_connect(*args, **kwargs):  # pragma: no cover - should not be invoked
        raise AssertionError('Proxmox connection should not be attempted on validation errors')

    monkeypatch.setattr(backend, '_connect_proxmox_from_secret', fake_connect)

    payload = {
        'bridge_name': 'vmbr-core',
        'hitl': {
            'proxmox': {'secret_id': 'secret-1'},
            'core': {
                'vm_key': 'pve1::101',
                'vm_name': 'CORE VM',
            },
            'interfaces': [
                {
                    'name': 'Link 1',
                    'attachment': 'proxmox_vm',
                    'proxmox_target': {
                        'node': 'pve1',
                        'vmid': 101,
                        'interface_id': 'net0',
                    },
                    'external_vm': {
                        'vm_key': 'pve2::202',
                        'vm_name': 'External VM',
                        'interface_id': 'net1',
                    },
                }
            ],
        },
    }

    resp = client.post('/api/hitl/apply_bridge', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert 'node pve1' in data['error']


def test_hitl_apply_bridge_errors_when_bridge_missing(client, monkeypatch):
    posts_core: list[dict] = []

    fake_client = _FakeClient({
        'pve1': _FakeNode({
            101: _FakeQemu({'net0': 'virtio=de:ad:be:ef:00:01,bridge=vmbr-old'}, posts_core),
        })
    })

    monkeypatch.setattr(backend, '_connect_proxmox_from_secret', lambda _: (fake_client, {}))

    def fake_ensure(*_args, **_kwargs):
        raise RuntimeError('Bridge vmbr-missing not available')

    monkeypatch.setattr(backend, '_ensure_proxmox_bridge', fake_ensure)

    payload = {
        'bridge_name': 'vmbr-missing',
        'hitl': {
            'proxmox': {'secret_id': 'secret-1'},
            'core': {
                'vm_key': 'pve1::101',
                'vm_name': 'CORE VM',
            },
            'interfaces': [
                {
                    'name': 'Link 1',
                    'attachment': 'proxmox_vm',
                    'proxmox_target': {
                        'node': 'pve1',
                        'vmid': 101,
                        'interface_id': 'net0',
                    },
                    'external_vm': {
                        'vm_key': 'pve1::202',
                        'interface_id': 'net1',
                    },
                }
            ],
        },
    }

    resp = client.post('/api/hitl/apply_bridge', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 502
    data = resp.get_json()
    assert data['success'] is False
    assert 'Bridge vmbr-missing not available' in data['error']


def test_hitl_apply_bridge_infers_proxmox_attachment(client, monkeypatch):
    posts = []

    fake_client = _FakeClient({
        'pve1': _FakeNode({
            101: _FakeQemu({'net0': 'virtio=ca:fe:00:00:00:01'}, posts),
            202: _FakeQemu({'net1': 'virtio=ca:fe:00:00:02:01'}, posts),
        })
    })

    monkeypatch.setattr(backend, '_connect_proxmox_from_secret', lambda _: (fake_client, {}))
    monkeypatch.setattr(backend, '_ensure_proxmox_bridge', lambda *args, **kwargs: {
        'created': False,
        'already_exists': True,
        'reload_invoked': False,
        'reload_ok': True,
        'reload_error': None,
    })

    payload = {
        'bridge_name': 'vmbr-ext',
        'hitl': {
            'proxmox': {'secret_id': 'secret-1'},
            'core': {
                'vm_key': 'pve1::101',
                'vm_name': 'CORE VM',
            },
            'interfaces': [
                {
                    'name': 'Link 1',
                    'attachment': 'existing_router',
                    'proxmox_target': {
                        'node': 'pve1',
                        'vmid': 101,
                        'interface_id': 'net0',
                    },
                    'external_vm': {
                        'vm_key': 'pve1::202',
                        'interface_id': 'net1',
                    },
                }
            ],
        },
    }

    resp = client.post('/api/hitl/apply_bridge', data=json.dumps(payload), content_type='application/json')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_normalize_internal_bridge_name_truncates_and_sanitizes():
    assert backend._normalize_internal_bridge_name('MyUserName12345') == 'myusername'
    assert backend._normalize_internal_bridge_name('user name with spaces') == 'user-name'
    assert backend._normalize_internal_bridge_name('a') == 'a'
