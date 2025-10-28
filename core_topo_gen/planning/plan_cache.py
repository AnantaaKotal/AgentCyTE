from __future__ import annotations
"""Persistent plan cache.

Stores orchestrator planning results keyed by (xml_hash, scenario, seed).
Cache file location: outputs/plan_cache.json (override with env TOPO_PLAN_CACHE_PATH).
"""
from typing import Any, Dict, Optional
import os, json, hashlib, threading, time

_lock = threading.Lock()

def _default_cache_path() -> str:
    env = os.environ.get('TOPO_PLAN_CACHE_PATH')
    if env:
        return env
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    out_dir = os.path.join(repo_root, 'outputs')
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, 'plan_cache.json')

def _load_cache(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return { 'version': 1, 'entries': {} }
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict) or 'entries' not in data:
            return { 'version': 1, 'entries': {} }
        return data
    except Exception:
        return { 'version': 1, 'entries': {} }

def _write_cache(path: str, data: Dict[str, Any]) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)

def hash_xml_file(xml_path: str) -> str:
    h = hashlib.sha256()
    with open(xml_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def try_get_cached_plan(xml_hash: str, scenario: Optional[str], seed: Optional[int]) -> Optional[Dict[str, Any]]:
    key = f"{xml_hash}:{scenario or ''}:{seed if seed is not None else ''}"
    path = _default_cache_path()
    with _lock:
        data = _load_cache(path)
        entry = data['entries'].get(key)
        if not entry:
            return None
        # Expiration optional: keep for now; could implement TTL later
        return entry.get('plan')

def save_plan_to_cache(xml_hash: str, scenario: Optional[str], seed: Optional[int], plan: Dict[str, Any]) -> None:
    key = f"{xml_hash}:{scenario or ''}:{seed if seed is not None else ''}"
    path = _default_cache_path()
    with _lock:
        data = _load_cache(path)
        data['entries'][key] = {
            'saved_at': int(time.time()),
            'plan': plan,
        }
        # Prune if too large (>50 entries)
        if len(data['entries']) > 50:
            # sort by saved_at oldest first
            items = sorted(data['entries'].items(), key=lambda kv: kv[1].get('saved_at', 0))
            for k, _ in items[:-50]:
                data['entries'].pop(k, None)
        _write_cache(path, data)
