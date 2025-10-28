from __future__ import annotations
import os
import sys
import re
import shutil
import subprocess
import io
import json
import datetime
import time
import uuid
import threading
import csv
import logging
import zipfile
import secrets
import socket
import hashlib

from pathlib import Path
from typing import Dict, Any, Optional, List

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - psutil is optional for tests
    psutil = None  # type: ignore
from collections import defaultdict
from types import SimpleNamespace
import xml.etree.ElementTree as ET

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, Response, jsonify, session, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from lxml import etree as LET  # XML validation
ALLOWED_EXTENSIONS = {'xml'}

FULL_PREVIEW_ARTIFACT_VERSION = 2

_HITL_ATTACHMENT_ALLOWED = {
    "existing_router",
    "existing_switch",
    "new_router",
}

_DEFAULT_HITL_ATTACHMENT = "existing_router"


def _normalize_hitl_attachment(raw_value: Any) -> str:
    if isinstance(raw_value, str):
        candidate = raw_value.strip()
        if candidate in _HITL_ATTACHMENT_ALLOWED:
            return candidate
        normalized = candidate.lower().replace('-', '_').replace(' ', '_')
        if normalized in _HITL_ATTACHMENT_ALLOWED:
            return normalized
        synonyms = {
            "router": "existing_router",
            "existing": "existing_router",
            "existingrouter": "existing_router",
            "existing_router": "existing_router",
            "existing-switch": "existing_switch",
            "existing switch": "existing_switch",
            "existing_switch": "existing_switch",
            "switch": "existing_switch",
            "newrouter": "new_router",
            "new_router": "new_router",
            "new router": "new_router",
            "router_new": "new_router",
        }
        if normalized in synonyms:
            return synonyms[normalized]
    return _DEFAULT_HITL_ATTACHMENT


def _slugify_hitl_name(raw_value: Any, fallback: str) -> str:
    value = ''
    if isinstance(raw_value, str):
        value = raw_value.strip().lower()
    elif raw_value is not None:
        value = str(raw_value).strip().lower()
    if not value:
        value = fallback.lower()
    cleaned = []
    for ch in value:
        if ch.isalnum():
            cleaned.append(ch)
        elif ch in {'-', '_'}:
            cleaned.append(ch)
        else:
            cleaned.append('-')
    slug = ''.join(cleaned).strip('-_')
    if not slug:
        slug = fallback.lower().strip('-_') or 'iface'
    return slug[:48]


def _stable_hitl_preview_router_id(scenario_key: str, slug: str, idx: int) -> int:
    key = f"hitl-router|{scenario_key or '__default__'}|{slug}|{idx}"
    digest = hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()
    return 700_000 + (int(digest[:10], 16) % 200_000)


def _build_hitl_preview_router(
    scenario_key: str,
    iface: Dict[str, Any],
    slug: str,
    ordinal: int,
    ip_info: Dict[str, Any],
) -> Dict[str, Any]:
    node_id = _stable_hitl_preview_router_id(scenario_key, slug, ordinal)
    new_router_ip = ip_info.get('new_router_ip4')
    link_network = ip_info.get('network_cidr') or ip_info.get('network')
    prefix_len = ip_info.get('prefix_len')
    new_router_ip_cidr = None
    if new_router_ip:
        if prefix_len and '/' not in str(new_router_ip):
            new_router_ip_cidr = f"{new_router_ip}/{prefix_len}"
        else:
            new_router_ip_cidr = str(new_router_ip)
    r2r_interfaces: Dict[str, Any] = {}
    metadata = {
        'hitl_preview': True,
        'hitl_interface_name': iface.get('name'),
        'hitl_attachment': iface.get('attachment'),
        'hitl_slug': slug,
        'link_network': link_network,
        'rj45_ip4': ip_info.get('rj45_ip4'),
        'existing_router_ip4': ip_info.get('existing_router_ip4'),
        'new_router_ip4': new_router_ip,
        'prefix_len': ip_info.get('prefix_len'),
        'netmask': ip_info.get('netmask'),
    }
    preview_router = {
        'node_id': node_id,
        'name': f"hitl-router-{slug}",
        'role': 'router',
        'kind': 'router',
        'ip4': new_router_ip_cidr,
        'r2r_interfaces': r2r_interfaces,
        'vulnerabilities': [],
        'is_base_bridge': False,
        'metadata': metadata,
    }
    return preview_router


def _sanitize_hitl_config(hitl_config: Any, scenario_name: Optional[str], xml_basename: Optional[str]) -> Dict[str, Any]:
    def _normalize_list(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if isinstance(value, str):
            return [part.strip() for part in value.split(',') if part.strip()]
        return []

    cfg = hitl_config if isinstance(hitl_config, dict) else {}
    enabled = bool(cfg.get('enabled'))
    raw_interfaces = cfg.get('interfaces')

    if isinstance(raw_interfaces, list):
        iterable = raw_interfaces
    elif isinstance(raw_interfaces, str) and raw_interfaces.strip():
        iterable = [{'name': raw_interfaces.strip()}]
    elif isinstance(raw_interfaces, dict) and raw_interfaces.get('name'):
        iterable = [raw_interfaces]
    else:
        iterable = []

    sanitized: List[Dict[str, Any]] = []
    for entry in iterable:
        if entry is None:
            continue
        if isinstance(entry, str):
            name = entry.strip()
            if name:
                sanitized.append({'name': name, 'attachment': _DEFAULT_HITL_ATTACHMENT})
            continue
        if not isinstance(entry, dict):
            continue
        clone = dict(entry)
        name_candidate = clone.get('name') or clone.get('interface') or clone.get('iface')
        if not isinstance(name_candidate, str):
            name_candidate = str(name_candidate or '').strip()
        else:
            name_candidate = name_candidate.strip()
        if not name_candidate:
            continue
        clone['name'] = name_candidate
        alias_candidate = clone.get('alias') or clone.get('description') or clone.get('display') or clone.get('summary')
        if isinstance(alias_candidate, str) and alias_candidate.strip():
            clone['alias'] = alias_candidate.strip()
        if 'display' in clone and not clone.get('description'):
            disp_val = clone.get('display')
            if isinstance(disp_val, str) and disp_val.strip():
                clone['description'] = disp_val.strip()
        clone['attachment'] = _normalize_hitl_attachment(clone.get('attachment'))
        if 'ipv4' in clone:
            clone['ipv4'] = _normalize_list(clone.get('ipv4'))
        if 'ipv6' in clone:
            clone['ipv6'] = _normalize_list(clone.get('ipv6'))
        sanitized.append(clone)

    scenario_key = ''
    candidate = cfg.get('scenario_key')
    if isinstance(candidate, str) and candidate.strip():
        scenario_key = candidate.strip()
    elif isinstance(scenario_name, str) and scenario_name.strip():
        scenario_key = scenario_name.strip()
    elif isinstance(xml_basename, str) and xml_basename.strip():
        scenario_key = xml_basename.strip()
    else:
        scenario_key = '__default__'

    sanitized_cfg = {
        'enabled': enabled,
        'interfaces': sanitized,
        'scenario_key': scenario_key,
    }
    _enrich_hitl_interfaces_with_ips(sanitized_cfg)
    return sanitized_cfg


def _enrich_hitl_interfaces_with_ips(hitl_cfg: Dict[str, Any]) -> None:
    interfaces = hitl_cfg.get('interfaces') or []
    scenario_key = hitl_cfg.get('scenario_key') or '__default__'
    preview_routers: List[Dict[str, Any]] = []
    total_interfaces = len(interfaces)
    for idx, iface in enumerate(list(interfaces)):
        if not isinstance(iface, dict):
            continue
        attachment = _normalize_hitl_attachment(iface.get('attachment'))
        iface['attachment'] = attachment
        slug = _slugify_hitl_name(iface.get('name'), f"iface-{idx+1}")
        iface['slug'] = slug
        iface['ordinal'] = idx
        iface['interface_count'] = total_interfaces
        ip_info: Optional[Dict[str, Any]] = None
        if attachment in {'new_router', 'existing_router'}:
            ip_info = predict_hitl_link_ips(scenario_key, iface.get('name'), idx)
        if attachment in {'new_router', 'existing_router'} and ip_info:
            iface['link_network'] = ip_info.get('network')
            iface['link_network_cidr'] = ip_info.get('network_cidr') or ip_info.get('network')
            iface['prefix_len'] = ip_info.get('prefix_len')
            iface['netmask'] = ip_info.get('netmask')
            iface['existing_router_ip4'] = ip_info.get('existing_router_ip4')
            iface['new_router_ip4'] = ip_info.get('new_router_ip4')
            iface['rj45_ip4'] = ip_info.get('rj45_ip4')
            ipv4_current = iface.get('ipv4') if isinstance(iface.get('ipv4'), list) else []
            rj45_ip = iface.get('rj45_ip4')
            if rj45_ip:
                ordered = [rj45_ip] + [ip for ip in ipv4_current if ip != rj45_ip]
                iface['ipv4'] = ordered
        if attachment != 'new_router':
            continue
        if not ip_info:
            continue
        preview_router = _build_hitl_preview_router(scenario_key, iface, slug, idx, ip_info)
        preview_metadata = preview_router.setdefault('metadata', {})
        preview_metadata['scenario_key'] = scenario_key
        preview_metadata['ordinal'] = idx
        preview_metadata['interface_count'] = total_interfaces
        iface['preview_router'] = preview_router
        preview_routers.append(preview_router)
    if preview_routers:
        hitl_cfg['preview_routers'] = preview_routers


def _deterministic_hitl_peer_index(
    scenario_key: str,
    iface_name: str,
    ordinal: int,
    total_ifaces: int,
    candidate_count: int,
) -> Optional[int]:
    if candidate_count <= 0:
        return None
    total = total_ifaces if total_ifaces and total_ifaces > 0 else candidate_count
    seed = f"{scenario_key or '__default__'}|{iface_name or ordinal}|{ordinal}|{total}"
    try:
        base_digest = hashlib.sha256(seed.encode('utf-8', 'replace')).digest()
        counter_bytes = (0).to_bytes(8, 'little', signed=False)
        digest = hashlib.sha256(base_digest + counter_bytes).digest()
        value = int.from_bytes(digest[:8], 'big') / float(1 << 64)
        index = int(value * candidate_count) % candidate_count
        return index
    except Exception:
        return 0


def _wire_hitl_preview_routers(full_preview: Dict[str, Any], hitl_cfg: Dict[str, Any]) -> None:
    routers_list = full_preview.get('routers')
    if not isinstance(routers_list, list) or not routers_list:
        return
    interfaces = hitl_cfg.get('interfaces') or []
    preview_interfaces = [iface for iface in interfaces if isinstance(iface, dict) and iface.get('preview_router')]
    if not preview_interfaces:
        return
    base_routers = [router for router in routers_list if not (router.get('metadata', {}) or {}).get('hitl_preview')]
    if not base_routers:
        return
    scenario_key = hitl_cfg.get('scenario_key') or '__default__'
    total_ifaces = len(preview_interfaces)
    edges_list = full_preview.setdefault('r2r_edges_preview', [])
    existing_edge_pairs: set[tuple[int, int]] = set()
    normalized_edges: List[tuple[int, int]] = []
    for edge in list(edges_list):
        try:
            a, b = edge
            pair = tuple(sorted((int(a), int(b))))
            normalized_edges.append(pair)
            existing_edge_pairs.add(pair)
        except Exception:
            continue
    if normalized_edges:
        edges_list[:] = normalized_edges
    else:
        edges_list.clear()
    links_list = full_preview.setdefault('r2r_links_preview', [])
    existing_edge_id = max(
        (
            detail.get('edge_id', 0)
            for detail in links_list
            if isinstance(detail, dict) and isinstance(detail.get('edge_id'), int)
        ),
        default=0,
    )
    next_edge_id = existing_edge_id + 1
    degree_map = full_preview.get('r2r_degree_preview')
    if not isinstance(degree_map, dict):
        degree_map = {}
        full_preview['r2r_degree_preview'] = degree_map
    policy_preview = full_preview.get('r2r_policy_preview')
    policy_degree = None
    if isinstance(policy_preview, dict):
        policy_degree = policy_preview.setdefault('degree_sequence', {})
    router_lookup = {router.get('node_id'): router for router in routers_list if isinstance(router, dict)}
    for iface in preview_interfaces:
        preview_router = iface.get('preview_router')
        if not isinstance(preview_router, dict):
            continue
        metadata = preview_router.setdefault('metadata', {})
        if metadata.get('hitl_peer_wired'):
            continue
        new_router_id = preview_router.get('node_id')
        if new_router_id is None:
            continue
        candidate_count = len(base_routers)
        if candidate_count <= 0:
            continue
        iface_name = iface.get('name') or metadata.get('hitl_interface_name') or iface.get('slug') or f"iface-{iface.get('ordinal', 0)}"
        ordinal = iface.get('ordinal') if isinstance(iface.get('ordinal'), int) else metadata.get('ordinal') or 0
        total_count = iface.get('interface_count') if isinstance(iface.get('interface_count'), int) else metadata.get('interface_count') or total_ifaces
        peer_index = _deterministic_hitl_peer_index(
            scenario_key,
            str(iface_name),
            int(ordinal),
            int(total_count or total_ifaces or 1),
            candidate_count,
        ) or 0
        peer_router = base_routers[peer_index % candidate_count]
        peer_id = peer_router.get('node_id')
        if peer_id is None:
            continue
        prefix_len = iface.get('prefix_len') or metadata.get('prefix_len')
        new_ip = iface.get('new_router_ip4') or metadata.get('new_router_ip4')
        existing_ip = iface.get('existing_router_ip4') or metadata.get('existing_router_ip4')
        subnet = (
            iface.get('link_network_cidr')
            or metadata.get('link_network')
            or iface.get('link_network')
        )
        if subnet and prefix_len and '/' not in str(subnet):
            subnet = f"{subnet}/{prefix_len}"

        def _fmt_ip(ip: Any) -> Optional[str]:
            if not ip:
                return None
            ip_str = str(ip)
            if '/' in ip_str:
                return ip_str
            if prefix_len:
                return f"{ip_str}/{prefix_len}"
            return ip_str

        new_ip_cidr = _fmt_ip(new_ip)
        existing_ip_cidr = _fmt_ip(existing_ip)
        preview_iface_map = preview_router.setdefault('r2r_interfaces', {})
        peer_iface_map = peer_router.setdefault('r2r_interfaces', {})
        if new_ip_cidr:
            preview_iface_map[str(peer_id)] = new_ip_cidr
        else:
            preview_iface_map.setdefault(str(peer_id), '')
        if existing_ip_cidr:
            peer_iface_map[str(new_router_id)] = existing_ip_cidr
        else:
            peer_iface_map.setdefault(str(new_router_id), '')
        metadata['peer_router_node_id'] = peer_id
        metadata['peer_router_name'] = peer_router.get('name')
        metadata['hitl_peer_wired'] = True
        iface['peer_router_node_id'] = peer_id
        iface['target_router_id'] = peer_id
        layout_positions = full_preview.get('layout_positions')
        if isinstance(layout_positions, dict):
            routers_positions = layout_positions.setdefault('routers', {})
            if isinstance(routers_positions, dict):
                peer_pos = routers_positions.get(str(peer_id)) or routers_positions.get(peer_id)
                offset_x = 90 + 15 * (int(metadata.get('ordinal') or 0))
                offset_y = 60 + 10 * (int(metadata.get('ordinal') or 0))
                if isinstance(peer_pos, dict):
                    base_x = peer_pos.get('x', 0)
                    base_y = peer_pos.get('y', 0)
                else:
                    base_x = 200 + 120 * (int(metadata.get('ordinal') or 0))
                    base_y = 200 + 90 * (int(metadata.get('ordinal') or 0))
                routers_positions[str(new_router_id)] = {
                    'x': int(base_x) + offset_x,
                    'y': int(base_y) + offset_y,
                }
        edge_pair = tuple(sorted((int(peer_id), int(new_router_id))))
        if edge_pair not in existing_edge_pairs:
            existing_edge_pairs.add(edge_pair)
            edges_list.append(edge_pair)
            link_detail = {
                'edge_id': next_edge_id,
                'routers': [
                    {'id': peer_id, 'ip': existing_ip_cidr},
                    {'id': new_router_id, 'ip': new_ip_cidr},
                ],
                'subnet': subnet,
                'hitl_preview': True,
            }
            links_list.append(link_detail)
            if subnet:
                subnets_list = full_preview.setdefault('r2r_subnets', [])
                if subnet not in subnets_list:
                    subnets_list.append(subnet)
            degree_map[peer_id] = degree_map.get(peer_id, 0) + 1
            degree_map[new_router_id] = degree_map.get(new_router_id, 0) + 1
            next_edge_id += 1
            metadata['peer_router_node_id'] = peer_id
            iface['peer_router_node_id'] = peer_id
        else:
            degree_map.setdefault(peer_id, degree_map.get(peer_id, 0))
            degree_map.setdefault(new_router_id, degree_map.get(new_router_id, 0))
        if policy_degree is not None:
            policy_degree[str(peer_id)] = degree_map.get(peer_id, 0)
            policy_degree[str(new_router_id)] = degree_map.get(new_router_id, 0)
    if degree_map:
        values = [int(v) for v in degree_map.values() if isinstance(v, int)]
        if values:
            full_preview['r2r_stats_preview'] = {
                'min': min(values),
                'max': max(values),
                'avg': round(sum(values) / len(values), 2),
            }


def _augment_hitl_existing_router_interfaces(full_preview: Dict[str, Any], hitl_cfg: Dict[str, Any]) -> None:
    if not isinstance(full_preview, dict) or not isinstance(hitl_cfg, dict):
        return
    routers_list = full_preview.get('routers')
    if not isinstance(routers_list, list) or not routers_list:
        return
    interfaces = hitl_cfg.get('interfaces') or []
    existing_router_ifaces = [
        iface for iface in interfaces
        if isinstance(iface, dict) and _normalize_hitl_attachment(iface.get('attachment')) == 'existing_router'
    ]
    if not existing_router_ifaces:
        return
    base_router_entries = [
        router for router in routers_list
        if isinstance(router, dict) and not (router.get('metadata', {}) or {}).get('hitl_preview')
    ]
    if not base_router_entries:
        return
    scenario_key = hitl_cfg.get('scenario_key') or '__default__'
    total_ifaces = len(existing_router_ifaces)
    router_lookup: Dict[Any, Dict[str, Any]] = {}
    for router in routers_list:
        if not isinstance(router, dict):
            continue
        node_id = router.get('node_id')
        if node_id is not None:
            router_lookup[node_id] = router
    links_list = full_preview.setdefault('r2r_links_preview', [])
    existing_edge_id = max(
        (
            detail.get('edge_id', 0)
            for detail in links_list
            if isinstance(detail, dict) and isinstance(detail.get('edge_id'), int)
        ),
        default=0,
    )
    next_edge_id = existing_edge_id + 1
    existing_link_keys: set[tuple[Any, Any]] = set()
    for link in list(links_list):
        if not isinstance(link, dict):
            continue
        routers = link.get('routers')
        if not isinstance(routers, list) or len(routers) < 2:
            continue
        ra = routers[0].get('id') if isinstance(routers[0], dict) else None
        rb = routers[1].get('id') if isinstance(routers[1], dict) else None
        if ra is None or rb is None:
            continue
        existing_link_keys.add((ra, rb))
        existing_link_keys.add((rb, ra))
    global_overlay = full_preview.setdefault('hitl_existing_router_interfaces', [])
    overlay_keys = {
        (entry.get('router_id'), entry.get('slug'))
        for entry in global_overlay
        if isinstance(entry, dict)
    }

    def _compose_ip_with_prefix(ip_val: Any, prefix_len: Any) -> Optional[str]:
        if not ip_val:
            return None
        ip_str = str(ip_val)
        if '/' in ip_str:
            return ip_str
        if prefix_len:
            try:
                return f"{ip_str}/{int(prefix_len)}"
            except Exception:
                return f"{ip_str}/{prefix_len}"
        return ip_str

    for iface in existing_router_ifaces:
        slug = iface.get('slug')
        if not isinstance(slug, str) or not slug:
            slug = _slugify_hitl_name(iface.get('name'), f"iface-{(iface.get('ordinal') or 0) + 1}")
            iface['slug'] = slug
        ordinal = iface.get('ordinal') if isinstance(iface.get('ordinal'), int) else existing_router_ifaces.index(iface)
        total_count = iface.get('interface_count') if isinstance(iface.get('interface_count'), int) else total_ifaces
        target_router_id = iface.get('target_router_id') if iface.get('target_router_id') in router_lookup else None
        if target_router_id is None:
            if not base_router_entries:
                continue
            iface_name = iface.get('name') or slug or f"iface-{ordinal}"
            peer_index = _deterministic_hitl_peer_index(
                scenario_key,
                str(iface_name),
                int(ordinal or 0),
                int(total_count or total_ifaces or 1),
                len(base_router_entries),
            ) or 0
            chosen_router = base_router_entries[peer_index % len(base_router_entries)]
            target_router_id = chosen_router.get('node_id')
        if target_router_id is None or target_router_id not in router_lookup:
            continue
        iface['target_router_id'] = target_router_id
        iface['peer_router_node_id'] = target_router_id
        router_entry = router_lookup[target_router_id]
        prefix_len = iface.get('prefix_len')
        existing_ip_cidr = _compose_ip_with_prefix(iface.get('existing_router_ip4'), prefix_len)
        rj45_ip_cidr = _compose_ip_with_prefix(iface.get('rj45_ip4'), prefix_len)
        iface['existing_router_ip4_cidr'] = existing_ip_cidr
        iface['rj45_ip4_cidr'] = rj45_ip_cidr
        peer_key = f"hitl-rj45-{slug}"
        iface['hitl_peer_key'] = peer_key
        router_iface_map = router_entry.setdefault('r2r_interfaces', {})
        if existing_ip_cidr:
            router_iface_map[peer_key] = existing_ip_cidr
        else:
            router_iface_map.setdefault(peer_key, '')
        router_metadata = router_entry.setdefault('metadata', {})
        router_overlay_list = router_metadata.setdefault('hitl_existing_router_interfaces', [])
        router_overlay_keys = {entry.get('slug') for entry in router_overlay_list if isinstance(entry, dict)}
        overlay_entry = {
            'slug': slug,
            'interface_name': iface.get('name'),
            'router_id': target_router_id,
            'router_name': router_entry.get('name'),
            'ip': existing_ip_cidr,
            'rj45_ip': rj45_ip_cidr,
            'network': iface.get('link_network_cidr') or iface.get('link_network'),
            'hitl_preview': True,
            'hitl_attachment': 'existing_router',
            'hitl_peer_key': peer_key,
            'scenario_key': scenario_key,
        }
        if slug not in router_overlay_keys:
            router_overlay_list.append(dict(overlay_entry))
        global_key = (target_router_id, slug)
        if global_key not in overlay_keys:
            global_overlay.append(dict(overlay_entry))
            overlay_keys.add(global_key)
        link_key = (target_router_id, peer_key)
        if link_key not in existing_link_keys:
            link_detail = {
                'edge_id': next_edge_id,
                'routers': [
                    {'id': target_router_id, 'ip': existing_ip_cidr},
                    {'id': peer_key, 'ip': rj45_ip_cidr},
                ],
                'subnet': iface.get('link_network_cidr') or iface.get('link_network'),
                'hitl_preview': True,
                'hitl_attachment': 'existing_router',
                'hitl_interface_slug': slug,
            }
            links_list.append(link_detail)
            existing_link_keys.add(link_key)
            existing_link_keys.add((peer_key, target_router_id))
            next_edge_id += 1


def _merge_hitl_preview_with_full_preview(full_preview: Dict[str, Any], hitl_cfg: Dict[str, Any]) -> None:
    if not isinstance(full_preview, dict) or not isinstance(hitl_cfg, dict):
        return
    preview_routers = hitl_cfg.get('preview_routers') or []
    routers_list = full_preview.get('routers')
    if not isinstance(routers_list, list):
        routers_list = []
        full_preview['routers'] = routers_list
    existing_ids = set()
    for entry in routers_list:
        if isinstance(entry, dict):
            node_id = entry.get('node_id')
            if node_id is not None:
                existing_ids.add(node_id)
    appended_ids: List[Any] = []
    for router in preview_routers:
        if not isinstance(router, dict):
            continue
        node_id = router.get('node_id')
        if node_id in existing_ids:
            continue
        routers_list.append(router)
        existing_ids.add(node_id)
        appended_ids.append(node_id)
    if appended_ids:
        # Keep routers sorted by node_id for deterministic previews
        try:
            def _router_sort_key(entry: Any) -> tuple[int, int]:
                if not isinstance(entry, dict):
                    return (1, 0)
                node_id = entry.get('node_id')
                if isinstance(node_id, int):
                    return (0, node_id)
                sort_val = 0
                if node_id is not None:
                    try:
                        sort_val = int(str(node_id))
                    except Exception:
                        digest = hashlib.sha256(str(node_id).encode('utf-8', 'replace')).hexdigest()
                        sort_val = int(digest[:8], 16)
                return (0, sort_val)

            routers_list.sort(key=_router_sort_key)
        except Exception:
            pass
        hitl_router_ids = full_preview.get('hitl_router_ids')
        if not isinstance(hitl_router_ids, list):
            hitl_router_ids = []
            full_preview['hitl_router_ids'] = hitl_router_ids
        for node_id in appended_ids:
            hitl_router_ids.append(node_id)
        try:
            seen = set()
            deduped = []
            for nid in hitl_router_ids:
                if nid in seen:
                    continue
                seen.add(nid)
                deduped.append(nid)
            full_preview['hitl_router_ids'] = deduped
            hitl_router_ids = deduped
        except Exception:
            pass
        full_preview['hitl_router_count'] = len([nid for nid in hitl_router_ids if nid is not None])
    _wire_hitl_preview_routers(full_preview, hitl_cfg)
    _augment_hitl_existing_router_interfaces(full_preview, hitl_cfg)

"""Flask web backend for core-topo-gen.

Augmented to guarantee the in-repo version of core_topo_gen is imported
instead of any globally installed distribution so new planning modules
like planning.full_preview are always available.
"""

# Ensure repository root (parent directory) precedes any site-packages version & purge shadowed installs
try:
    _THIS_DIR = os.path.abspath(os.path.dirname(__file__))
    _REPO_ROOT = os.path.abspath(os.path.join(_THIS_DIR, '..'))
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    # Purge any pre-imported site-packages version of core_topo_gen so we always load in-repo
    import sys as _sys
    for k in list(_sys.modules.keys()):
        if k == 'core_topo_gen' or k.startswith('core_topo_gen.'):
            del _sys.modules[k]
except Exception:
    pass

try:
    from core_topo_gen.parsers.hitl import parse_hitl_info
except ModuleNotFoundError as exc:
    raise RuntimeError(
        "core_topo_gen package is not available from this context. "
        "Run webapp commands from the repository root so the in-repo package is importable."
    ) from exc

from core_topo_gen.utils.hitl import predict_hitl_link_ips

# Proactively ensure the in-repo planning.full_preview module is available even if an
# older site-packages installation of core_topo_gen (without that module) is first on sys.path.
def _ensure_full_preview_module():  # safe no-op if already present
    try:
        import importlib, sys as _sys
        try:
            # Fast path: module already importable
            import core_topo_gen.planning.full_preview  # type: ignore
            try:
                app.logger.debug('[full_preview] already importable (fast path)')
            except Exception:
                pass
            return True
        except ModuleNotFoundError:
            # Force reload planning package from repo root then load file directly
            repo_root = _REPO_ROOT
            planning_dir = os.path.join(repo_root, 'core_topo_gen', 'planning')
            candidate = os.path.join(planning_dir, 'full_preview.py')
            if not os.path.exists(candidate):
                try:
                    app.logger.error('[full_preview] candidate missing at %s', candidate)
                except Exception:
                    pass
                return False
            import importlib.util
            spec = importlib.util.spec_from_file_location('core_topo_gen.planning.full_preview', candidate)
            if not spec or not spec.loader:
                try:
                    app.logger.error('[full_preview] spec/loader missing for %s', candidate)
                except Exception:
                    pass
                return False
            module = importlib.util.module_from_spec(spec)
            _sys.modules['core_topo_gen.planning.full_preview'] = module
            try:
                spec.loader.exec_module(module)  # type: ignore
            except Exception:
                try:
                    import traceback, io as _io
                    buf = _io.StringIO(); traceback.print_exc(file=buf)
                    app.logger.error('[full_preview] exec_module failed: %s', buf.getvalue())
                except Exception:
                    pass
                return False
            # Attach as attribute of planning package for attribute-based access patterns
            try:
                import core_topo_gen.planning as planning_pkg  # type: ignore
                setattr(planning_pkg, 'full_preview', module)
            except Exception:
                pass
            try:
                app.logger.info('[full_preview] dynamically loaded from %s', candidate)
            except Exception:
                pass
            return True
    except Exception:
        return False

# Attempt early so later endpoints succeed
try:
    if not _ensure_full_preview_module():
        # Will try again lazily in the endpoint if needed
        pass
except Exception:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'coretopogenweb')
try:
    app.logger.setLevel(logging.DEBUG)
except Exception:
    pass

def _enumerate_host_interfaces(include_down: bool = False) -> List[Dict[str, Any]]:
    """Return host network interfaces available for Hardware-in-the-Loop selection."""
    results: List[Dict[str, Any]] = []
    logger = getattr(app, 'logger', logging.getLogger(__name__))
    if psutil is None:
        logger.warning('[hitl] psutil not available; host interface enumeration skipped')
        try:
            logger.warning('[hitl] psutil import failed under interpreter: %s', sys.executable)
            logger.debug('[hitl] sys.path=%s', sys.path)
            logger.debug('[hitl] PATH=%s', os.environ.get('PATH'))
            logger.debug('[hitl] PYTHONPATH=%s', os.environ.get('PYTHONPATH'))
        except Exception:
            pass
        return results
    try:
        logger.debug('[hitl] enumerating host interfaces (include_down=%s)', include_down)
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
    except Exception as exc:
        logger.error('[hitl] interface enumeration failed while retrieving stats: %s', exc, exc_info=True)
        return results

    link_families = set()
    for attr in ('AF_LINK',):
        fam = getattr(psutil, attr, None)
        if fam is not None:
            link_families.add(fam)
    for attr in ('AF_PACKET', 'AF_LINK'):
        fam = getattr(socket, attr, None)
        if fam is not None:
            link_families.add(fam)

    total_seen = 0
    skipped_down = 0
    skipped_loopback = 0
    skipped_other = 0

    for name, addr_list in addrs.items():
        total_seen += 1
        stat = stats.get(name)
        is_up = bool(getattr(stat, 'isup', False)) if stat else False
        if not include_down and not is_up:
            skipped_down += 1
            logger.debug('[hitl] skipping interface %s: interface is down', name)
            continue

        ipv4: List[str] = []
        ipv6: List[str] = []
        mac_addr: Optional[str] = None
        is_loopback = False

        for addr in addr_list:
            fam = addr.family
            if fam == socket.AF_INET:
                if addr.address:
                    ipv4.append(addr.address)
                    if addr.address.startswith('127.'):
                        is_loopback = True
            elif fam == getattr(socket, 'AF_INET6', None):
                if addr.address:
                    address = addr.address.split('%')[0]
                    ipv6.append(address)
                    if address == '::1':
                        is_loopback = True
            elif fam in link_families:
                if addr.address and addr.address != '00:00:00:00:00:00':
                    mac_addr = addr.address

        name_lc = name.lower()
        if name_lc.startswith('lo') or name == 'lo0':
            is_loopback = True

        if is_loopback:
            skipped_loopback += 1
            logger.debug('[hitl] skipping interface %s: loopback detected', name)
            continue

        entry: Dict[str, Any] = {
            'name': name,
            'display': name,
            'mac': mac_addr,
            'ipv4': ipv4,
            'ipv6': ipv6,
            'mtu': getattr(stat, 'mtu', None) if stat else None,
            'speed': getattr(stat, 'speed', None) if stat else None,
            'is_up': is_up,
        }
        flags = getattr(stat, 'flags', None)
        if isinstance(flags, str):
            entry['flags'] = [flag for flag in flags.replace(',', ' ').split() if flag]
        elif isinstance(flags, (list, tuple, set)):
            entry['flags'] = list(flags)

        results.append(entry)
        logger.debug('[hitl] captured interface %s: mac=%s ipv4=%s ipv6=%s is_up=%s',
                     name, mac_addr, ','.join(ipv4) or '-', ','.join(ipv6) or '-', is_up)

    logger.info(
        '[hitl] host interface enumeration complete: total_seen=%d exported=%d skipped_down=%d skipped_loopback=%d skipped_other=%d',
        total_seen,
        len(results),
        skipped_down,
        skipped_loopback,
        skipped_other,
    )

    results.sort(key=lambda item: item['name'])
    return results

# ----------------------- Basic Path Helpers (restored) -----------------------
def _get_repo_root() -> str:
    """Return absolute repository root (directory containing this webapp folder)."""
    try:
        return _REPO_ROOT
    except Exception:
        return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def _outputs_dir() -> str:
    d = os.path.join(_get_repo_root(), 'outputs')
    os.makedirs(d, exist_ok=True)
    return d

def _uploads_dir() -> str:
    d = os.path.join(_get_repo_root(), 'uploads')
    os.makedirs(d, exist_ok=True)
    return d

def _reports_dir() -> str:
    d = os.path.join(_get_repo_root(), 'reports')
    os.makedirs(d, exist_ok=True)
    return d


def _derive_default_seed(xml_hash: str) -> int:
    try:
        seed_val = int(xml_hash[:12], 16)
        seed_val %= (2**31 - 1)
        if seed_val <= 0:
            seed_val = 97531
        return seed_val
    except Exception:
        return 1357911

# Additional helper dirs (stubs restored after accidental removal)
def _traffic_dir() -> str:
    d = os.path.join(_outputs_dir(), 'traffic')
    os.makedirs(d, exist_ok=True)
    return d

def _segmentation_dir() -> str:
    d = os.path.join(_outputs_dir(), 'segmentation')
    os.makedirs(d, exist_ok=True)
    return d

def _vuln_base_dir() -> str:
    d = os.path.join(_outputs_dir(), 'vulns')
    os.makedirs(d, exist_ok=True)
    return d

def _vuln_repo_subdir() -> str:
    return 'repo'

# ---------------- User persistence helpers (restored) ----------------
def _users_db_path() -> str:
    base = os.path.join(_outputs_dir(), 'users')
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, 'users.json')


def _base_upload_state_path() -> str:
    return os.path.join(_outputs_dir(), 'base_upload.json')


def _sanitize_base_upload_meta(meta: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(meta, dict):
        return None
    out: Dict[str, Any] = {}
    path = meta.get('path') or meta.get('filepath')
    if isinstance(path, str) and path:
        out['path'] = path
    display = meta.get('display_name') or meta.get('name')
    if isinstance(display, str) and display:
        out['display_name'] = display
    if 'valid' in meta:
        out['valid'] = bool(meta.get('valid'))
    if 'exists' in meta:
        out['exists'] = bool(meta.get('exists'))
    if not out.get('path'):
        return None
    return out


def _load_base_upload_state() -> Optional[Dict[str, Any]]:
    path = _base_upload_state_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return _sanitize_base_upload_meta(data)
    except Exception:
        return None


def _save_base_upload_state(meta: Dict[str, Any]) -> None:
    clean = _sanitize_base_upload_meta(meta)
    if not clean:
        return
    clean = dict(clean)
    clean['updated_at'] = datetime.datetime.now(datetime.UTC).isoformat()
    try:
        with open(_base_upload_state_path(), 'w', encoding='utf-8') as f:
            json.dump(clean, f, indent=2)
    except Exception:
        pass


def _clear_base_upload_state() -> None:
    path = _base_upload_state_path()
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def _hydrate_base_upload_from_disk(payload: Dict[str, Any]) -> None:
    if payload.get('base_upload'):
        return
    meta = _load_base_upload_state()
    if not meta:
        return
    meta = dict(meta)
    path = meta.get('path') or ''
    exists = bool(path) and os.path.exists(path)
    meta['exists'] = exists
    if path and exists:
        ok, _errs = _validate_core_xml(path)
        meta['valid'] = bool(ok)
        if 'display_name' not in meta or not meta['display_name']:
            meta['display_name'] = os.path.basename(path)
    payload['base_upload'] = meta
    scen_list = payload.get('scenarios') or []
    if scen_list and isinstance(scen_list[0], dict):
        base_section = scen_list[0].setdefault('base', {})
        if path and not base_section.get('filepath'):
            base_section['filepath'] = path
        display = meta.get('display_name')
        if display and not base_section.get('display_name'):
            base_section['display_name'] = display

def _load_users() -> dict:
    p = _users_db_path()
    if not os.path.exists(p):
        return { 'users': [] }
    try:
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get('users'), list):
                return data
    except Exception:
        pass
    return { 'users': [] }

def _save_users(data: dict) -> None:
    p = _users_db_path(); tmp = p + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, p)
    except Exception:
        try:
            if os.path.exists(tmp): os.remove(tmp)
        except Exception: pass

def _ensure_admin_user() -> None:
    db = _load_users(); users = db.get('users', [])
    if not users:
        users = [{ 'username': 'coreadmin', 'password_hash': generate_password_hash('coreadmin'), 'role': 'admin' }]
        db['users'] = users; _save_users(db)
        try: app.logger.warning("Seeded default admin user 'coreadmin' / 'coreadmin'. Change immediately.")
        except Exception: pass
        return
    if not any(u.get('role') == 'admin' for u in users):
        import secrets as _secrets
        pwd = os.environ.get('ADMIN_PASSWORD') or _secrets.token_urlsafe(10)
        users.append({ 'username': 'admin', 'password_hash': generate_password_hash(pwd), 'role': 'admin' })
        db['users'] = users; _save_users(db)
        try: app.logger.warning("No admin found; created 'admin' user with generated password: %s", pwd)
        except Exception: pass

_ensure_admin_user()

# Diagnostic endpoint for environment/module troubleshooting
@app.route('/diag/modules')
def diag_modules():
    out = {}
    # core_topo_gen package file
    try:
        import core_topo_gen as ctg  # type: ignore
        out['core_topo_gen.__file__'] = getattr(ctg, '__file__', None)
    except Exception as e:
        out['core_topo_gen_error'] = str(e)
    # planning package
    try:
        import core_topo_gen.planning as plan_pkg  # type: ignore
        planning_file = getattr(plan_pkg, '__file__', None)
        out['planning_dir'] = os.path.dirname(planning_file) if planning_file else None
        if not planning_file:
            out['planning_file_is_none'] = True
    except Exception as e:
        out['planning_import_error'] = str(e)

def _current_user() -> dict | None:
    user = session.get('user')
    if isinstance(user, dict) and user.get('username'):
        return user
    return None


def _set_current_user(user: dict | None) -> None:
    if user:
        session['user'] = {
            'username': user.get('username'),
            'role': user.get('role', 'user')
        }
    else:
        session.pop('user', None)


@app.before_request
def _inject_current_user() -> None:
    try:
        g.current_user = _current_user()
    except Exception:
        g.current_user = None


@app.context_processor
def _inject_template_user() -> dict:
    try:
        user = _current_user()
        if user:
            return {
                'current_user': SimpleNamespace(
                    username=user.get('username'),
                    role=user.get('role', 'user'),
                    is_authenticated=True,
                )
            }
    except Exception:
        pass
    return {
        'current_user': SimpleNamespace(
            username=None,
            role=None,
            is_authenticated=False,
        )
    }


_LOGIN_EXEMPT_ENDPOINTS = {
    'login',
    'static',
    'healthz',
}


@app.before_request
def _require_login_redirect() -> None | Response:
    try:
        endpoint = request.endpoint or ''
        if not endpoint:
            return None
        if endpoint.startswith('static'):
            return None
        if endpoint in _LOGIN_EXEMPT_ENDPOINTS:
            return None
        if _current_user() is None:
            return redirect(url_for('login'))
    except Exception:
        return None
    return None


def _require_admin() -> bool:
    user = _current_user()
    if user and (user.get('role') == 'admin'):
        return True
    flash('Admin privileges required')
    return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    if not username or not password:
        flash('Username and password required')
        return render_template('login.html', error=True), 400
    db = _load_users()
    users = db.get('users', [])
    user = next((u for u in users if u.get('username') == username), None)
    if user and check_password_hash(user.get('password_hash', ''), password):
        _set_current_user({'username': user.get('username'), 'role': user.get('role', 'user')})
        session.permanent = True
        return redirect(url_for('index'))
    flash('Invalid username or password')
    return render_template('login.html', error=True), 401


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    _set_current_user(None)
    return redirect(url_for('login'))


@app.route('/users', methods=['GET'])
def users_page():
    if not _require_admin():
        return redirect(url_for('index'))
    db = _load_users()
    users = db.get('users', [])
    return render_template('users.html', users=users, self_change=False)


@app.route('/users', methods=['POST'])
def users_create():
    if not _require_admin():
        return redirect(url_for('index'))
    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()
    role = (request.form.get('role') or 'user').strip() or 'user'
    if not username or not password:
        flash('Username and password required')
        return redirect(url_for('users_page'))
    db = _load_users()
    users = db.get('users', [])
    if any(u.get('username') == username for u in users):
        flash('Username already exists')
        return redirect(url_for('users_page'))
    users.append({
        'username': username,
        'password_hash': generate_password_hash(password),
        'role': role
    })
    db['users'] = users
    _save_users(db)
    flash('User created')
    return redirect(url_for('users_page'))


@app.route('/users/delete/<username>', methods=['POST'])
def users_delete(username: str):
    if not _require_admin():
        return redirect(url_for('users_page'))
    username = (username or '').strip()
    if not username:
        flash('Invalid username')
        return redirect(url_for('users_page'))
    cur = _current_user()
    db = _load_users()
    users = db.get('users', [])
    remain = [u for u in users if u.get('username') != username]
    if cur and username == cur.get('username'):
        flash('Cannot delete your own account')
        return redirect(url_for('users_page'))
    if not any(u.get('role') == 'admin' for u in remain):
        flash('At least one admin must remain')
        return redirect(url_for('users_page'))
    db['users'] = remain
    _save_users(db)
    flash('User deleted')
    return redirect(url_for('users_page'))


@app.route('/users/password/<username>', methods=['POST'])
def users_password(username: str):
    if not _require_admin():
        return redirect(url_for('users_page'))
    new_pwd = request.form.get('password') or ''
    if not new_pwd:
        flash('New password required')
        return redirect(url_for('users_page'))
    db = _load_users()
    changed = False
    for u in db.get('users', []):
        if u.get('username') == username:
            u['password_hash'] = generate_password_hash(new_pwd)
            changed = True
            break
    if changed:
        _save_users(db)
        flash('Password updated')
    else:
        flash('User not found')
    return redirect(url_for('users_page'))


@app.route('/me/password', methods=['GET', 'POST'])
def me_password():
    if _current_user() is None:
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('users.html', self_change=True)
    cur = _current_user()
    cur_pwd = request.form.get('current_password') or ''
    new_pwd = request.form.get('password') or ''
    if not cur_pwd or not new_pwd:
        flash('Current and new passwords required')
        return redirect(url_for('me_password'))
    db = _load_users()
    updated = False
    for u in db.get('users', []):
        if u.get('username') == cur.get('username'):
            if not check_password_hash(u.get('password_hash', ''), cur_pwd):
                flash('Current password incorrect')
                return redirect(url_for('me_password'))
            u['password_hash'] = generate_password_hash(new_pwd)
            updated = True
            break
    if updated:
        _save_users(db)
        flash('Password changed')
    else:
        flash('User not found')
    return redirect(url_for('index'))


@app.route('/healthz')
def healthz():
    return Response('ok', mimetype='text/plain')


# Environment-configurable CORE daemon location (useful inside Docker)
CORE_HOST = os.environ.get('CORE_HOST', 'localhost')
try:
    CORE_PORT = int(os.environ.get('CORE_PORT', '50051'))
except Exception:
    CORE_PORT = 50051

def _default_core_dict():
    return {"host": CORE_HOST, "port": CORE_PORT}


def _select_python_interpreter() -> str:
    """Select the python interpreter to invoke the core_topo_gen CLI.

    Priority order:
    1. Explicit environment override CORE_PY (if it points to an existing file or is resolvable in PATH)
    2. 'core-python' if found in PATH (common when CORE provides a renamed interpreter)
    3. 'python3' if found
    4. 'python' if found
    5. sys.executable as final fallback

    Returns the chosen executable string (absolute path or name)."""
    override = os.environ.get('CORE_PY')
    candidates: list[str] = []
    if override:
        # If override is an absolute path and exists, short-circuit
        if os.path.isabs(override) and os.path.exists(override):
            return override
        # Otherwise treat as a command name to resolve later; put at front
        candidates.append(override)
    # Standard discovery chain
    candidates.extend(['core-python', 'python3', 'python'])
    for c in candidates:
        try:
            path = shutil.which(c)
            if path:
                return path
        except Exception:
            continue
    # Fallback to current process executable
    return sys.executable or 'python'

def _get_cli_script_path() -> str:
    """Return absolute path to config2scen_core_grpc.py script."""
    return os.path.join(_get_repo_root(), 'config2scen_core_grpc.py')

# Now that helpers can resolve repo root, configure upload folder
UPLOAD_FOLDER = _uploads_dir()
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER = _uploads_dir()
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# In-memory registry for async runs
RUNS: Dict[str, Dict[str, Any]] = {}

# Run history persistence (simple JSON log)
RUN_HISTORY_PATH = os.path.join(_outputs_dir(), 'run_history.json')

def _load_run_history():
    try:
        if os.path.exists(RUN_HISTORY_PATH):
            with open(RUN_HISTORY_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _append_run_history(entry: dict):
    history = _load_run_history()
    history.append(entry)
    os.makedirs(os.path.dirname(RUN_HISTORY_PATH), exist_ok=True)
    tmp = RUN_HISTORY_PATH + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
        os.replace(tmp, RUN_HISTORY_PATH)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


## Full preview is the sole planning interface.



def _find_latest_report_path() -> str | None:
    """Find the most recent scenario_report_*.md under repo_root/reports."""
    try:
        base = _reports_dir()
        if not os.path.isdir(base):
            return None
        cands = []
        for name in os.listdir(base):
            if not name.startswith('scenario_report_') or not name.endswith('.md'):
                continue
            p = os.path.join(base, name)
            try:
                st = os.stat(p)
                cands.append((st.st_mtime, p))
            except Exception:
                continue
        if not cands:
            return None
        cands.sort(key=lambda x: x[0], reverse=True)
        return cands[0][1]
    except Exception:
        return None

def _scenario_names_from_xml(xml_path: str) -> list[str]:
    names: list[str] = []
    try:
        if not xml_path or not os.path.exists(xml_path):
            return names
        data = _parse_scenarios_xml(xml_path)
        for scen in data.get('scenarios', []):
            nm = scen.get('name')
            if nm and nm not in names:
                names.append(nm)
    except Exception:
        pass
    return names

def _extract_report_path_from_text(text: str) -> str | None:
    """Parse CLI output to extract a generated report path.

    The modern CLI (core_topo_gen.cli) logs a line like:
        "Scenario report written to /abs/path/reports/scenario_report_<ts>.md"
    """
    if not text:
        return None
    m = re.search(r"Scenario report written to\s+(.+)", text)
    if m:
        path = m.group(1).strip()
        # Trim trailing punctuation if any
        path = path.rstrip(' .')
        # Make absolute if not already
        if not os.path.isabs(path):
            repo_root = _get_repo_root()
            path = os.path.abspath(os.path.join(repo_root, path))
        if os.path.exists(path):
            return path
    return None

def _find_latest_report_path(since_ts: float | None = None) -> str | None:
    """Find the most recent scenario_report_*.md under the repo reports directory.

    If since_ts is provided (epoch seconds), prefer files modified after this time.
    """
    try:
        report_dir = _reports_dir()
        if not os.path.isdir(report_dir):
            return None
        cands = []
        for name in os.listdir(report_dir):
            if not name.endswith('.md'):
                continue
            if not name.startswith('scenario_report_'):
                continue
            p = os.path.join(report_dir, name)
            try:
                st = os.stat(p)
                if since_ts is None or st.st_mtime >= max(0.0, float(since_ts) - 5.0):
                    cands.append((st.st_mtime, p))
            except Exception:
                continue
        if not cands:
            return None
        cands.sort(key=lambda x: x[0], reverse=True)
        return cands[0][1]
    except Exception:
        return None


def _derive_summary_from_report(report_path: str | None) -> str | None:
    try:
        if not report_path:
            return None
        candidate = os.path.splitext(report_path)[0] + '.json'
        if os.path.exists(candidate):
            return candidate
    except Exception:
        pass
    return None


def _extract_summary_path_from_text(text: str) -> str | None:
    """Parse CLI output to extract a generated JSON summary path."""
    if not text:
        return None
    try:
        m = re.search(r"Scenario summary written to\s+(.+)", text)
        if m:
            path = m.group(1).strip().rstrip(' .')
            if not os.path.isabs(path):
                repo_root = _get_repo_root()
                path = os.path.abspath(os.path.join(repo_root, path))
            if os.path.exists(path):
                return path
    except Exception:
        pass
    return None


def _find_latest_summary_path(since_ts: float | None = None) -> str | None:
    try:
        report_dir = _reports_dir()
        if not os.path.isdir(report_dir):
            return None
        cands = []
        for name in os.listdir(report_dir):
            if not name.endswith('.json'):
                continue
            if not name.startswith('scenario_report_'):
                continue
            p = os.path.join(report_dir, name)
            try:
                st = os.stat(p)
                if since_ts is None or st.st_mtime >= max(0.0, float(since_ts) - 5.0):
                    cands.append((st.st_mtime, p))
            except Exception:
                continue
        if not cands:
            return None
        cands.sort(key=lambda x: x[0], reverse=True)
        return cands[0][1]
    except Exception:
        return None

def _extract_session_id_from_text(text: str) -> str | None:
    """Parse CLI logs for the session id marker emitted by core_topo_gen.cli.

    Expected line:
        CORE_SESSION_ID: <id>
    """
    try:
        if not text:
            return None
        m = re.search(r"CORE_SESSION_ID:\s*(\S+)", text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def _safe_add_to_zip(zf: zipfile.ZipFile, abs_path: str, arcname: str) -> None:
    try:
        if abs_path and os.path.exists(abs_path):
            zf.write(abs_path, arcname)
    except Exception:
        pass

def _gather_scripts_into_zip(zf: zipfile.ZipFile, scenario_dir: str | None = None) -> int:
    """Collect generated traffic and segmentation artifacts into the provided zip file.

    This now walks both persistent output directories and the runtime `/tmp`
    locations used by the CLI so that *all* generated scripts and supporting
    files (JSON summaries, helper assets, custom plugin payloads, etc.) are
    included in the bundle. Returns the count of files added.
    """
    added = 0
    seen: set[str] = set()

    def _collect(label: str, dir_candidates: list[str]) -> None:
        nonlocal added
        for base in dir_candidates:
            if not base:
                continue
            try:
                base_abs = os.path.abspath(base)
            except Exception:
                base_abs = base
            if not base_abs or not os.path.isdir(base_abs):
                continue
            for root, dirs, files in os.walk(base_abs):
                # Skip hidden directories to avoid noise like .cache/.DS_Store
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for fname in files:
                    if fname.startswith('.'):
                        continue
                    try:
                        path = os.path.join(root, fname)
                        if not os.path.isfile(path) or os.path.islink(path):
                            continue
                        rel = os.path.relpath(path, base_abs)
                        # Defensive: ignore paths that navigate upwards
                        if rel.startswith('..'):
                            continue
                        rel = rel.replace('\\', '/')
                        arcname = f"{label}/{rel}".lstrip('/')
                        key = arcname.lower()
                        if key in seen:
                            continue
                        _safe_add_to_zip(zf, path, arcname)
                        seen.add(key)
                        added += 1
                    except Exception:
                        continue

    traffic_dirs = []
    try:
        traffic_dirs.append(_traffic_dir())
    except Exception:
        pass
    # Runtime traffic scripts live under /tmp/traffic by default
    traffic_dirs.extend(filter(None, [
        os.path.join(_outputs_dir(), 'traffic'),
        '/tmp/traffic',
        os.path.join(scenario_dir, 'traffic') if scenario_dir else None,
    ]))
    # Preserve order but drop duplicates
    traffic_dirs = list(dict.fromkeys(traffic_dirs))

    segmentation_dirs = []
    try:
        segmentation_dirs.append(_segmentation_dir())
    except Exception:
        pass
    segmentation_dirs.extend(filter(None, [
        os.path.join(_outputs_dir(), 'segmentation'),
        '/tmp/segmentation',
        os.path.join(scenario_dir, 'segmentation') if scenario_dir else None,
    ]))
    segmentation_dirs = list(dict.fromkeys(segmentation_dirs))

    _collect('traffic', traffic_dirs)
    _collect('segmentation', segmentation_dirs)
    return added

def _normalize_core_device_types(xml_path: str) -> None:
    """Normalize device 'type' attributes in a saved CORE session XML.

    - Docker/podman devices (class='docker'/'podman' or with compose attrs) -> type='docker'
    - Devices with routing services (zebra/BGP/OSPF*/RIP*/Xpimd) -> type='router'
    - Otherwise -> type='PC'
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        devices = root.find('devices')
        if devices is None:
            return
        routing_like = {"zebra", "BGP", "Babel", "OSPFv2", "OSPFv3", "OSPFv3MDR", "RIP", "RIPNG", "Xpimd"}
        changed = False
        for dev in list(devices):
            if not isinstance(dev.tag, str) or dev.tag != 'device':
                continue
            clazz = (dev.get('class') or '').strip().lower()
            compose = (dev.get('compose') or '').strip()
            compose_name = (dev.get('compose_name') or '').strip()
            dtype = dev.get('type') or ''
            # collect services
            svc_names = set()
            try:
                services_el = dev.find('services') or dev.find('configservices')
                if services_el is not None:
                    for s in list(services_el):
                        nm = s.get('name')
                        if nm:
                            svc_names.add(nm)
            except Exception:
                pass
            new_type = None
            if clazz in ('docker', 'podman') or compose or compose_name:
                new_type = 'docker'
            elif any(s in routing_like for s in svc_names):
                new_type = 'router'
            else:
                new_type = 'PC'
            if new_type and new_type != dtype:
                dev.set('type', new_type)
                changed = True
        if changed:
            try:
                raw = ET.tostring(root, encoding='utf-8')
                lroot = LET.fromstring(raw)
                pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
                with open(xml_path, 'wb') as f:
                    f.write(pretty)
            except Exception:
                tree.write(xml_path, encoding='utf-8', xml_declaration=True)
    except Exception:
        pass

def _write_single_scenario_xml(src_xml_path: str, scenario_name: str | None, out_dir: str | None = None) -> str | None:
    """Create a new XML file containing only the selected Scenario from a Scenarios XML.

    - If `scenario_name` is None, selects the first Scenario present.
    - Returns the path to the new XML written under `out_dir` (or next to the source file) or None on failure.
    """
    try:
        if not (src_xml_path and os.path.exists(src_xml_path)):
            return None
        tree = ET.parse(src_xml_path)
        root = tree.getroot()
        # Normalize: if file is a single ScenarioEditor root, just copy it under Scenarios/Scenario
        chosen_se = None
        chosen_name = scenario_name
        if root.tag == 'Scenarios':
            # find Scenario child with matching name, else use first
            scenarios = [c for c in list(root) if isinstance(c.tag, str) and c.tag == 'Scenario']
            target = None
            if chosen_name:
                for s in scenarios:
                    if (s.get('name') or '') == chosen_name:
                        target = s
                        break
            if target is None and scenarios:
                target = scenarios[0]
                chosen_name = target.get('name') or 'Scenario'
            if target is None:
                return None
            se = target.find('ScenarioEditor')
            if se is None:
                # allow copying entire Scenario element if no ScenarioEditor child
                chosen_se = target
            else:
                chosen_se = se
        elif root.tag == 'ScenarioEditor':
            chosen_se = root
            if not chosen_name:
                # attempt to infer from nested metadata (not guaranteed)
                chosen_name = 'Scenario'
        else:
            # if root is Scenario, accept it
            if root.tag == 'Scenario':
                chosen_se = root.find('ScenarioEditor') or root
                chosen_name = chosen_name or (root.get('name') or 'Scenario')
            else:
                return None
        # Build new XML
        new_root = ET.Element('Scenarios')
        scen_el = ET.SubElement(new_root, 'Scenario')
        scen_el.set('name', chosen_name or 'Scenario')
        if chosen_se.tag == 'ScenarioEditor':
            # deep copy ScenarioEditor
            scen_el.append(ET.fromstring(ET.tostring(chosen_se)))
        else:
            # chosen_se was Scenario; append its contents
            scen_el.append(ET.fromstring(ET.tostring(chosen_se.find('ScenarioEditor'))) if chosen_se.find('ScenarioEditor') is not None else ET.Element('ScenarioEditor'))
        new_tree = ET.ElementTree(new_root)
        # Determine output path
        base_dir = out_dir or os.path.dirname(os.path.abspath(src_xml_path))
        os.makedirs(base_dir, exist_ok=True)
        stem = secure_filename((chosen_name or 'scenario')).strip('_-.') or 'scenario'
        out_path = os.path.join(base_dir, f"{stem}.xml")
        try:
            raw = ET.tostring(new_tree.getroot(), encoding='utf-8')
            lroot = LET.fromstring(raw)
            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
            with open(out_path, 'wb') as f:
                f.write(pretty)
        except Exception:
            new_tree.write(out_path, encoding='utf-8', xml_declaration=True)
        return out_path if os.path.exists(out_path) else None
    except Exception:
        return None

def _build_full_scenario_archive(out_dir: str, scenario_xml_path: str | None, report_path: str | None, pre_xml_path: str | None, post_xml_path: str | None, *, summary_path: str | None = None, run_id: str | None = None) -> str | None:
    """Create a zip bundle that includes the scenario XML, pre/post session XML, report, and any generated scripts.

    Returns the path to the created zip, or None on failure.
    """
    try:
        os.makedirs(out_dir, exist_ok=True)
        stem = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        if run_id:
            stem = f"{stem}-{run_id[:8]}"
        zip_path = os.path.join(out_dir, f"full_scenario_{stem}.zip")
        scenario_dir = os.path.dirname(os.path.abspath(scenario_xml_path)) if scenario_xml_path else None
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            # Add top-level artifacts if present
            if scenario_xml_path and os.path.exists(scenario_xml_path):
                _safe_add_to_zip(zf, scenario_xml_path, "scenario.xml")
            if report_path and os.path.exists(report_path):
                _safe_add_to_zip(zf, report_path, os.path.join("report", os.path.basename(report_path)))
            if summary_path and os.path.exists(summary_path):
                _safe_add_to_zip(zf, summary_path, os.path.join("report", os.path.basename(summary_path)))
            csv_candidate = f"{report_path}.connectivity.csv" if report_path else None
            if csv_candidate and os.path.exists(csv_candidate):
                _safe_add_to_zip(zf, csv_candidate, os.path.join("report", os.path.basename(csv_candidate)))
            if pre_xml_path and os.path.exists(pre_xml_path):
                _safe_add_to_zip(zf, pre_xml_path, os.path.join("core-session", os.path.basename(pre_xml_path)))
            if post_xml_path and os.path.exists(post_xml_path):
                _safe_add_to_zip(zf, post_xml_path, os.path.join("core-session", os.path.basename(post_xml_path)))
            # Add generated scripts and summaries
            _gather_scripts_into_zip(zf, scenario_dir)
        return zip_path if os.path.exists(zip_path) else None
    except Exception:
        return None

# Data sources state
DATA_SOURCES_DIR = os.path.abspath(os.path.join('..', 'data_sources'))
DATA_STATE_PATH = os.path.join(DATA_SOURCES_DIR, '_state.json')
os.makedirs(DATA_SOURCES_DIR, exist_ok=True)

def _load_data_sources_state():
    try:
        if not os.path.exists(DATA_STATE_PATH):
            return {"sources": []}
        with open(DATA_STATE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Legacy format
        if isinstance(data, dict) and 'enabled' in data and 'sources' not in data:
            return {"sources": []}
        if 'sources' not in data:
            data['sources'] = []
        return data
    except Exception:
        return {"sources": []}

def _save_data_sources_state(state):
    tmp = DATA_STATE_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, DATA_STATE_PATH)

def _validate_csv(file_path: str, max_bytes: int = 2_000_000):
    try:
        st = os.stat(file_path)
        if st.st_size > max_bytes:
            return False, f"File too large (> {max_bytes} bytes)"
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            rows = []
            for i, row in enumerate(reader):
                if i > 10000:
                    break
                rows.append(row)
        if len(rows) < 2:
            return False, "CSV must have header + at least one data row"
        widths = {len(r) for r in rows}
        if len(widths) != 1:
            return False, "Inconsistent column counts"
        return True, f"{len(rows)-1} rows"
    except Exception as e:
        return False, str(e)

# --- Data Source CSV schema enforcement ---
REQUIRED_DS_COLUMNS = ["Name", "Path", "Type", "Startup", "Vector"]
OPTIONAL_DS_DEFAULTS = {
    "CVE": "n/a",
    "Description": "n/a",
    "References": "n/a",
}
ALLOWED_TYPE_VALUES = {"artifact", "docker", "docker-compose", "misconfig", "incompetence"}
ALLOWED_VECTOR_VALUES = {"local", "remote"}

def _validate_and_normalize_data_source_csv(file_path: str, max_bytes: int = 2_000_000, *, skip_invalid: bool = False):
    """Validate uploaded CSV for Data Sources and normalize optional columns.

    Rules:
    - Must be under max size, have header + at least one data row, and consistent row widths (after normalization step below).
    - Must include all REQUIRED_DS_COLUMNS (exact names).
    - Optional columns from OPTIONAL_DS_DEFAULTS will be appended to header if missing, and populated per-row with defaults if empty/missing.
    - Type values must be one of ALLOWED_TYPE_VALUES (case-insensitive), Vector values one of ALLOWED_VECTOR_VALUES (case-insensitive).
    - Name, Path, Startup must be non-empty strings.

        Parameters:
            file_path: path to CSV file
            max_bytes: size cap
            skip_invalid: if True, invalid data rows are skipped instead of failing the whole import.

        Returns: (ok: bool, note_or_error: str, rows: list[list[str]]|None, skipped_rows: list[int])
            ok: overall success
            note_or_error: description / counts; if skip_invalid True may include skip summary
            rows: normalized rows including header (only valid rows if skipping)
            skipped_rows: list of 1-based data row indices (relative to first data line after header) that were skipped
    """
    try:
        st = os.stat(file_path)
        if st.st_size > max_bytes:
            return False, f"File too large (> {max_bytes} bytes)", None
        # Load CSV
        rows: list[list[str]] = []
        with open(file_path, 'r', encoding='utf-8', errors='replace', newline='') as f:
            rdr = csv.reader(f)
            for i, row in enumerate(rdr):
                if i > 10000:
                    break
                rows.append([str(c) if c is not None else '' for c in row])
        if len(rows) < 2:
            return False, "CSV must have header + at least one data row", None, []
        header = rows[0]
        # Strip UTF-8 BOM if present in first cell
        if header and header[0].startswith('\ufeff'):
            header[0] = header[0].lstrip('\ufeff')
        # Ensure required headers exist
        # Case-insensitive match for required headers
        header_lower_map = {h.lower(): h for h in header}
        missing = [h for h in REQUIRED_DS_COLUMNS if h.lower() not in header_lower_map]
        # Normalize header casing to canonical names (only for required columns)
        if not missing:
            for req in REQUIRED_DS_COLUMNS:
                real = header_lower_map.get(req.lower())
                if real != req:
                    # rename in place
                    idx = header.index(real)
                    header[idx] = req
        if missing:
            return False, f"Missing required column(s): {', '.join(missing)}", None, []
        # Append optional headers if missing
        for opt_col, default in OPTIONAL_DS_DEFAULTS.items():
            if opt_col not in header:
                header.append(opt_col)
        # Normalize all rows to header length
        width = len(header)
        norm_rows: list[list[str]] = [header]
        # Build column index map
        col_idx = {name: header.index(name) for name in header}
        # Validate and fill rows
        errs: list[str] = []
        skipped_rows: list[int] = []
        for data_idx, row in enumerate(rows[1:], start=1):  # data_idx: 1-based index of data row (excluding header)
            r = list(row)
            if len(r) < width:
                r = r + [''] * (width - len(r))
            elif len(r) > width:
                r = r[:width]
            # Pull fields
            name = (r[col_idx['Name']]).strip()
            path = (r[col_idx['Path']]).strip()
            typ = (r[col_idx['Type']]).strip()
            startup = (r[col_idx['Startup']]).strip()
            vector = (r[col_idx['Vector']]).strip()
            row_err = False
            if not name:
                errs.append(f"row {data_idx}: Name is required"); row_err = True
            if not path:
                errs.append(f"row {data_idx}: Path is required"); row_err = True
            if not startup:
                errs.append(f"row {data_idx}: Startup is required"); row_err = True
            if typ:
                if typ.lower() not in ALLOWED_TYPE_VALUES:
                    errs.append(f"row {data_idx}: Type '{typ}' not in {sorted(ALLOWED_TYPE_VALUES)}"); row_err = True
                else:
                    # Normalize to lower
                    r[col_idx['Type']] = typ.lower()
            else:
                errs.append(f"row {data_idx}: Type is required"); row_err = True
            if vector:
                if vector.lower() not in ALLOWED_VECTOR_VALUES:
                    errs.append(f"row {data_idx}: Vector '{vector}' not in {sorted(ALLOWED_VECTOR_VALUES)}"); row_err = True
                else:
                    r[col_idx['Vector']] = vector.lower()
            else:
                errs.append(f"row {data_idx}: Vector is required"); row_err = True
            # Fill optionals with defaults if empty
            for opt_col, default in OPTIONAL_DS_DEFAULTS.items():
                if not r[col_idx[opt_col]].strip():
                    r[col_idx[opt_col]] = default
            if row_err and skip_invalid:
                skipped_rows.append(data_idx)
                continue
            norm_rows.append(r)
        if skip_invalid:
            if len(norm_rows) == 1:
                return False, "All data rows invalid", None, skipped_rows
            note_parts = [f"{len(norm_rows)-1} rows"]
            if skipped_rows:
                listed = ','.join(str(i) for i in skipped_rows[:20])
                extra = '' if len(skipped_rows) <= 20 else '...'
                note_parts.append(f"skipped {len(skipped_rows)} invalid row(s): {listed}{extra}")
            return True, ' | '.join(note_parts), norm_rows, skipped_rows
        else:
            if errs:
                return False, "; ".join(errs[:20]) + (" ..." if len(errs)>20 else ''), None, []
            return True, f"{len(norm_rows)-1} rows", norm_rows, []
    except Exception as e:
        return False, str(e), None, []

def _default_scenarios_payload():
    # Single default scenario with empty sections mirroring PyQt structure
    sections = [
        "Node Information", "Routing", "Services", "Traffic",
        "Events", "Vulnerabilities", "Segmentation", "HITL"
    ]
    scen = {
        "name": "Scenario 1",
        "base": {"filepath": ""},
        "hitl": {"enabled": False, "interfaces": []},
        "sections": {name: {
            "density": 0.5 if name not in ("Node Information", "HITL") else None,
            "total_nodes": 1 if name == "Node Information" else None,
            "items": []
        } for name in sections},
        "notes": ""
    }
    return {
        "scenarios": [scen],
        "result_path": None,
        "core": _default_core_dict(),
        "host_interfaces": _enumerate_host_interfaces(),
    }


def _prepare_payload_for_index(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize payload data before rendering the index page."""
    if not isinstance(payload, dict):
        payload = {}
    else:
        payload = dict(payload)

    defaults = _default_scenarios_payload()

    # --- Core connection defaults ---
    core_meta = payload.get('core')
    if not isinstance(core_meta, dict):
        core_meta = {}
    core_defaults = defaults['core']
    core_host = core_meta.get('host') or core_defaults['host']
    core_port = core_meta.get('port', core_defaults['port'])
    try:
        core_port = int(core_port)
    except Exception:
        core_port = core_defaults['port']
    payload['core'] = {'host': core_host, 'port': core_port}

    # --- Scenarios ---
    scenarios_raw = payload.get('scenarios')
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        scenarios_raw = defaults['scenarios']

    required_sections = {
        'Node Information': {'density': None, 'total_nodes': None},
        'Routing': {'density': 0.5},
        'Services': {'density': 0.5},
        'Traffic': {'density': 0.5},
        'Events': {'density': 0.5},
        'Vulnerabilities': {'density': 0.5},
        'Segmentation': {'density': 0.5},
        'HITL': {},
    }

    normalized_scenarios: List[Dict[str, Any]] = []
    for idx, scen in enumerate(scenarios_raw, start=1):
        if not isinstance(scen, dict):
            continue
        scen_norm = dict(scen)
        scen_norm['name'] = scen_norm.get('name') or f"Scenario {idx}"

        base_meta = scen_norm.get('base')
        if not isinstance(base_meta, dict):
            base_meta = {}
        base_meta = dict(base_meta)
        filepath = base_meta.get('filepath')
        if not isinstance(filepath, str):
            filepath = '' if filepath is None else str(filepath)
        base_meta['filepath'] = filepath
        if filepath and not base_meta.get('display_name'):
            base_meta['display_name'] = os.path.basename(filepath)
        scen_norm['base'] = base_meta

        if 'density_count' not in scen_norm:
            scen_norm['density_count'] = 10

        sections_meta = scen_norm.get('sections')
        if not isinstance(sections_meta, dict):
            sections_meta = {}
        sections_out: Dict[str, Any] = {}
        for section_name, defaults_map in required_sections.items():
            sec_val = sections_meta.get(section_name)
            if isinstance(sec_val, dict):
                sec_norm = dict(sec_val)
            else:
                sec_norm = {}
            items = sec_norm.get('items')
            if isinstance(items, list):
                sec_norm['items'] = [item for item in items if isinstance(item, dict)]
            else:
                sec_norm['items'] = []
            for key, val in defaults_map.items():
                sec_norm.setdefault(key, val)
            sections_out[section_name] = sec_norm
        for extra_name, extra_val in sections_meta.items():
            if extra_name not in sections_out:
                sections_out[extra_name] = extra_val
        scen_norm['sections'] = sections_out

        hitl_meta = scen_norm.get('hitl')
        if isinstance(hitl_meta, dict):
            hitl_norm = dict(hitl_meta)
        else:
            hitl_norm = {}
        hitl_norm['enabled'] = bool(hitl_norm.get('enabled'))
        interfaces_raw = hitl_norm.get('interfaces')
        interfaces_norm: List[Dict[str, Any]] = []
        if isinstance(interfaces_raw, list):
            for iface in interfaces_raw:
                if not isinstance(iface, dict):
                    continue
                iface_norm = dict(iface)
                name = iface_norm.get('name')
                if not isinstance(name, str):
                    name = '' if name is None else str(name)
                name = name.strip()
                if not name:
                    continue
                iface_norm['name'] = name
                iface_norm['attachment'] = _normalize_hitl_attachment(iface_norm.get('attachment'))
                for addr_key in ('ipv4', 'ipv6'):
                    vals = iface_norm.get(addr_key)
                    if isinstance(vals, list):
                        iface_norm[addr_key] = [str(v).strip() for v in vals if v is not None and str(v).strip()]
                interfaces_norm.append(iface_norm)
        hitl_norm['interfaces'] = interfaces_norm
        scen_norm['hitl'] = hitl_norm

        normalized_scenarios.append(scen_norm)

    if not normalized_scenarios:
        normalized_scenarios = defaults['scenarios']
    payload['scenarios'] = normalized_scenarios

    # --- Base upload metadata ---
    base_upload = payload.get('base_upload')
    if isinstance(base_upload, dict):
        base_norm = dict(base_upload)
        path = base_norm.get('path')
        if isinstance(path, str):
            base_norm['path'] = path
            base_norm.setdefault('display_name', os.path.basename(path) if path else '')
        else:
            base_norm['path'] = ''
        if 'valid' in base_norm:
            base_norm['valid'] = bool(base_norm['valid'])
        payload['base_upload'] = base_norm

    # --- Host interfaces ---
    host_ifaces = payload.get('host_interfaces')
    if not isinstance(host_ifaces, list):
        host_ifaces = []
    sanitized_ifaces: List[Dict[str, Any]] = []
    adaptor_names: set[str] = set()
    for iface in host_ifaces:
        if not isinstance(iface, dict):
            continue
        entry = dict(iface)
        name = entry.get('name')
        if isinstance(name, str):
            name = name.strip()
        elif name is not None:
            name = str(name)
        else:
            name = ''
        entry['name'] = name
        if name:
            adaptor_names.add(name)
        for arr_key in ('ipv4', 'ipv6', 'flags'):
            vals = entry.get(arr_key)
            if isinstance(vals, list):
                entry[arr_key] = [v for v in vals if v not in (None, '')]
        sanitized_ifaces.append(entry)
    payload['host_interfaces'] = sanitized_ifaces
    payload['hitl_adaptors'] = sorted(adaptor_names)

    payload.setdefault('result_path', defaults['result_path'])

    return payload


# Hardware in the Loop utilities
@app.route('/api/host_interfaces', methods=['GET'])
def api_host_interfaces():
    return jsonify({'interfaces': _enumerate_host_interfaces()})

# ---------------- Docker (per-node) status & cleanup ----------------
def _compose_assignments_path() -> str:
    return os.path.join(_vuln_base_dir() or "/tmp/vulns", "compose_assignments.json")


def _load_compose_assignments() -> dict:
    p = _compose_assignments_path()
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        app.logger.debug("compose assignments read failed: %s", e)
    return {}


def _compose_file_for_node(node_name: str) -> str:
    base = _vuln_base_dir() or "/tmp/vulns"
    return os.path.join(base, f"docker-compose-{node_name}.yml")


def _docker_container_exists(name: str) -> tuple[bool, bool]:
    try:
        proc = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            return (False, False)
        names = set(ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip())
        if name not in names:
            return (False, False)
        proc2 = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        running = (proc2.returncode == 0 and (proc2.stdout or '').strip().lower() == 'true')
        return (True, running)
    except Exception:
        return (False, False)


def _images_pulled_for_compose_safe(yml_path: str) -> bool:
    try:
        from core_topo_gen.utils.vuln_process import _images_pulled_for_compose as _pulled  # type: ignore
        return bool(_pulled(yml_path))
    except Exception as e:
        try: app.logger.debug("pull check failed for %s: %s", yml_path, e)
        except Exception: pass
        return False


@app.route('/docker/status', methods=['GET'])
def docker_status():
    data = _load_compose_assignments()
    assignments = data.get('assignments', {}) if isinstance(data, dict) else {}
    items = []
    for node_name in sorted(assignments.keys()):
        yml = _compose_file_for_node(node_name)
        exists = os.path.exists(yml)
        pulled = _images_pulled_for_compose_safe(yml) if exists else False
        c_exists, running = _docker_container_exists(node_name)
        items.append({
            'name': node_name,
            'compose': yml,
            'exists': bool(exists),
            'pulled': bool(pulled),
            'container_exists': bool(c_exists),
            'running': bool(running),
        })
    return jsonify({'items': items, 'timestamp': int(time.time())})


@app.route('/docker/cleanup', methods=['POST'])
def docker_cleanup():
    names = []
    try:
        if request.is_json:
            body = request.get_json(silent=True) or {}
            if isinstance(body.get('names'), list):
                names = [str(x) for x in body.get('names')]
        else:
            raw = request.form.get('names')
            if raw:
                try:
                    arr = json.loads(raw)
                    if isinstance(arr, list):
                        names = [str(x) for x in arr]
                except Exception:
                    names = [str(raw)]
        if not names:
            data = _load_compose_assignments()
            assignments = data.get('assignments', {}) if isinstance(data, dict) else {}
            names = list(assignments.keys())
        results = []
        for nm in names:
            stopped = removed = False
            try:
                p1 = subprocess.run(['docker', 'stop', nm], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                stopped = (p1.returncode == 0)
            except Exception:
                stopped = False
            try:
                p2 = subprocess.run(['docker', 'rm', nm], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                removed = (p2.returncode == 0)
            except Exception:
                removed = False
            results.append({'name': nm, 'stopped': bool(stopped), 'removed': bool(removed)})
        return jsonify({'ok': True, 'results': results})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


def _find_latest_session_xml(base_dir: str, stem: str | None = None) -> str | None:
    """Best-effort helper to locate the newest session XML written previously.

    If `stem` is provided, prefer files beginning with that stem; otherwise
    return the most recent .xml file under the directory.
    """
    try:
        if not base_dir or not os.path.isdir(base_dir):
            return None
        candidates: list[tuple[float, str]] = []
        for name in os.listdir(base_dir):
            if not name.lower().endswith('.xml'):
                continue
            if stem:
                prefix = f"{stem}-"
                if not name.startswith(prefix):
                    continue
            path = os.path.join(base_dir, name)
            try:
                st = os.stat(path)
                candidates.append((st.st_mtime, path))
            except Exception:
                continue
        if not candidates and stem:
            # If no stem-specific match, allow fallback to any latest XML
            return _find_latest_session_xml(base_dir, stem=None)
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]
    except Exception:
        return None


def _grpc_save_current_session_xml(host: str, port: int, out_dir: str, session_id: str | None = None) -> str | None:
    """Attempt to connect to CORE daemon via gRPC and save the active session XML.

    This uses CoreGrpcClient.save_xml if available. If no active session exists
    or the gRPC client modules are unavailable, returns None silently.

    A timestamped filename is written to out_dir. Preferred pattern when possible:
        <scenario-name>-<timestamp>.xml
    Falls back to:
        core-session-<session_id>-<timestamp>.xml
    """
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        app.logger.debug("gRPC CoreGrpcClient not available; skipping save_xml (host=%s port=%s)", host, port)
        return None
    address = f"{host}:{port}"
    ts = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    # Ensure a centralized session XML directory for discoverability
    base_sessions_dir = os.path.join(_outputs_dir(), 'core-sessions')
    try:
        os.makedirs(base_sessions_dir, exist_ok=True)
    except Exception:
        pass
    # Still ensure caller-provided directory exists (legacy paths)
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        pass
    # Pick first running/defined session if any; API lacks direct 'current' concept here.
    def _unique_path(base_path: str) -> str:
        if not os.path.exists(base_path):
            return base_path
        root, ext = os.path.splitext(base_path)
        counter = 2
        while True:
            candidate = f"{root}-{counter}{ext}"
            if not os.path.exists(candidate):
                return candidate
            counter += 1

    try:
        app.logger.debug("Connecting to CORE gRPC at %s (requested session_id=%s)", address, session_id)
        client = CoreGrpcClient(address=address)
        try:
            from core_topo_gen.utils.grpc_logging import wrap_core_client  # type: ignore
            client = wrap_core_client(client, app.logger)
        except Exception:
            pass
        client.connect()
        try:
            sessions = client.get_sessions()
            if not sessions:
                app.logger.info("No CORE sessions found at %s; cannot save session XML", address)
                return None
            # If a specific session id is requested, select it; otherwise default to first
            target = None
            if session_id is not None:
                for s in sessions:
                    sid = getattr(s, 'id', None) or getattr(s, 'session_id', None)
                    if str(sid) == str(session_id):
                        target = s
                        break
                if target is None:
                    app.logger.warning("Requested session_id=%s not found; defaulting to first session", session_id)
                    target = sessions[0]
            else:
                target = sessions[0]
            session_id = getattr(target, 'id', None) or getattr(target, 'session_id', None)
            if session_id is None:
                app.logger.warning("Selected CORE session has no id; aborting save_xml")
                return None
            session_meta = target
            try:
                meta_detail = client.get_session(session_id)
                if meta_detail is not None:
                    session_meta = meta_detail
            except Exception as e:
                app.logger.debug("get_session(%s) lookup failed: %s", session_id, e)
            try:
                client.open_session(session_id)
            except Exception as e:
                app.logger.debug("open_session(%s) failed or not required: %s", session_id, e)
            existing_candidates: list[str] = []

            def _add_candidate_path(path_candidate: str | None) -> None:
                if not path_candidate:
                    return
                try:
                    abs_path = os.path.abspath(path_candidate)
                except Exception:
                    return
                if not os.path.exists(abs_path):
                    return
                existing_candidates.append(abs_path)

            _add_candidate_path(getattr(session_meta, 'file', None))
            _add_candidate_path(getattr(target, 'file', None))
            for attr in ('dir', 'path', 'directory'):
                dir_candidate = getattr(session_meta, attr, None) or getattr(target, attr, None)
                if not dir_candidate or not os.path.isdir(dir_candidate):
                    continue
                try:
                    for entry in os.listdir(dir_candidate):
                        if entry.lower().endswith('.xml'):
                            _add_candidate_path(os.path.join(dir_candidate, entry))
                except Exception:
                    continue
            seen_candidates: set[str] = set()
            filtered_candidates: list[str] = []
            for cand in existing_candidates:
                if cand in seen_candidates:
                    continue
                seen_candidates.add(cand)
                filtered_candidates.append(cand)
            def _candidate_priority(path: str) -> tuple[int, float, str]:
                base = os.path.basename(path).lower()
                priority = 0 if 'session-deployed' in base else 1
                try:
                    mtime = -os.stat(path).st_mtime
                except Exception:
                    mtime = 0.0
                return (priority, mtime, base)
            filtered_candidates.sort(key=_candidate_priority)
            # Derive a friendly stem from the original scenario XML if available
            stem = None
            try:
                orig_file = getattr(session_meta, 'file', None)
                if orig_file and os.path.exists(orig_file):
                    # Try to parse scenario names from the original XML
                    names = _scenario_names_from_xml(orig_file)
                    raw = (names[0] if names else os.path.splitext(os.path.basename(orig_file))[0])
                    stem = secure_filename(raw).strip('_-.') or None
            except Exception:
                stem = None
            if not stem:
                stem = f"core-session-{session_id}"
            for candidate_path in filtered_candidates:
                try:
                    suffix = ''
                    base_name = os.path.basename(candidate_path).lower()
                    if 'session-deployed' in base_name and not stem.lower().startswith('session-deployed'):
                        suffix = '-session-deployed'
                    copy_dest = os.path.join(base_sessions_dir, f"{stem}-{ts}{suffix}.xml")
                    copy_dest = _unique_path(copy_dest)
                    shutil.copy2(candidate_path, copy_dest)
                    try:
                        _normalize_core_device_types(copy_dest)
                    except Exception as norm_err:
                        app.logger.debug("core xml type normalization skipped for copied candidate %s: %s", copy_dest, norm_err)
                    try:
                        size = os.stat(copy_dest).st_size
                    except Exception:
                        size = -1
                    app.logger.info("Copied CORE session XML from %s to %s (%s bytes)", candidate_path, copy_dest, size if size >= 0 else '?')
                    return copy_dest
                except Exception as copy_err:
                    app.logger.debug("Failed copying session XML candidate %s: %s", candidate_path, copy_err)
                    continue
            # Always store under outputs/core-sessions so CORE page can find it
            out_path = os.path.join(base_sessions_dir, f"{stem}-{ts}.xml")
            # Attempt save with small retries to handle transient timing issues
            save_errors: list[Exception] = []
            session_id_arg = session_id
            try:
                session_id_arg = int(session_id)  # type: ignore[assignment]
            except Exception:
                session_id_arg = session_id
            for attempt in range(3):
                try:
                    app.logger.info("Invoking save_xml(session_id=%s) -> %s (attempt %d)", session_id, out_path, attempt + 1)
                    client.save_xml(session_id=session_id_arg, file_path=out_path)
                    break
                except Exception as e:
                    save_errors.append(e)
                    if attempt < 2:
                        try:
                            time.sleep(0.5 * (attempt + 1))
                        except Exception:
                            pass
                        continue
                    app.logger.warning("save_xml final failure for session %s at %s: %s", session_id, address, e)
            else:
                # Loop exhausted without break
                last = save_errors[-1] if save_errors else None
                if last:
                    app.logger.warning("save_xml could not persist session XML: %s", last)
            if not os.path.exists(out_path):
                for _ in range(3):
                    try:
                        time.sleep(0.2)
                    except Exception:
                        break
                    if os.path.exists(out_path):
                        break
            if os.path.exists(out_path):
                # Validate that it's a CORE XML and not our editor format
                try:
                    ok, errs = _validate_core_xml(out_path)
                except Exception as e:
                    app.logger.warning("CORE XML validation raised exception for %s: %s", out_path, e)
                    ok = False
                if ok:
                    # Normalize device types: set 'router' if routing services present; 'docker' for docker class; else 'PC'
                    try:
                        _normalize_core_device_types(out_path)
                    except Exception as e:
                        app.logger.debug("core xml type normalization skipped for %s: %s", out_path, e)
                    try:
                        size = os.stat(out_path).st_size
                    except Exception:
                        size = -1
                    app.logger.info("Saved valid CORE session XML (session_id=%s) at %s (%s bytes)", session_id, out_path, size if size >= 0 else '?')
                    return out_path
                else:
                    app.logger.warning("Saved XML failed CORE validation; deleting file %s. Errors: %s", out_path, errs if 'errs' in locals() else '(unknown)')
                    try:
                        os.remove(out_path)
                    except Exception:
                        pass
            # Fallback: try to locate an existing session XML from previous saves
            fallback = _find_latest_session_xml(base_sessions_dir, stem)
            if fallback and os.path.exists(fallback):
                try:
                    size = os.stat(fallback).st_size
                except Exception:
                    size = -1
                app.logger.info("Using existing CORE session XML fallback for session_id=%s: %s (%s bytes)", session_id, fallback, size if size >= 0 else '?')
                return fallback
            return None
        finally:
            try:
                client.close()
            except Exception:
                pass
    except Exception:
        return None

def _attach_base_upload(payload: Dict[str, Any]):
    """Ensure payload['base_upload'] is present if first scenario has a base filepath referencing an existing file.
    Performs validation to set valid flag. Does nothing if already present.
    """
    try:
        if payload.get('base_upload'):
            return
        scen_list = payload.get('scenarios') or []
        if not scen_list:
            return
        base_path = scen_list[0].get('base', {}).get('filepath') or ''
        if not base_path or not os.path.exists(base_path):
            return
        ok, _errs = _validate_core_xml(base_path)
        display_name = os.path.basename(base_path)
        payload['base_upload'] = {
            'path': base_path,
            'valid': bool(ok),
            'display_name': display_name,
        }
        try:
            scen_list[0].setdefault('base', {})['display_name'] = display_name
        except Exception:
            pass
    except Exception:
        pass


def _parse_scenarios_xml(path):
    data = {"scenarios": []}
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "Scenarios":
        # Fallback: if file is a single ScenarioEditor, wrap
        if root.tag == "ScenarioEditor":
            scen = _parse_scenario_editor(root)
            scen["name"] = os.path.splitext(os.path.basename(path))[0]
            data["scenarios"].append(scen)
            return data
        raise ValueError("Root element must be <Scenarios> or <ScenarioEditor>")
    for scen_el in root.findall("Scenario"):
        scen = {"name": scen_el.get("name", "Scenario")}
        # Capture scenario-level density_count attribute if present
        dc_attr = scen_el.get('density_count')
        if dc_attr is not None and dc_attr != '':
            try:
                scen['density_count'] = int(dc_attr)
            except Exception:
                pass
        se = scen_el.find("ScenarioEditor")
        if se is None:
            continue
        scen.update(_parse_scenario_editor(se))
        # If scenario-level density_count was absent but Node Information section provided one, keep existing.
        data["scenarios"].append(scen)
    return data


def _parse_scenario_editor(se):
    scen = {"base": {"filepath": ""}, "sections": {}, "notes": ""}
    # If parent <Scenario> carries scenario-level density_count attribute, capture it.
    try:
        parent = se.getparent()  # lxml style (if ever switched) - fallback below
    except Exception:
        parent = None
    # ElementTree doesn't support getparent; instead inspect tail by traversing immediate children of root in caller.
    # Simplest: look for density_count on any ancestor via attrib access on 'se' .attrib is only local, so rely on caller to have set scen_el attrib earlier.
    # We can recover by walking up using a cheap hack: se._parent if present (cpython impl detail) else ignore.
    try:
        scen_el = getattr(se, 'attrib', None)
    except Exception:
        scen_el = None
    # Instead of fragile parent access, during parsing of root we can read attribute directly from the sibling Scenario element (handled in outer loop); emulate by checking se.get('density_count') first.
    # For backward compatibility, allow density_count on Scenario or Node Information section.
    # We'll set scen['density_count'] here only if Scenario element attribute is available; Node Information section handled later.
    # Outer loop already hands us 'se'; its parent was processed to create scen dict. We'll modify outer function to inject attribute before calling this if needed.
    # Simpler: just check if 'density_count' exists on any ancestor by scanning se.iterfind('..') unsupported; fallback: pass.
    pass
    base = se.find("BaseScenario")
    if base is not None:
        scen["base"]["filepath"] = base.get("filepath", "")
    hitl_el = se.find("HardwareInLoop")
    hitl_info: Dict[str, Any] = {"enabled": False, "interfaces": []}
    if hitl_el is not None:
        enabled_raw = (hitl_el.get("enabled") or "").strip().lower()
        hitl_info["enabled"] = enabled_raw in ("1", "true", "yes", "on")
        interfaces: List[Dict[str, Any]] = []
        for iface_el in hitl_el.findall("Interface"):
            name = (iface_el.get("name") or "").strip()
            if not name:
                continue
            entry: Dict[str, Any] = {"name": name}
            alias = (iface_el.get("alias") or iface_el.get("display") or iface_el.get("description") or "").strip()
            if alias:
                entry["alias"] = alias
            mac_attr = iface_el.get("mac")
            if mac_attr:
                entry["mac"] = mac_attr
            attachment_attr = iface_el.get("attachment") or iface_el.get("attach")
            entry["attachment"] = _normalize_hitl_attachment(attachment_attr)
            ipv4_attr = iface_el.get("ipv4") or iface_el.get("ipv4_addresses")
            if ipv4_attr:
                entry["ipv4"] = [p.strip() for p in ipv4_attr.split(',') if p.strip()]
            ipv6_attr = iface_el.get("ipv6") or iface_el.get("ipv6_addresses")
            if ipv6_attr:
                entry["ipv6"] = [p.strip() for p in ipv6_attr.split(',') if p.strip()]
            interfaces.append(entry)
        hitl_info["interfaces"] = interfaces
    scen["hitl"] = hitl_info
    # Sections
    for sec in se.findall("section"):
        name = sec.get("name", "")
        if not name:
            continue
        entry = {"density": None, "total_nodes": None, "items": []}
        if name == "Node Information":
            tn = sec.get("total_nodes")
            if tn is not None:
                try:
                    entry["total_nodes"] = int(tn)
                except Exception:
                    entry["total_nodes"] = 1
        else:
            dens = sec.get("density")
            entry["density"] = float(dens) if dens is not None else 0.5
        for item in sec.findall("item"):
            d = {
                "selected": item.get("selected", "Random"),
                "factor": float(item.get("factor", "1.0")),
            }
            if name == "Routing":
                em = item.get('r2r_mode')
                if em is not None:
                    # Store under new key r2r_mode; keep legacy key for UI components still referencing it
                    d['r2r_mode'] = em
                ev = item.get('r2r_edges') or item.get('edges')
                if ev is not None and ev.strip() != '':
                    try:
                        d['r2r_edges'] = int(ev)
                    except Exception:
                        pass
                r2s_m = item.get('r2s_mode')
                if r2s_m is not None:
                    d['r2s_mode'] = r2s_m
                r2s_ev = item.get('r2s_edges')
                if r2s_ev is not None and r2s_ev.strip() != '':
                    try:
                        d['r2s_edges'] = int(r2s_ev)
                    except Exception:
                        pass
                # New per-item hosts-per-switch bounds
                hmin_attr = item.get('r2s_hosts_min')
                hmax_attr = item.get('r2s_hosts_max')
                try:
                    if hmin_attr is not None and hmin_attr.strip() != '':
                        d['r2s_hosts_min'] = int(hmin_attr)
                except Exception:
                    pass
                try:
                    if hmax_attr is not None and hmax_attr.strip() != '':
                        d['r2s_hosts_max'] = int(hmax_attr)
                except Exception:
                    pass
            if name == "Events":
                d["script_path"] = item.get("script_path", "")
            if name == "Traffic":
                d.update({
                    "pattern": item.get("pattern", "continuous"),
                    "rate_kbps": float(item.get("rate_kbps", "64.0")),
                    "period_s": float(item.get("period_s", "1.0")),
                    "jitter_pct": float(item.get("jitter_pct", "10.0")),
                    "content_type": (item.get("content_type") or item.get("content") or "Random"),
                })
            if name == "Vulnerabilities":
                # Extra attributes for Vulnerabilities section
                sel = (d.get("selected") or "").strip()
                if sel == "Type/Vector":
                    d["v_type"] = item.get("v_type", "Random")
                    d["v_vector"] = item.get("v_vector", "Random")
                elif sel == "Specific":
                    d["v_name"] = item.get("v_name", "")
                    d["v_path"] = item.get("v_path", "")
                    # Default count to 1 if missing/invalid
                    try:
                        d["v_count"] = int(item.get("v_count", "1"))
                    except Exception:
                        d["v_count"] = 1
                # Persist metric choice if present (Weight or Count)
                vm = item.get("v_metric")
                if vm:
                    d["v_metric"] = vm
            # Generic metric/count for all sections (including Vulnerabilities)
            try:
                vm_generic = item.get("v_metric")
                if vm_generic and vm_generic in ("Weight", "Count"):
                    d["v_metric"] = vm_generic
                vc_generic = item.get("v_count")
                if vc_generic is not None:
                    try:
                        d["v_count"] = int(vc_generic)
                    except Exception:
                        d["v_count"] = 1
            except Exception:
                pass
            entry["items"].append(d)
        scen["sections"][name] = entry
        # Capture scenario-level density_count if present on Scenario element once
        if 'density_count' not in scen and se is not None:
            # Attempt to access parent <Scenario> by scanning for attribute on sec's ancestors is not directly supported.
            # Instead, rely on convention: during writing we place density_count on <Scenario>. So parse root manually here.
            try:
                # Walk up by brute force: find the nearest ancestor named 'Scenario'
                # We don't have parent links; reconstruct by searching from current element root.
                root = sec
                while getattr(root, 'tag', None) and root.tag != 'Scenario':
                    # ElementTree lacks parent pointer; break to avoid infinite loop
                    break
            except Exception:
                root = None
        # Fallback: if Node Information section carries density_count/base_nodes and scenario-level missing, propagate to scen.
        if name == 'Node Information' and 'density_count' not in scen:
            dc_attr = sec.get('density_count') or sec.get('base_nodes') or sec.get('total_nodes')
            if dc_attr:
                try:
                    scen['density_count'] = int(dc_attr)
                except Exception:
                    pass
    # Notes
    notes_sec = None
    for sec in se.findall("section"):
        if sec.get("name") == "Notes":
            notes_sec = sec; break
    if notes_sec is not None:
        notes_el = notes_sec.find("notes")
        if notes_el is not None and notes_el.text:
            scen["notes"] = notes_el.text
    return scen


def _build_scenarios_xml(data_dict: dict) -> ET.ElementTree:
    root = ET.Element("Scenarios")
    for scen in data_dict.get("scenarios", []):
        scen_el = ET.SubElement(root, "Scenario")
        scen_el.set("name", scen.get("name", "Scenario"))
        # Persist scenario-level density_count (Count for Density) so parser priority can pick it up on reload.
        try:
            if 'density_count' in scen and scen.get('density_count') is not None:
                scen_el.set('density_count', str(int(scen.get('density_count'))))
        except Exception:
            pass
        se = ET.SubElement(scen_el, "ScenarioEditor")
        base = ET.SubElement(se, "BaseScenario")
        base.set("filepath", scen.get("base", {}).get("filepath", ""))

        hitl = scen.get("hitl") or {}
        raw_ifaces = hitl.get("interfaces") if isinstance(hitl, dict) else None
        normalized_ifaces: List[Dict[str, Any]] = []
        if isinstance(raw_ifaces, list):
            for entry in raw_ifaces:
                if not entry:
                    continue
                if isinstance(entry, str):
                    normalized_ifaces.append({"name": entry})
                    continue
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or entry.get("interface") or entry.get("iface")
                if not name:
                    continue
                clean: Dict[str, Any] = {"name": str(name)}
                for key in ("alias", "display", "description"):
                    val = entry.get(key)
                    if isinstance(val, str) and val.strip():
                        clean["alias"] = val.strip()
                        break
                mac_val = entry.get("mac")
                if isinstance(mac_val, str) and mac_val.strip():
                    clean["mac"] = mac_val.strip()
                clean["attachment"] = _normalize_hitl_attachment(entry.get("attachment"))
                for attr_key in ("ipv4", "ipv6"):
                    val = entry.get(attr_key)
                    if isinstance(val, str):
                        items = [p.strip() for p in val.split(',') if p.strip()]
                        if items:
                            clean[attr_key] = items
                    elif isinstance(val, (list, tuple, set)):
                        items = [str(p).strip() for p in val if str(p).strip()]
                        if items:
                            clean[attr_key] = items
                normalized_ifaces.append(clean)
        for iface in normalized_ifaces:
            if "attachment" not in iface:
                iface["attachment"] = _DEFAULT_HITL_ATTACHMENT

        if hitl and (hitl.get("enabled") or normalized_ifaces):
            hitl_el = ET.SubElement(se, "HardwareInLoop")
            hitl_el.set("enabled", "true" if hitl.get("enabled") else "false")
            for iface in normalized_ifaces:
                name = iface.get("name")
                if not name:
                    continue
                iface_el = ET.SubElement(hitl_el, "Interface")
                iface_el.set("name", str(name))
                alias = iface.get("alias")
                if alias:
                    iface_el.set("alias", str(alias))
                if iface.get("mac"):
                    iface_el.set("mac", str(iface["mac"]))
                attachment = _normalize_hitl_attachment(iface.get("attachment"))
                if attachment:
                    iface_el.set("attachment", attachment)
                ipv4_vals = iface.get("ipv4")
                if isinstance(ipv4_vals, (list, tuple, set)):
                    joined = ",".join(str(p) for p in ipv4_vals if p)
                    if joined:
                        iface_el.set("ipv4", joined)
                ipv6_vals = iface.get("ipv6")
                if isinstance(ipv6_vals, (list, tuple, set)):
                    joined6 = ",".join(str(p) for p in ipv6_vals if p)
                    if joined6:
                        iface_el.set("ipv6", joined6)

        order = [
            "Node Information", "Routing", "Services", "Traffic",
            "Events", "Vulnerabilities", "Segmentation", "Notes"
        ]
        combined_host_pool: int | None = None
        scenario_host_additive = 0
        scenario_routing_total = 0
        scenario_vuln_total = 0

        for name in order:
            if name == "Notes":
                sec_el = ET.SubElement(se, "section", name="Notes")
                ne = ET.SubElement(sec_el, "notes")
                ne.text = scen.get("notes", "") or ""
                continue
            sec = scen.get("sections", {}).get(name)
            if not sec:
                continue
            sec_el = ET.SubElement(se, "section", name=name)
            items_list = sec.get("items", []) or []
            weight_rows = [it for it in items_list if (it.get('v_metric') or (it.get('selected')=='Specific' and name=='Vulnerabilities') or 'Weight') == 'Weight']
            count_rows = [it for it in items_list if (it.get('v_metric') == 'Count') or (name == 'Vulnerabilities' and it.get('selected') == 'Specific')]
            weight_sum = sum(float(it.get('factor', 0) or 0) for it in weight_rows) if weight_rows else 0.0

            if name == "Node Information":
                # Determine if an explicit density_count was provided (scenario-level or legacy section field).
                explicit_density_raw = None
                scen_level_dc = scen.get('density_count')
                if scen_level_dc is not None:
                    explicit_density_raw = scen_level_dc
                else:
                    for legacy_key in ('density_count', 'total_nodes', 'base_nodes'):
                        if sec.get(legacy_key) not in (None, ""):
                            explicit_density_raw = sec.get(legacy_key)
                            break
                density_count: int | None = None
                if explicit_density_raw is not None:
                    try:
                        density_count = max(0, int(explicit_density_raw))
                    except Exception:
                        density_count = 0
                # additive Count rows always additive even if base omitted
                additive_nodes = sum(int(it.get('v_count') or 0) for it in count_rows)
                # For derived counts we only have a combined host pool if explicit density_count provided
                combined_nodes = (density_count or 0) + additive_nodes
                norm_sum = 0.0
                if weight_rows:
                    raw_sum = sum(float(it.get('factor') or 0) for it in weight_rows)
                    if raw_sum > 0:
                        for it in weight_rows:
                            try:
                                it['factor'] = float(it.get('factor') or 0) / raw_sum
                            except Exception:
                                it['factor'] = 0.0
                        norm_sum = 1.0
                    else:
                        weight_rows[0]['factor'] = 1.0
                        for it in weight_rows[1:]:
                            it['factor'] = 0.0
                        norm_sum = 1.0
                # Only persist base-related fields if an explicit density_count was supplied. Otherwise omit so parser can apply default.
                if density_count is not None:
                    sec_el.set("density_count", str(density_count))
                    sec_el.set("base_nodes", str(density_count))
                sec_el.set("additive_nodes", str(additive_nodes))
                if density_count is not None:
                    sec_el.set("combined_nodes", str(combined_nodes))
                sec_el.set("weight_rows", str(len(weight_rows)))
                sec_el.set("count_rows", str(len(count_rows)))
                sec_el.set("weight_sum", f"{weight_sum:.3f}")
                sec_el.set("normalized_weight_sum", f"{norm_sum:.3f}")
                combined_host_pool = combined_nodes if density_count is not None else None
                scenario_host_additive += combined_nodes if density_count is not None else additive_nodes
            else:
                dens = sec.get("density")
                if dens is not None:
                    try:
                        sec_el.set("density", f"{float(dens):.3f}")
                    except Exception:
                        sec_el.set("density", str(dens))
                if name in ("Routing", "Vulnerabilities"):
                    base_pool = combined_host_pool if isinstance(combined_host_pool, int) else None
                    explicit = sum(int(it.get('v_count') or 0) for it in count_rows)
                    derived = 0
                    try:
                        dens_val = float(dens or 0)
                    except Exception:
                        dens_val = 0.0
                    if weight_rows and base_pool and base_pool > 0:
                        if name == 'Routing':
                            if dens_val >= 1:
                                derived = int(round(dens_val))
                            elif dens_val > 0:
                                derived = int(round(base_pool * dens_val))
                        else:  # Vulnerabilities
                            if dens_val > 0:
                                dens_clip = min(1.0, dens_val)
                                derived = int(round(base_pool * dens_clip))
                    total_planned = explicit + derived
                    sec_el.set("explicit_count", str(explicit))
                    sec_el.set("derived_count", str(derived))
                    sec_el.set("total_planned", str(total_planned))
                    sec_el.set("weight_rows", str(len(weight_rows)))
                    sec_el.set("count_rows", str(len(count_rows)))
                    sec_el.set("weight_sum", f"{weight_sum:.3f}")
                    if name == 'Routing':
                        scenario_routing_total += total_planned
                    else:
                        scenario_vuln_total += total_planned
                elif name in ("Services", "Traffic", "Segmentation"):
                    explicit = sum(int(it.get('v_count') or 0) for it in count_rows)
                    sec_el.set("explicit_count", str(explicit))
                    sec_el.set("weight_rows", str(len(weight_rows)))
                    sec_el.set("count_rows", str(len(count_rows)))
                    sec_el.set("weight_sum", f"{weight_sum:.3f}")

            for item in items_list:
                it = ET.SubElement(sec_el, "item")
                it.set("selected", str(item.get('selected', 'Random')))
                try:
                    it.set("factor", f"{float(item.get('factor', 1.0)):.3f}")
                except Exception:
                    it.set("factor", "0.000")
                if name == 'Routing':
                    em = (item.get('r2r_mode') or '').strip()
                    r2s_mode = (item.get('r2s_mode') or '').strip()
                    if em:
                        it.set('r2r_mode', em)
                    if r2s_mode:
                        it.set('r2s_mode', r2s_mode)
                    # Persist edge budget hints when provided (including Uniform/NonUniform / aggregate modes)
                    try:
                        ev_raw = item.get('r2r_edges') or item.get('edges')
                        if em == 'Exact' and ev_raw is not None and str(ev_raw).strip() != '':
                            ev = int(ev_raw)
                            if ev > 0:  # only meaningful positive degrees
                                it.set('r2r_edges', str(ev))
                    except Exception:
                        pass
                    try:
                        r2s_raw = item.get('r2s_edges')
                        if r2s_raw is not None and str(r2s_raw).strip() != '':
                            ev2 = int(r2s_raw)
                            if ev2 >= 0:
                                it.set('r2s_edges', str(ev2))
                    except Exception:
                        pass
                    # Persist per-item host grouping bounds if provided (non-empty and >=0)
                    try:
                        hmin_raw = item.get('r2s_hosts_min')
                        if hmin_raw not in (None, ''):
                            hmin_val = int(hmin_raw)
                            if hmin_val >= 0:
                                it.set('r2s_hosts_min', str(hmin_val))
                    except Exception:
                        pass
                    try:
                        hmax_raw = item.get('r2s_hosts_max')
                        if hmax_raw not in (None, ''):
                            hmax_val = int(hmax_raw)
                            if hmax_val >= 0:
                                it.set('r2s_hosts_max', str(hmax_val))
                    except Exception:
                        pass
                    # If still absent, write explicit defaults (UI defaults 1 and 4) for deterministic round-trip
                    if 'r2s_hosts_min' not in it.attrib:
                        it.set('r2s_hosts_min', '1')
                    if 'r2s_hosts_max' not in it.attrib:
                        it.set('r2s_hosts_max', '4')
                if name == 'Events':
                    sp = item.get('script_path') or ''
                    if sp:
                        it.set('script_path', sp)
                if name == 'Traffic':
                    it.set('pattern', str(item.get('pattern', 'continuous')))
                    it.set('rate_kbps', f"{float(item.get('rate_kbps', 64.0)):.1f}")
                    it.set('period_s', f"{float(item.get('period_s', 1.0)):.1f}")
                    it.set('jitter_pct', f"{float(item.get('jitter_pct', 10.0)):.1f}")
                    ct = (item.get('content_type') or item.get('content') or '').strip()
                    if ct:
                        it.set('content_type', ct)
                if name == 'Vulnerabilities':
                    sel = str(item.get('selected', 'Random'))
                    if sel == 'Type/Vector':
                        vt = item.get('v_type')
                        vv = item.get('v_vector')
                        if vt:
                            it.set('v_type', str(vt))
                        if vv:
                            it.set('v_vector', str(vv))
                    elif sel == 'Specific':
                        vn = item.get('v_name')
                        vp = item.get('v_path')
                        if vn:
                            it.set('v_name', str(vn))
                        if vp:
                            it.set('v_path', str(vp))
                vm_any = item.get('v_metric')
                if vm_any:
                    it.set('v_metric', str(vm_any))
                if (item.get('v_metric') == 'Count') or (name == 'Vulnerabilities' and str(item.get('selected', '')) == 'Specific'):
                    vc_any = item.get('v_count')
                    try:
                        if vc_any is not None:
                            it.set('v_count', str(int(vc_any)))
                    except Exception:
                        pass

        # Final scenario-level aggregate
        try:
            total_nodes = scenario_host_additive + scenario_routing_total + scenario_vuln_total
            scen_el.set('scenario_total_nodes', str(total_nodes))
            scen_el.set('base_nodes', '0')
        except Exception:
            pass

    return ET.ElementTree(root)


def _validate_core_xml(xml_path: str):
    """Validate the scenario XML against the CORE XML XSD. Returns (ok, errors_text)."""
    try:
        # Derive project root relative to this file (../) then the validation directory
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, '..'))
        xsd_path = os.path.join(repo_root, 'validation', 'core-xml-syntax', 'corexml_codebased.xsd')
        # Fallback: if not found, try relative to current working directory (for unusual run contexts)
        if not os.path.exists(xsd_path):
            alt = os.path.abspath(os.path.join(os.getcwd(), 'validation', 'core-xml-syntax', 'corexml_codebased.xsd'))
            if os.path.exists(alt):
                xsd_path = alt
        if not os.path.exists(xsd_path):
            return False, f"Schema not found: {xsd_path}"
        with open(xsd_path, 'rb') as f:
            schema_doc = LET.parse(f)
        schema = LET.XMLSchema(schema_doc)
        # Read original XML; if it contains any <container> elements (session export artifacts),
        # strip them prior to validation so that user-provided or auto-exported session XML can
        # still be validated against the scenario schema. This addresses UI errors like:
        #   Element 'container': This element is not expected.
        # We purposefully do NOT mutate the source file on disk; sanitization is in-memory.
        try:
            raw_tree = LET.parse(xml_path)
            root = raw_tree.getroot()
            # Collect and remove any elements whose local-name is 'container'
            containers = root.xpath('.//*[local-name()="container"]')
            if containers:
                for el in containers:
                    parent = el.getparent()
                    if parent is not None:
                        parent.remove(el)
                # Validate sanitized tree
                try:
                    schema.assertValid(root)
                    return True, ''
                except LET.DocumentInvalid as e:
                    # Fall through to structured error collection below
                    err_log = e.error_log
                    lines = [f"{er.level_name} L{er.line}:C{er.column} - {er.message}" for er in err_log]
                    return False, "\n".join(lines) or str(e)
            else:
                # No <container>; validate normally using parser bound to schema for speed
                parser = LET.XMLParser(schema=schema)
                LET.parse(xml_path, parser)
                return True, ''
        except LET.XMLSyntaxError as e:  # low-level parse error before schema phase
            lines = []
            for err in e.error_log:
                lines.append(f"{err.level_name} L{err.line}:C{err.column} - {err.message}")
            return False, "\n".join(lines) or str(e)
    except LET.XMLSyntaxError as e:
        lines = []
        for err in e.error_log:
            lines.append(f"{err.level_name} L{err.line}:C{err.column} - {err.message}")
        return False, "\n".join(lines) or str(e)
    except Exception as e:
        return False, str(e)


def _analyze_core_xml(xml_path: str) -> Dict[str, Any]:
    """Extract a topology summary from a CORE session/scenario XML."""
    info: Dict[str, Any] = {}
    try:
        tree = LET.parse(xml_path)
        root = tree.getroot()

        def attrs(el, *names):
            return {n: el.get(n) for n in names if el.get(n) is not None}

        def local(tag: str) -> str:
            if not tag:
                return ''
            if '}' in tag:
                return tag.split('}', 1)[1]
            return tag

        def iter_by_local(el, lname: str):
            lname = lname.lower()
            for e in el.iter():
                if local(getattr(e, 'tag', '')).lower() == lname:
                    yield e

        # Combine device/node representations (session exports sometimes use <node>)
        candidates = list(iter_by_local(root, 'device')) + list(iter_by_local(root, 'node'))
        devices: list[Any] = []
        seen_ids: set[str] = set()
        for cand in candidates:
            ident = cand.get('id') or cand.get('name')
            key = str(ident).strip() if ident is not None else ''
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            devices.append(cand)

        networks = list(iter_by_local(root, 'network'))
        links = list(iter_by_local(root, 'link'))
        services = list(iter_by_local(root, 'service'))

        routing_edge_policies: list[dict] = []
        try:
            for sec in root.findall('.//section'):
                if (sec.get('name') or '').strip() != 'Routing':
                    continue
                for item in sec.findall('./item'):
                    r2r_edges = item.get('r2r_edges') or item.get('edges')
                    r2s_edges = item.get('r2s_edges')
                    if any([item.get('r2r_mode'), r2r_edges, item.get('r2s_mode'), r2s_edges]):
                        routing_edge_policies.append({
                            'r2r_mode': item.get('r2r_mode') or '',
                            'r2r_edges': int(r2r_edges) if (r2r_edges and r2r_edges.isdigit()) else None,
                            'r2s_mode': item.get('r2s_mode') or '',
                            'r2s_edges': int(r2s_edges) if (r2s_edges and r2s_edges.isdigit()) else None,
                            'protocol': item.get('selected') or '',
                        })
        except Exception:
            routing_edge_policies = []

        interface_store: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)

        def record_interface(node_ref: Any, iface_el: Any) -> None:
            node_key = str(node_ref or '').strip()
            if not node_key or iface_el is None:
                return
            try:
                attrs_iface = dict(getattr(iface_el, 'attrib', {}) or {})
            except Exception:
                attrs_iface = {}
            name_raw = (attrs_iface.get('name') or attrs_iface.get('id') or '').strip()
            if not name_raw:
                name_el = iface_el.find('./name') if hasattr(iface_el, 'find') else None
                if name_el is not None and getattr(name_el, 'text', None):
                    name_raw = name_el.text.strip()
            mac = (attrs_iface.get('mac') or '').strip()
            if not mac and hasattr(iface_el, 'find'):
                mac_el = iface_el.find('./mac')
                if mac_el is not None and getattr(mac_el, 'text', None):
                    mac = mac_el.text.strip()
            ip4 = (attrs_iface.get('ip4') or attrs_iface.get('ipv4') or '').strip()
            ip4_mask = (attrs_iface.get('ip4_mask') or attrs_iface.get('ipv4_mask') or '').strip()
            ip6 = (attrs_iface.get('ip6') or attrs_iface.get('ipv6') or '').strip()
            ip6_mask = (attrs_iface.get('ip6_mask') or attrs_iface.get('ipv6_mask') or '').strip()
            try:
                for addr in iface_el.findall('.//addr'):
                    addr_type = (addr.get('type') or addr.get('family') or '').lower()
                    addr_val = (addr.get('address') or addr.get('ip') or (addr.text or '')).strip()
                    mask_val = (addr.get('mask') or addr.get('prefix') or addr.get('netmask') or '').strip()
                    if not addr_val:
                        continue
                    if '6' in addr_type:
                        if not ip6:
                            ip6 = addr_val
                        if not ip6_mask:
                            ip6_mask = mask_val
                    else:
                        if not ip4:
                            ip4 = addr_val
                        if not ip4_mask:
                            ip4_mask = mask_val
                for addr in iface_el.findall('.//address'):
                    addr_val = (addr.get('value') or addr.get('address') or (addr.text or '')).strip()
                    mask_val = (addr.get('mask') or addr.get('prefix') or '').strip()
                    addr_type = (addr.get('type') or '').lower()
                    if not addr_val:
                        continue
                    if '6' in addr_type:
                        if not ip6:
                            ip6 = addr_val
                        if not ip6_mask:
                            ip6_mask = mask_val
                    else:
                        if not ip4:
                            ip4 = addr_val
                        if not ip4_mask:
                            ip4_mask = mask_val
            except Exception:
                pass
            if not any([name_raw, mac, ip4, ip6]):
                return
            stable_key = '|'.join([
                name_raw.lower(),
                ip4,
                ip6,
            ])
            existing = interface_store[node_key].get(stable_key)
            if existing:
                if mac and not existing.get('mac'):
                    existing['mac'] = mac
                if ip4_mask and not existing.get('ipv4_mask'):
                    existing['ipv4_mask'] = ip4_mask
                if ip6_mask and not existing.get('ipv6_mask'):
                    existing['ipv6_mask'] = ip6_mask
                if name_raw and not existing.get('name'):
                    existing['name'] = name_raw
                return
            interface_store[node_key][stable_key] = {
                'name': name_raw or None,
                'mac': mac or None,
                'ipv4': ip4 or None,
                'ipv4_mask': ip4_mask or None,
                'ipv6': ip6 or None,
                'ipv6_mask': ip6_mask or None,
            }

        id_to_name: Dict[str, str] = {}
        id_to_type: Dict[str, str] = {}
        id_to_services: Dict[str, list] = {}

        def coerce_device_id(raw_id: Any, fallback_index: int) -> str:
            value = str(raw_id).strip() if raw_id is not None else ''
            if value:
                return value
            return f"device_{fallback_index}"

        for idx, dev in enumerate(devices, start=1):
            did = coerce_device_id(dev.get('id') or dev.get('name'), idx)
            name_val = (dev.get('name') or '').strip()
            if not name_val and hasattr(dev, 'find'):
                name_el = dev.find('./name')
                if name_el is not None and getattr(name_el, 'text', None):
                    name_val = name_el.text.strip()
            type_val = (dev.get('type') or '').strip()
            if not type_val and hasattr(dev, 'find'):
                type_el = dev.find('./type') or dev.find('./model') or dev.find('./icon')
                if type_el is not None and getattr(type_el, 'text', None):
                    type_val = type_el.text.strip()
            id_to_name[did] = name_val or did
            id_to_type[did] = type_val or ''

            services_found: set[str] = set()
            try:
                for svc in dev.findall('./services/service'):
                    nm = (svc.get('name') or (svc.text or '')).strip()
                    if nm:
                        services_found.add(nm)
                for svc in dev.findall('./service'):
                    nm = (svc.get('name') or (svc.text or '')).strip()
                    if nm:
                        services_found.add(nm)
            except Exception:
                pass
            id_to_services[did] = sorted(services_found)

            try:
                for iface in dev.findall('.//interface'):
                    record_interface(did, iface)
                for iface in dev.findall('.//iface'):
                    record_interface(did, iface)
            except Exception:
                pass

        adj: Dict[str, set[str]] = defaultdict(set)

        def normalize_ref(value: Any) -> str:
            return str(value).strip() if value is not None else ''

        for link in links:
            n1 = normalize_ref(link.get('node1') or link.get('node1_id'))
            n2 = normalize_ref(link.get('node2') or link.get('node2_id'))
            if not n1 or not n2:
                try:
                    if not n1 and hasattr(link, 'find'):
                        iface1 = link.find('.//iface1')
                        if iface1 is not None:
                            n1 = normalize_ref(iface1.get('node') or iface1.get('device') or iface1.get('node_id'))
                    if not n2 and hasattr(link, 'find'):
                        iface2 = link.find('.//iface2')
                        if iface2 is not None:
                            n2 = normalize_ref(iface2.get('node') or iface2.get('device') or iface2.get('node_id'))
                except Exception:
                    pass
            if n1 and n2:
                adj[n1].add(n2)
                adj[n2].add(n1)
            try:
                for child in list(link):
                    tag = local(getattr(child, 'tag', '')).lower()
                    target = None
                    if tag in ('iface1', 'interface1'):
                        target = n1
                    elif tag in ('iface2', 'interface2'):
                        target = n2
                    elif tag in ('iface', 'interface'):
                        target = normalize_ref(child.get('node') or child.get('node_id') or child.get('device')) or n2
                    if target:
                        record_interface(target, child)
            except Exception:
                continue

        nodes: list[dict] = []
        for idx, dev in enumerate(devices, start=1):
            did = coerce_device_id(dev.get('id') or dev.get('name'), idx)
            raw_ifaces = interface_store.get(did, {})
            iface_entries = []
            for entry in raw_ifaces.values():
                cleaned = {k: v for k, v in entry.items() if v not in (None, '')}
                if cleaned:
                    iface_entries.append(cleaned)
            iface_entries.sort(key=lambda e: ((e.get('name') or '').lower(), e.get('ipv4') or '', e.get('ipv6') or ''))
            nodes.append({
                'id': did,
                'name': id_to_name.get(did, did),
                'type': id_to_type.get(did, ''),
                'services': id_to_services.get(did, []),
                'linked_nodes': [],
                'interfaces': iface_entries,
            })

        switches = [n for n in nodes if (n.get('type') or '').lower() == 'switch']
        extra_switch_nodes: list[dict] = []
        try:
            for net in networks:
                ntype = (net.get('type') or '').lower()
                if 'switch' not in ntype:
                    continue
                sw_id = normalize_ref(net.get('id') or net.get('name'))
                if not sw_id:
                    continue
                sw_name = (net.get('name') or sw_id).strip() or sw_id
                if any(sw_id == sw.get('id') or sw_name == sw.get('name') for sw in switches):
                    continue
                raw_ifaces = interface_store.get(sw_id, {})
                iface_entries = []
                for entry in raw_ifaces.values():
                    cleaned = {k: v for k, v in entry.items() if v not in (None, '')}
                    if cleaned:
                        iface_entries.append(cleaned)
                iface_entries.sort(key=lambda e: ((e.get('name') or '').lower(), e.get('ipv4') or '', e.get('ipv6') or ''))
                extra_switch = {
                    'id': sw_id,
                    'name': sw_name,
                    'type': 'switch',
                    'services': [],
                    'linked_nodes': [],
                    'interfaces': iface_entries,
                }
                switches.append(extra_switch)
                extra_switch_nodes.append(extra_switch)
                id_to_name.setdefault(sw_id, sw_name)
                id_to_type.setdefault(sw_id, 'switch')
        except Exception:
            pass

        valid_ids: set[str] = {n['id'] for n in nodes}
        valid_ids.update(sw['id'] for sw in extra_switch_nodes)
        adj_clean: Dict[str, set[str]] = {}
        for nid, neighbors in adj.items():
            if nid not in valid_ids:
                continue
            adj_clean[nid] = {nbr for nbr in neighbors if nbr in valid_ids}
        for sw in extra_switch_nodes:
            adj_clean.setdefault(sw['id'], set())

        def _prune_neighbors(node_id: str, node_type: str) -> None:
            if node_type in ('router', 'switch'):
                return
            current_neighbors = sorted(adj_clean.get(node_id, set()), key=lambda vid: id_to_name.get(vid, vid).lower())
            routers = [vid for vid in current_neighbors if (id_to_type.get(vid, '').lower() == 'router')]
            switches_local = [vid for vid in current_neighbors if (id_to_type.get(vid, '').lower() == 'switch')]

            def _trim_group(group: list[str]) -> None:
                if len(group) <= 1:
                    return
                keep = group[0]
                for extra in group[1:]:
                    adj_clean.get(node_id, set()).discard(extra)
                    if extra in adj_clean:
                        adj_clean[extra].discard(node_id)

            _trim_group(routers)
            _trim_group(switches_local)

        for node in nodes:
            _prune_neighbors(node['id'], (node.get('type') or '').lower())
        for sw in extra_switch_nodes:
            _prune_neighbors(sw['id'], (sw.get('type') or '').lower())

        def _neighbor_names(node_id: str) -> list[str]:
            neighbors = sorted(adj_clean.get(node_id, set()), key=lambda vid: id_to_name.get(vid, vid).lower())
            return [id_to_name.get(vid, vid) for vid in neighbors]

        filtered_nodes: list[dict] = []
        for node in nodes:
            nid = node['id']
            linked = adj_clean.get(nid, set())
            if linked or (node.get('interfaces') and len(node.get('interfaces')) > 0) or (node.get('type') or '').lower() in ('router', 'switch'):
                node['linked_nodes'] = _neighbor_names(nid)
                filtered_nodes.append(node)
        nodes = filtered_nodes

        filtered_extra_switch_nodes: list[dict] = []
        for sw in extra_switch_nodes:
            nid = sw['id']
            linked = adj_clean.get(nid, set())
            if linked:
                sw['linked_nodes'] = _neighbor_names(nid)
                filtered_extra_switch_nodes.append(sw)
        extra_switch_nodes = filtered_extra_switch_nodes

        valid_ids = {n['id'] for n in nodes}
        valid_ids.update(sw['id'] for sw in extra_switch_nodes)
        adj_clean = {nid: {nbr for nbr in neighbors if nbr in valid_ids} for nid, neighbors in adj_clean.items() if nid in valid_ids}

        switches = [n for n in nodes if (n.get('type') or '').lower() == 'switch']

        link_details: list[dict] = []
        seen_pairs: set[tuple[str, str]] = set()
        for src, neighbors in adj_clean.items():
            for dst in neighbors:
                if src == dst or dst not in valid_ids:
                    continue
                ordered = tuple(sorted((src, dst)))
                if ordered in seen_pairs:
                    continue
                seen_pairs.add(ordered)
                link_details.append({
                    'node1': ordered[0],
                    'node2': ordered[1],
                    'node1_name': id_to_name.get(ordered[0], ordered[0]),
                    'node2_name': id_to_name.get(ordered[1], ordered[1]),
                })

        info.update({
            'nodes_count': len(nodes),
            'networks_count': len(networks),
            'links_count': len(link_details),
            'services_count': len(services),
            'nodes': nodes,
            'switches_count': len(switches),
            'switches': [sw['name'] for sw in switches],
            'switch_nodes': extra_switch_nodes,
            'links_detail': link_details,
            'routing_edges_policies': routing_edge_policies,
        })
        info['devices'] = [attrs(d, 'id', 'name', 'type', 'class', 'image') for d in devices[:50]]
        info['networks'] = [attrs(n, 'id', 'name', 'type', 'model', 'mobility') for n in networks[:50]]
        info['links_sample'] = len(link_details)

        try:
            st = os.stat(xml_path)
            info['file_size_bytes'] = st.st_size
        except Exception:
            pass

        try:
            router_ids = [normalize_ref(dev.get('id')) for dev in devices if (dev.get('type') or '').lower().find('router') >= 0]
            degs = {rid: len(adj_clean.get(rid, set())) for rid in router_ids if rid}
            if degs:
                vals = list(degs.values())
                info['router_degree_stats'] = {
                    'min': min(vals),
                    'max': max(vals),
                    'avg': round(sum(vals) / len(vals), 2),
                    'per_router': degs,
                }
        except Exception:
            pass

        return info
    except Exception as e:
        return {'error': str(e)}


@app.route('/', methods=['GET'])
def index():
    payload = _default_scenarios_payload()
    # Reconstruct base_upload if base filepath already present
    _attach_base_upload(payload)
    _hydrate_base_upload_from_disk(payload)
    payload['host_interfaces'] = _enumerate_host_interfaces()
    if payload.get('base_upload'):
        _save_base_upload_state(payload['base_upload'])
    payload = _prepare_payload_for_index(payload)
    return render_template('index.html', payload=payload, logs="", xml_preview="")


@app.route('/load_xml', methods=['POST'])
def load_xml():
    file = request.files.get('scenarios_xml')
    if not file or file.filename == '':
        flash('No file selected.')
        return redirect(url_for('index'))
    if not allowed_file(file.filename):
        flash('Invalid file type. Only XML allowed.')
        return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)
    try:
        payload = _parse_scenarios_xml(filepath)
        # add default CORE connection parameters
        if "core" not in payload:
            payload["core"] = _default_core_dict()
        payload["result_path"] = filepath
        _attach_base_upload(payload)
        _hydrate_base_upload_from_disk(payload)
        payload['host_interfaces'] = _enumerate_host_interfaces()
        if payload.get('base_upload'):
            _save_base_upload_state(payload['base_upload'])
        xml_text = ""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        payload = _prepare_payload_for_index(payload)
        return render_template('index.html', payload=payload, logs="", xml_preview=xml_text)
    except Exception as e:
        flash(f'Failed to parse XML: {e}')
        return redirect(url_for('index'))


@app.route('/save_xml', methods=['POST'])
def save_xml():
    data_str = request.form.get('scenarios_json')
    if not data_str:
        flash('No data received.')
        return redirect(url_for('index'))
    try:
        data = json.loads(data_str)
    except Exception as e:
        flash(f'Invalid JSON: {e}')
        return redirect(url_for('index'))
    try:
        active_index = None
        try:
            active_index = int(data.get('active_index')) if 'active_index' in data else None
        except Exception:
            active_index = None
        tree = _build_scenarios_xml({ 'scenarios': data.get('scenarios') })
        ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        out_dir = os.path.join(_outputs_dir(), f'scenarios-{ts}')
        os.makedirs(out_dir, exist_ok=True)
        # Determine filename: <scenario-name>.xml (no timestamp in filename)
        try:
            scen_names = [s.get('name') for s in (data.get('scenarios') or []) if isinstance(s, dict) and s.get('name')]
        except Exception:
            scen_names = []
        chosen_name = None
        try:
            if active_index is not None and 0 <= active_index < len(scen_names):
                chosen_name = scen_names[active_index]
        except Exception:
            chosen_name = None
        stem_raw = (chosen_name or (scen_names[0] if scen_names else 'scenarios')) or 'scenarios'
        stem = secure_filename(stem_raw).strip('_-.') or 'scenarios'
        out_path = os.path.join(out_dir, f"{stem}.xml")
        # Pretty print if lxml available else fallback
        try:
            from lxml import etree as LET  # type: ignore
            raw = ET.tostring(tree.getroot(), encoding='utf-8')
            lroot = LET.fromstring(raw)
            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
            with open(out_path, 'wb') as f:
                f.write(pretty)
        except Exception:
            tree.write(out_path, encoding='utf-8', xml_declaration=True)
        # Read back XML content for preview
        xml_text = ""
        try:
            with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        flash(f'Scenarios saved as {os.path.basename(out_path)}')
        # Re-parse the saved XML to ensure the UI reflects exactly what was persisted
        try:
            payload = _parse_scenarios_xml(out_path)
            if "core" not in payload:
                payload["core"] = _default_core_dict()
            payload["result_path"] = out_path
        except Exception:
            payload = {"scenarios": data.get("scenarios", []), "result_path": out_path, "core": _default_core_dict()}
        payload['host_interfaces'] = _enumerate_host_interfaces()
        _attach_base_upload(payload)
        _hydrate_base_upload_from_disk(payload)
        if payload.get('base_upload'):
            _save_base_upload_state(payload['base_upload'])
        payload = _prepare_payload_for_index(payload)
        return render_template('index.html', payload=payload, logs="", xml_preview=xml_text)
    except Exception as e:
        flash(f'Failed to save XML: {e}')
        return redirect(url_for('index'))


@app.route('/save_xml_api', methods=['POST'])
def save_xml_api():
    try:
        data = request.get_json(silent=True) or {}
        scenarios = data.get('scenarios')
        active_index = None
        try:
            active_index = int(data.get('active_index')) if 'active_index' in data else None
        except Exception:
            active_index = None
        if not isinstance(scenarios, list):
            return jsonify({ 'ok': False, 'error': 'Invalid payload (scenarios list required)' }), 400
        tree = _build_scenarios_xml({ 'scenarios': scenarios })
        ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        out_dir = os.path.join(_outputs_dir(), f'scenarios-{ts}')
        os.makedirs(out_dir, exist_ok=True)
        # Determine filename: <scenario-name>.xml
        try:
            scen_names = [s.get('name') for s in scenarios if isinstance(s, dict) and s.get('name')]
        except Exception:
            scen_names = []
        chosen_name = None
        try:
            if active_index is not None and 0 <= active_index < len(scen_names):
                chosen_name = scen_names[active_index]
        except Exception:
            chosen_name = None
        stem_raw = (chosen_name or (scen_names[0] if scen_names else 'scenarios')) or 'scenarios'
        stem = secure_filename(stem_raw).strip('_-.') or 'scenarios'
        out_path = os.path.join(out_dir, f"{stem}.xml")
        # Pretty print when possible
        try:
            raw = ET.tostring(tree.getroot(), encoding='utf-8')
            lroot = LET.fromstring(raw)
            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
            with open(out_path, 'wb') as f:
                f.write(pretty)
        except Exception:
            tree.write(out_path, encoding='utf-8', xml_declaration=True)
        return jsonify({ 'ok': True, 'result_path': out_path })
    except Exception as e:
        try:
            app.logger.exception("[save_xml_api] failed: %s", e)
        except Exception:
            pass
        return jsonify({ 'ok': False, 'error': str(e) }), 500


@app.route('/run_cli', methods=['POST'])
def run_cli():
    xml_path = request.form.get('xml_path')
    if not xml_path:
        flash('XML path missing. Save XML first.')
        return redirect(url_for('index'))
    # Always resolve to absolute path
    xml_path = os.path.abspath(xml_path)
    # Path fallback: if user supplied /app/outputs but actual saved path lives under /app/webapp/outputs (volume mapping difference)
    if not os.path.exists(xml_path) and '/outputs/' in xml_path:
        try:
            # Replace first occurrence of '/app/outputs' with '/app/webapp/outputs'
            alt = xml_path.replace('/app/outputs', '/app/webapp/outputs')
            if alt != xml_path and os.path.exists(alt):
                app.logger.info("[sync] Remapped XML path %s -> %s", xml_path, alt)
                xml_path = alt
        except Exception:
            pass
    if not os.path.exists(xml_path):
        flash(f'XML path not found: {xml_path}')
        return redirect(url_for('index'))
    # Skip schema validation: format differs from CORE XML
    # Run gRPC CLI script (config2scen_core_grpc.py) instead of internal module
    try:
        # Attempt to parse current scenarios JSON (if present) to extract core host/port overrides
        core_host = '127.0.0.1'
        core_port = 50051
        try:
            # attempt to load previously saved payload for core info
            payload = _parse_scenarios_xml(xml_path)
            ch = payload.get('core', {}).get('host') if isinstance(payload.get('core'), dict) else None
            cp = payload.get('core', {}).get('port') if isinstance(payload.get('core'), dict) else None
            if ch: core_host = str(ch)
            if cp: core_port = int(cp)
        except Exception:
            pass
        app.logger.info("[sync] Running CLI with CORE %s:%s, xml=%s", core_host, core_port, xml_path)
        # Pre-save any existing active CORE session XML (best-effort) using derived host/port
        try:
            # Save pre-run session XML into a sibling 'core-pre' directory next to scenarios.xml
            pre_dir = os.path.join(os.path.dirname(xml_path) or _outputs_dir(), 'core-pre')
            pre_saved = _grpc_save_current_session_xml(core_host, core_port, pre_dir)
            if pre_saved:
                flash(f'Captured current CORE session XML: {os.path.basename(pre_saved)}')
                app.logger.debug("[sync] Pre-run session XML saved to %s", pre_saved)
        except Exception:
            pass
        repo_root = _get_repo_root()
        # Invoke package CLI so it can generate reports under repo_root/reports
        # Resolve python interpreter with fallback logic
        py_exec = _select_python_interpreter()
        app.logger.info("[sync] Using python interpreter: %s", py_exec)
        # Determine active scenario name (first in the saved editor XML) and pass to CLI
        active_scenario_name = None
        try:
            names_for_cli = _scenario_names_from_xml(xml_path)
            if names_for_cli:
                active_scenario_name = names_for_cli[0]
        except Exception:
            active_scenario_name = None
        cli_args = [py_exec, '-m', 'core_topo_gen.cli', '--xml', xml_path, '--host', core_host, '--port', str(core_port), '--verbose']
        if active_scenario_name:
            cli_args.extend(['--scenario', active_scenario_name])
        proc = subprocess.run(cli_args, cwd=repo_root, check=False, capture_output=True, text=True)
        logs = (proc.stdout or '') + ('\n' + proc.stderr if proc.stderr else '')
        app.logger.debug("[sync] CLI return code: %s", proc.returncode)
        # Report path (if generated by CLI): parse logs or fallback to latest under reports/
        report_md = _extract_report_path_from_text(logs) or _find_latest_report_path()
        if report_md:
            app.logger.info("[sync] Detected report path: %s", report_md)
        summary_json = _extract_summary_path_from_text(logs)
        if not summary_json:
            summary_json = _derive_summary_from_report(report_md)
        if not summary_json and not report_md:
            summary_json = _find_latest_summary_path()
        if summary_json and not os.path.exists(summary_json):
            summary_json = None
        if summary_json:
            app.logger.info("[sync] Detected summary path: %s", summary_json)
        # Try to capture the exact session id from logs for precise post-run save
        session_id = _extract_session_id_from_text(logs)
        if session_id:
            app.logger.info("[sync] Detected CORE session id: %s", session_id)
        # Read XML for preview
        xml_text = ""
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        run_success = (proc.returncode == 0)
        post_saved = None
        # Inform user
        if run_success:
            if report_md and os.path.exists(report_md):
                flash('CLI completed. Report ready to download.')
            else:
                flash('CLI completed. No report found.')
        else:
            flash('CLI finished with errors. See logs.')
        # Best-effort: save the active CORE session XML after run (try even on failures)
        try:
            post_dir = os.path.join(os.path.dirname(xml_path), 'core-post')
            post_saved = _grpc_save_current_session_xml(core_host, core_port, post_dir, session_id=session_id)
            if post_saved:
                flash(f'Captured post-run CORE session XML: {os.path.basename(post_saved)}')
                app.logger.debug("[sync] Post-run session XML saved to %s", post_saved)
        except Exception:
            post_saved = None
        payload = _parse_scenarios_xml(xml_path)
        if "core" not in payload:
            payload["core"] = _default_core_dict()
        _attach_base_upload(payload)
        # Always use absolute xml_path for result_path fallback
        payload["result_path"] = report_md if (report_md and os.path.exists(report_md)) else xml_path
        # Append run history entry regardless of intermediate failures; log details
        scen_names = []
        try:
            scen_names = _scenario_names_from_xml(xml_path)
        except Exception as e_names:
            app.logger.exception("[sync] failed extracting scenario names from %s: %s", xml_path, e_names)
        full_bundle_path = None
        single_scen_xml = None
        try:
            # Build a single-scenario XML containing only the active scenario to satisfy bundling constraint
            try:
                single_scen_xml = _write_single_scenario_xml(xml_path, (active_scenario_name or (scen_names[0] if scen_names else None)), out_dir=os.path.dirname(xml_path))
            except Exception:
                single_scen_xml = None
            bundle_xml = single_scen_xml or xml_path
            app.logger.info("[sync] Building full scenario archive (xml=%s, report=%s, pre=%s, post=%s)", bundle_xml, report_md, (pre_saved if 'pre_saved' in locals() else None), post_saved)
            full_bundle_path = _build_full_scenario_archive(
                os.path.dirname(bundle_xml),
                bundle_xml,
                (report_md if (report_md and os.path.exists(report_md)) else None),
                (pre_saved if 'pre_saved' in locals() else None),
                post_saved,
                summary_path=summary_json,
                run_id=None,
            )
        except Exception as e_bundle:
            app.logger.exception("[sync] failed building full scenario bundle: %s", e_bundle)
        try:
            session_xml_path = post_saved if (post_saved and os.path.exists(post_saved)) else None
            _append_run_history({
                'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                'mode': 'sync',
                'xml_path': xml_path,
                'post_xml_path': session_xml_path,
                'session_xml_path': session_xml_path,
                'scenario_xml_path': xml_path,
                'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
                'pre_xml_path': pre_saved if 'pre_saved' in locals() else None,
                'full_scenario_path': full_bundle_path,
                'single_scenario_xml_path': single_scen_xml,
                'returncode': proc.returncode,
                'scenario_names': scen_names,
            })
        except Exception as e_hist:
            app.logger.exception("[sync] failed appending run history: %s", e_hist)
        payload = _prepare_payload_for_index(payload)
        return render_template('index.html', payload=payload, logs=logs, xml_preview=xml_text, run_success=run_success)
    except Exception as e:
        flash(f'Error running core-topo-gen: {e}')
        return redirect(url_for('index'))


# ----------------------- Planning (Preview / Run) -----------------------



@app.route('/api/plan/preview_full', methods=['POST'])
def api_plan_preview_full():
    """Compute a full dry-run plan (no CORE session) including routers, hosts, IPs, services,
    vulnerabilities, segmentation slot preview and connectivity policies.

    Request JSON: { xml_path: "/abs/scenarios.xml", scenario: optionalName }
    Response: { ok, full_preview: {...} }
    """
    try:
        payload = request.get_json(silent=True) or {}
        xml_path = payload.get('xml_path')
        scenario = payload.get('scenario') or None
        seed = payload.get('seed')
        r2s_hosts_min_list = payload.get('r2s_hosts_min_list') or []
        r2s_hosts_max_list = payload.get('r2s_hosts_max_list') or []
        try:
            if seed is not None:
                seed = int(seed)
        except Exception:
            seed = None
        if not xml_path:
            return jsonify({'ok': False, 'error': 'xml_path missing'}), 400
        xml_path = os.path.abspath(xml_path)
        if not os.path.exists(xml_path):
            return jsonify({'ok': False, 'error': f'XML not found: {xml_path}'}), 404
        from core_topo_gen.planning.orchestrator import compute_full_plan
        from core_topo_gen.planning.plan_cache import hash_xml_file, try_get_cached_plan, save_plan_to_cache
        xml_hash = hash_xml_file(xml_path)
        plan = try_get_cached_plan(xml_hash, scenario, seed)
        if plan:
            app.logger.debug('[plan.preview_full] using cached plan (%s, scenario=%s, seed=%s)', xml_hash[:12], scenario, seed)
        else:
            plan = compute_full_plan(xml_path, scenario=scenario, seed=seed, include_breakdowns=True)
            try:
                save_plan_to_cache(xml_hash, scenario, seed, plan)
            except Exception as ce:
                app.logger.debug('[plan.preview_full] cache save failed: %s', ce)
        if seed is None:
            seed = plan.get('seed') or _derive_default_seed(xml_hash)
        full_prev = _build_full_preview_from_plan(plan, seed, r2s_hosts_min_list, r2s_hosts_max_list)
        xml_basename = os.path.splitext(os.path.basename(xml_path))[0]
        try:
            raw_hitl_config = parse_hitl_info(xml_path, scenario)
        except Exception as hitl_exc:
            try:
                app.logger.debug('[plan.preview_full] hitl parse failed: %s', hitl_exc)
            except Exception:
                pass
            raw_hitl_config = {"enabled": False, "interfaces": []}
        hitl_config = _sanitize_hitl_config(raw_hitl_config, scenario, xml_basename)
        try:
            full_prev['hitl_interfaces'] = hitl_config.get('interfaces', [])
            full_prev['hitl_enabled'] = bool(hitl_config.get('enabled'))
            full_prev['hitl_scenario_key'] = hitl_config.get('scenario_key')
        except Exception:
            pass
        try:
            _merge_hitl_preview_with_full_preview(full_prev, hitl_config)
        except Exception:
            pass
        return jsonify({'ok': True, 'full_preview': full_prev, 'plan': plan, 'breakdowns': plan.get('breakdowns')})
    except Exception as e:
        app.logger.exception('[plan.preview_full] error: %s', e)
        return jsonify({'ok': False, 'error': str(e) }), 500

@app.route('/plan/full_preview_page', methods=['POST'])
def plan_full_preview_page():
    """Generate a full preview and render a dedicated page similar to core_details but without CORE.

    Form fields: xml_path, optional scenario, seed
    """
    try:
        xml_path = request.form.get('xml_path')
        scenario = request.form.get('scenario') or None
        seed_raw = request.form.get('seed') or ''
        seed = None
        try:
            if seed_raw:
                s = int(seed_raw)
                if s>0: seed = s
        except Exception:
            seed = None
        if not xml_path:
            flash('xml_path missing (full preview page)')
            return redirect(url_for('index'))
        xml_path = os.path.abspath(xml_path)
        xml_basename = os.path.splitext(os.path.basename(xml_path))[0] if xml_path else ''
        if not os.path.exists(xml_path):
            flash(f'XML not found: {xml_path}')
            return redirect(url_for('index'))
        from core_topo_gen.planning.orchestrator import compute_full_plan
        from core_topo_gen.planning.plan_cache import hash_xml_file, try_get_cached_plan, save_plan_to_cache

        plan = None
        xml_hash = None
        try:
            xml_hash = hash_xml_file(xml_path)
            plan = try_get_cached_plan(xml_hash, scenario, seed)
            if plan:
                app.logger.debug('[plan.full_preview_page] using cached plan (%s, scenario=%s, seed=%s)', (xml_hash or '')[:12], scenario, seed)
        except Exception as cache_err:
            try:
                app.logger.debug('[plan.full_preview_page] cache lookup failed: %s', cache_err)
            except Exception:
                pass
            plan = None
        if not plan:
            plan = compute_full_plan(xml_path, scenario=scenario, seed=seed, include_breakdowns=True)
            try:
                if xml_hash is None:
                    xml_hash = hash_xml_file(xml_path)
                save_plan_to_cache(xml_hash, scenario, seed, plan)
            except Exception as cache_save_err:
                try:
                    app.logger.debug('[plan.full_preview_page] cache save failed: %s', cache_save_err)
                except Exception:
                    pass
        if seed is None:
            seed = plan.get('seed') or _derive_default_seed(xml_hash or hash_xml_file(xml_path))
        full_prev = _build_full_preview_from_plan(plan, seed, [], [])
        display_artifacts = full_prev.get('display_artifacts')
        if not display_artifacts:
            try:
                display_artifacts = _attach_display_artifacts(full_prev)
            except Exception:
                display_artifacts = {
                    'segmentation': {
                        'rows': [],
                        'table_rows': [],
                        'tableRows': [],
                        'json': {'rules_count': 0, 'types_summary': {}, 'rules': [], 'metadata': None},
                    },
                    '__version': FULL_PREVIEW_ARTIFACT_VERSION,
                }
        segmentation_artifacts = (display_artifacts or {}).get('segmentation')
        # Annotate & enforce enumerated host roles (Server, Workstation, PC) in preview
        # Full preview already receives normalized roles from planning layer
        # Attempt scenario name
        scenario_name = scenario or None
        if not scenario_name:
            try:
                names_for_cli = _scenario_names_from_xml(xml_path)
                if names_for_cli: scenario_name = names_for_cli[0]
            except Exception:
                pass
        try:
            raw_hitl_config = parse_hitl_info(xml_path, scenario_name)
        except Exception as hitl_exc:
            try:
                app.logger.debug('[plan.full_preview_page] hitl parse failed: %s', hitl_exc)
            except Exception:
                pass
            raw_hitl_config = {"enabled": False, "interfaces": []}
        hitl_config = _sanitize_hitl_config(raw_hitl_config, scenario_name, xml_basename)
        try:
            full_prev['hitl_interfaces'] = hitl_config.get('interfaces', [])
            full_prev['hitl_enabled'] = bool(hitl_config.get('enabled'))
            full_prev['hitl_scenario_key'] = hitl_config.get('scenario_key')
        except Exception:
            pass
        try:
            _merge_hitl_preview_with_full_preview(full_prev, hitl_config)
        except Exception:
            pass
        # Persist preview payload for downstream execution wiring
        preview_plan_path = None
        try:
            import json as _json
            plans_dir = os.path.join(_outputs_dir(), 'plans')
            os.makedirs(plans_dir, exist_ok=True)
            seed_tag = full_prev.get('seed') or 'preview'
            unique_tag = f"{seed_tag}_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            preview_plan_path = os.path.join(plans_dir, f"plan_from_preview_{unique_tag}.json")
            plan_payload = {
                'full_preview': full_prev,
                'metadata': {
                    'xml_path': xml_path,
                    'scenario': scenario_name,
                    'seed': full_prev.get('seed'),
                    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
                },
            }
            with open(preview_plan_path, 'w', encoding='utf-8') as pf:
                _json.dump(plan_payload, pf, indent=2, sort_keys=True)
        except Exception as plan_err:
            preview_plan_path = None
            try:
                app.logger.warning('[plan.full_preview_page] failed to persist preview plan: %s', plan_err)
            except Exception:
                pass
        # Provide JSON string for embedding (stringify smaller subset for safety)
        import json as _json
        preview_json_str = _json.dumps(full_prev, indent=2, default=str)
        return render_template(
            'full_preview.html',
            full_preview=full_prev,
            preview_json=preview_json_str,
            xml_path=xml_path,
            scenario=scenario_name,
            seed=full_prev.get('seed'),
            preview_plan_path=preview_plan_path,
            display_artifacts=display_artifacts,
            segmentation_artifacts=segmentation_artifacts,
            hitl_config=hitl_config,
            xml_basename=xml_basename,
        )
    except Exception as e:
        app.logger.exception('[plan.full_preview_page] error: %s', e)
        flash(f'Full preview page error: {e}')
        return redirect(url_for('index'))

def _plan_summary_from_full_preview(full_prev: dict) -> dict:
    try:
        role_counts = full_prev.get('role_counts') or {}
    except Exception:
        role_counts = {}
    hosts_total = len(full_prev.get('hosts') or [])
    routers_planned = len(full_prev.get('routers') or [])
    switches = full_prev.get('switches_detail') or []
    services_plan = full_prev.get('services_plan') or full_prev.get('services_preview') or {}
    vuln_plan = full_prev.get('vulnerabilities_plan') or full_prev.get('vulnerabilities_preview') or {}
    r2r_policy = full_prev.get('r2r_policy_preview') or {}
    r2s_policy = full_prev.get('r2s_policy_preview') or {}
    summary = {
        'hosts_total': hosts_total,
        'routers_planned': routers_planned,
        'hosts_allocated': 0,
        'routers_allocated': 0,
        'role_counts': role_counts,
        'services_plan': services_plan,
        'services_assigned': {},
        'vulnerabilities_plan': vuln_plan,
        'vulnerabilities_assigned': 0,
        'r2r_policy': r2r_policy,
        'r2s_policy': r2s_policy,
        'switches_allocated': len(switches),
        'notes': ['generated_from_full_preview'],
        'full_preview_seed': full_prev.get('seed'),
    }
    return summary

# --- Unified Preview Helpers (ensure modal JSON preview == full page preview) ---
def _derive_routing_policies(routing_items):
    """Derive R2R and R2S policies from routing items (first item wins)."""
    r2r_policy_plan = None
    r2s_policy_plan = None
    try:
        first_r2r = next((ri for ri in (routing_items or []) if getattr(ri,'r2r_mode',None)), None)  # type: ignore
        if first_r2r:
            m = getattr(first_r2r, 'r2r_mode', '')
            if m == 'Exact' and getattr(first_r2r, 'r2r_edges', 0) > 0:
                r2r_policy_plan = { 'mode': 'Exact', 'target_degree': int(getattr(first_r2r,'r2r_edges',0)) }
            elif m:
                r2r_policy_plan = { 'mode': m }
        first_r2s = next((ri for ri in (routing_items or []) if getattr(ri,'r2s_mode',None)), None)  # type: ignore
        if first_r2s:
            m2 = getattr(first_r2s, 'r2s_mode', '')
            if m2 == 'Exact' and getattr(first_r2s, 'r2s_edges', 0) > 0:
                r2s_policy_plan = { 'mode': 'Exact', 'target_per_router': int(getattr(first_r2s,'r2s_edges',0)) }
            elif m2:
                r2s_policy_plan = { 'mode': m2 }
    except Exception:
        pass
    return r2r_policy_plan, r2s_policy_plan

def _json_ready(value):
    """Convert nested objects into JSON-friendly primitives (recursively)."""
    if isinstance(value, dict):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_ready(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, '__dict__'):
        try:
            return {k: _json_ready(v) for k, v in vars(value).items() if not k.startswith('_')}
        except Exception:
            pass
    try:
        return str(value)
    except Exception:
        return repr(value)


def _summarize_seg_rule(rule_dict: dict) -> str:
    if not isinstance(rule_dict, dict):
        return ''
    type_raw = rule_dict.get('type') or rule_dict.get('action') or ''
    type_str = str(type_raw).strip()
    if not type_str:
        return ''
    lower = type_str.lower()
    if lower == 'nat':
        mode = str(rule_dict.get('mode')).strip() if rule_dict.get('mode') not in (None, '') else ''
        internal = rule_dict.get('internal') or rule_dict.get('internal_subnet') or ''
        external = rule_dict.get('external') or rule_dict.get('external_subnet') or ''
        parts = []
        if mode:
            parts.append(mode)
        if internal:
            parts.append(str(internal))
        summary = ' '.join(parts)
        if internal and external:
            summary = f"{summary} -> {external}" if summary else f"{internal} -> {external}"
        elif external:
            summary = f"{summary} {external}".strip()
        return summary.strip()
    if lower == 'host_block':
        src = rule_dict.get('src') or rule_dict.get('source') or ''
        dst = rule_dict.get('dst') or rule_dict.get('destination') or ''
        return f"{src} X {dst}".strip()
    if lower == 'custom':
        desc = rule_dict.get('description') or rule_dict.get('summary') or ''
        desc_str = str(desc).strip()
        return desc_str or 'custom'
    src = rule_dict.get('src') or rule_dict.get('source')
    dst = rule_dict.get('dst') or rule_dict.get('destination')
    if src or dst:
        return f"{type_str}: {src or '*'} -> {dst or '*'}"
    return type_str


def _build_segmentation_display_artifacts(full_preview: dict) -> dict:
    seg_preview = {}
    try:
        seg_preview = _json_ready((full_preview or {}).get('segmentation_preview') or {})
    except Exception:
        seg_preview = {}
    raw_rules = []
    if isinstance(seg_preview, dict):
        raw_rules = seg_preview.get('rules') or []
    if not isinstance(raw_rules, list):
        raw_rules = []
    entries = []
    type_counts = {}
    for raw_entry in raw_rules:
        entry = _json_ready(raw_entry)
        if not isinstance(entry, dict):
            continue
        rule_dict = entry.get('rule')
        if rule_dict is None:
            rule_dict = entry
        rule_dict = _json_ready(rule_dict)
        if not isinstance(rule_dict, dict):
            continue
        node_id = entry.get('node_id', rule_dict.get('node_id'))
        rule_type = rule_dict.get('type') or rule_dict.get('action')
        rule_type_str = str(rule_type) if rule_type not in (None, '') else None
        summary = _summarize_seg_rule(rule_dict)
        script_path = entry.get('script') or rule_dict.get('script')
        if not isinstance(script_path, str):
            script_path = None
        script_name = os.path.basename(script_path) if script_path else None
        table_row = {
            'node_id': node_id,
            'type': rule_type_str,
            'summary': summary,
            'src': rule_dict.get('src') or rule_dict.get('source'),
            'dst': rule_dict.get('dst') or rule_dict.get('destination'),
            'subnet': rule_dict.get('subnet'),
            'internal': rule_dict.get('internal') or rule_dict.get('internal_subnet'),
            'external': rule_dict.get('external') or rule_dict.get('external_subnet'),
            'proto': rule_dict.get('proto') or rule_dict.get('protocol'),
            'port': rule_dict.get('port'),
            'script_path': script_path,
            'script_name': script_name,
            'detail': rule_dict,
        }
        entries.append(table_row)
        key = rule_type_str or 'unknown'
        type_counts[key] = type_counts.get(key, 0) + 1
    metadata = None
    if isinstance(seg_preview, dict):
        metadata = {k: v for k, v in seg_preview.items() if k != 'rules'}
        if not metadata:
            metadata = None
    result = {
        'rows': [{'node_id': e['node_id'], 'type': e['type'], 'summary': e['summary']} for e in entries],
        'table_rows': entries,
        'tableRows': entries,
        'json': {
            'rules_count': len(entries),
            'types_summary': type_counts,
            'rules': [
                {
                    'node_id': e['node_id'],
                    'type': e['type'],
                    'summary': e['summary'],
                    'detail': e['detail'],
                }
                for e in entries
            ],
            'metadata': metadata,
        },
    }
    return result


def _attach_display_artifacts(full_preview: dict) -> dict:
    artifacts = {
        'segmentation': _build_segmentation_display_artifacts(full_preview),
        '__version': FULL_PREVIEW_ARTIFACT_VERSION,
    }
    if isinstance(full_preview, dict):
        full_preview['display_artifacts'] = artifacts
        full_preview['display_artifacts_version'] = FULL_PREVIEW_ARTIFACT_VERSION
    return artifacts


def _build_full_preview_from_plan(plan: dict, seed, r2s_hosts_min_list=None, r2s_hosts_max_list=None):
    """Single source of truth to invoke build_full_preview using a compute_full_plan result."""
    try:
        from core_topo_gen.planning.full_preview import build_full_preview  # lazy import
    except ModuleNotFoundError:
        if _ensure_full_preview_module():
            from core_topo_gen.planning.full_preview import build_full_preview  # type: ignore
        else:
            raise
    role_counts = plan['role_counts']
    prelim_router_count = plan['routers_planned']
    routing_items = plan.get('routing_items') or []
    service_plan = plan.get('service_plan') or {}
    vplan = plan.get('vulnerability_plan') or {}
    seg_items_serial = plan.get('breakdowns', {}).get('segmentation', {}).get('raw_items_serialized') or []
    seg_density = plan.get('breakdowns', {}).get('segmentation', {}).get('density')
    r2r_policy_plan, r2s_policy_plan = _derive_routing_policies(routing_items)
    fp = build_full_preview(
        role_counts=role_counts,
        routers_planned=prelim_router_count,
        services_plan=service_plan,
        vulnerabilities_plan=vplan,
        r2r_policy=r2r_policy_plan,
        r2s_policy=r2s_policy_plan,
        routing_items=routing_items,
        routing_plan=plan.get('breakdowns', {}).get('router', {}).get('simple_plan', {}),
        segmentation_density=seg_density,
        segmentation_items=seg_items_serial,
        traffic_plan=plan.get('traffic_plan'),
        seed=seed,
        ip4_prefix='10.0.0.0/24',
        r2s_hosts_min_list=r2s_hosts_min_list,
        r2s_hosts_max_list=r2s_hosts_max_list,
        base_scenario=plan.get('base_scenario'),
    )
    fp['router_plan'] = plan.get('breakdowns', {}).get('router', {})
    try:
        _attach_display_artifacts(fp)
    except Exception:
        pass
    return fp


@app.route('/api/open_scripts', methods=['GET'])
def api_open_scripts():
    """Return a listing of traffic or segmentation script directory contents.

    Query params: kind=traffic|segmentation
    """
    kind = request.args.get('kind','traffic').lower()
    scope = request.args.get('scope','runtime').lower()  # runtime|preview
    if kind not in ('traffic','segmentation'):
        return jsonify({'ok': False, 'error': 'invalid kind'}), 400
    if scope == 'preview':
        # Look for latest preview dir (deterministic naming core-topo-preview-*)
        import tempfile, glob
        base = tempfile.gettempdir()
        pattern = 'core-topo-preview-traffic-*' if kind=='traffic' else 'core-topo-preview-seg-*'
        candidates = sorted(glob.glob(os.path.join(base, pattern)), key=lambda p: os.path.getmtime(p), reverse=True)
        path = candidates[0] if candidates else None
        if not path:
            return jsonify({'ok': False, 'error': 'no preview dir found for kind', 'pattern': pattern}), 404
    else:
        path = '/tmp/traffic' if kind == 'traffic' else '/tmp/segmentation'
    if not os.path.isdir(path):
        return jsonify({'ok': False, 'error': 'directory does not exist', 'path': path}), 404
    files = []
    try:
        for name in sorted(os.listdir(path)):
            fp = os.path.join(path, name)
            if not os.path.isfile(fp):
                continue
            try:
                sz = os.path.getsize(fp)
            except Exception:
                sz = 0
            files.append({'file': name, 'size': sz})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    return jsonify({'ok': True, 'kind': kind, 'path': path, 'files': files})

@app.route('/api/open_script_file', methods=['GET'])
def api_open_script_file():
    """Return (truncated) contents of a requested script file.

    Query params: kind=traffic|segmentation, scope=runtime|preview, file=<filename>
    """
    kind = request.args.get('kind','traffic').lower()
    scope = request.args.get('scope','runtime').lower()
    fname = request.args.get('file') or ''
    if kind not in ('traffic','segmentation'):
        return jsonify({'ok': False, 'error': 'invalid kind'}), 400
    if not fname or '/' in fname or '..' in fname:
        return jsonify({'ok': False, 'error': 'invalid filename'}), 400
    if scope == 'preview':
        import tempfile, glob
        base = tempfile.gettempdir()
        pattern = 'core-topo-preview-traffic-*' if kind=='traffic' else 'core-topo-preview-seg-*'
        candidates = sorted(glob.glob(os.path.join(base, pattern)), key=lambda p: os.path.getmtime(p), reverse=True)
        path = candidates[0] if candidates else None
    else:
        path = '/tmp/traffic' if kind == 'traffic' else '/tmp/segmentation'
    if not path or not os.path.isdir(path):
        return jsonify({'ok': False, 'error': 'dir not found', 'path': path}), 404
    fp = os.path.join(path, fname)
    if not os.path.isfile(fp):
        return jsonify({'ok': False, 'error': 'file not found', 'file': fname}), 404
    try:
        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(8000)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    return jsonify({'ok': True, 'file': fname, 'path': path, 'content': content, 'truncated': len(content)==8000})

@app.route('/api/download_scripts', methods=['GET'])
def api_download_scripts():
    """Download a zip of segmentation or traffic scripts (preview or runtime).

    Query: kind=traffic|segmentation scope=runtime|preview
    """
    kind = request.args.get('kind','traffic').lower()
    scope = request.args.get('scope','runtime').lower()
    if kind not in ('traffic','segmentation'):
        return jsonify({'ok': False, 'error': 'invalid kind'}), 400
    if scope not in ('runtime','preview'):
        return jsonify({'ok': False, 'error': 'invalid scope'}), 400
    # Resolve directory
    if scope == 'runtime':
        base_dir = '/tmp/traffic' if kind=='traffic' else '/tmp/segmentation'
    else:
        import tempfile, glob
        pattern = 'core-topo-preview-traffic-*' if kind=='traffic' else 'core-topo-preview-seg-*'
        cands = sorted(glob.glob(os.path.join(tempfile.gettempdir(), pattern)), key=lambda p: os.path.getmtime(p), reverse=True)
        base_dir = cands[0] if cands else None
    if not base_dir or not os.path.isdir(base_dir):
        return jsonify({'ok': False, 'error': 'directory not found'}), 404
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(base_dir):
            for f in files:
                fp = os.path.join(root, f)
                # avoid huge non-script artifacts except summary json
                if not (f.endswith('.py') or f.endswith('.json')):
                    continue
                arc = os.path.relpath(fp, base_dir)
                try:
                    zf.write(fp, arc)
                except Exception:
                    continue
    buf.seek(0)
    from flask import send_file as _send_file
    filename = f"{kind}_{scope}_scripts.zip"
    return _send_file(buf, mimetype='application/zip', as_attachment=True, download_name=filename)

@app.route('/download_report')
def download_report():
    result_path = request.args.get('path')
    # Normalize incoming value: strip quotes, decode percent-encoding, handle file://, expand ~
    try:
        if result_path:
            # strip surrounding quotes if present
            if (result_path.startswith('"') and result_path.endswith('"')) or (result_path.startswith("'") and result_path.endswith("'")):
                result_path = result_path[1:-1]
            # convert file:// URIs
            if result_path.startswith('file://'):
                result_path = result_path[len('file://'):]
            # percent-decode
            try:
                from urllib.parse import unquote
                result_path = unquote(result_path)
            except Exception:
                pass
            # expand ~ and normalize slashes
            result_path = os.path.expanduser(result_path)
            result_path = os.path.normpath(result_path)
    except Exception:
        pass
    # Attempt to resolve common path variants to absolute existing file
    candidates = []
    if result_path:
        candidates.append(result_path)
        # Absolute from repo root if provided as repo-relative
        try:
            repo_root = _get_repo_root()
            if not os.path.isabs(result_path):
                candidates.append(os.path.abspath(os.path.join(repo_root, result_path)))
            # Also try if client included an extra 'webapp/' segment
            if result_path.startswith('webapp' + os.sep):
                candidates.append(os.path.abspath(os.path.join(repo_root, result_path)))
                # Strip 'webapp/' and try from repo root
                candidates.append(os.path.abspath(os.path.join(repo_root, result_path.split(os.sep, 1)[-1])))
            # If path looks like outputs/<...>, join with configured outputs dir
            if result_path.startswith('outputs' + os.sep):
                candidates.append(os.path.abspath(os.path.join(_outputs_dir(), result_path.split(os.sep, 1)[-1])))
            # If absolute path contains '/webapp/outputs/...', remap to configured outputs dir
            rp_norm = os.path.normpath(result_path)
            parts = rp_norm.strip(os.sep).split(os.sep)
            if os.path.isabs(result_path) and 'outputs' in parts:
                try:
                    idx = parts.index('outputs')
                    tail = os.path.join(*parts[idx+1:]) if idx+1 < len(parts) else ''
                    candidates.append(os.path.join(_outputs_dir(), tail))
                except Exception:
                    pass
            if os.path.isabs(result_path) and 'webapp' in parts:
                # Remove the 'webapp' segment entirely
                parts_wo = [p for p in parts if p != 'webapp']
                candidates.append(os.path.sep + os.path.join(*parts_wo))
            # If the path already lives under our configured outputs dir but with different root, try direct mapping
            try:
                outputs_dir = os.path.abspath(_outputs_dir())
                if os.path.isabs(result_path) and 'core-sessions' in parts and not result_path.startswith(outputs_dir):
                    # replace everything up to 'core-sessions' with outputs_dir/core-sessions
                    idx = parts.index('core-sessions')
                    tail = os.path.join(*parts[idx+1:]) if idx+1 < len(parts) else ''
                    candidates.append(os.path.join(outputs_dir, 'core-sessions', tail))
            except Exception:
                pass
        except Exception:
            pass
    # Pick the first existing path
    chosen = None
    for p in candidates:
        if p and os.path.exists(p):
            chosen = p
            break
    if chosen:
        try:
            app.logger.info("[download] serving file: %s", os.path.abspath(chosen))
        except Exception:
            pass
        return send_file(chosen, as_attachment=True)
    # Fallback: try to match by basename within outputs/core-sessions and outputs/scenarios-*
    try:
        # Log diagnostics about missing primary candidates
        app.logger.warning("[download] file not found via direct candidates; requested=%s; candidates=%s", result_path, candidates)
    except Exception:
        pass
    try:
        base_name = None
        try:
            base_name = os.path.basename(result_path) if result_path else None
        except Exception:
            base_name = None
        if base_name and base_name.lower().endswith('.xml'):
            candidates_found = []
            # Search core-sessions
            root_dir = os.path.join(_outputs_dir(), 'core-sessions')
            if os.path.exists(root_dir):
                for dp, _dn, files in os.walk(root_dir):
                    for fn in files:
                        if fn == base_name:
                            alt = os.path.join(dp, fn)
                            if os.path.exists(alt):
                                candidates_found.append(alt)
            # Search scenarios-* (Scenario Editor saves)
            out_dir = _outputs_dir()
            if os.path.exists(out_dir):
                try:
                    for name in os.listdir(out_dir):
                        if not name.startswith('scenarios-'):
                            continue
                        p = os.path.join(out_dir, name)
                        if not os.path.isdir(p):
                            continue
                        for dp, _dn, files in os.walk(p):
                            for fn in files:
                                if fn == base_name:
                                    alt = os.path.join(dp, fn)
                                    if os.path.exists(alt):
                                        candidates_found.append(alt)
                except Exception:
                    pass
            if candidates_found:
                # Prefer the newest by mtime
                try:
                    candidates_found.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
                except Exception:
                    pass
                chosen_alt = candidates_found[0]
                app.logger.info("[download] basename match: %s -> %s", base_name, chosen_alt)
                return send_file(chosen_alt, as_attachment=True)
    except Exception:
        pass
    app.logger.warning("[download] file not found: %s (candidates=%s)", result_path, candidates)
    return "File not found", 404

@app.route('/reports')
def reports_page():
    raw = _load_run_history()
    enriched = []
    for entry in raw:
        e = dict(entry)
        # Keep xml_path as stored (session xml only if available)
        if 'scenario_names' not in e:
            # Prefer names parsed from the Scenario Editor XML, fall back to session xml if missing
            src_xml = e.get('scenario_xml_path') or e.get('xml_path')
            e['scenario_names'] = _scenario_names_from_xml(src_xml)
        # Normalize session xml pointer for UI compatibility
        session_xml = e.get('session_xml_path') or e.get('post_xml_path')
        if session_xml:
            e['session_xml_path'] = session_xml
        if not e.get('summary_path'):
            derived_summary = _derive_summary_from_report(e.get('report_path'))
            if derived_summary:
                e['summary_path'] = derived_summary
        # Hardening: ensure scenario_names is always a list
        sn = e.get('scenario_names')
        if not isinstance(sn, list):
            if sn is None:
                e['scenario_names'] = []
            elif isinstance(sn, str):
                # Split comma or pipe delimited legacy forms
                if '||' in sn:
                    e['scenario_names'] = [s for s in sn.split('||') if s]
                else:
                    e['scenario_names'] = [s.strip() for s in sn.split(',') if s.strip()]
            else:
                e['scenario_names'] = []
        enriched.append(e)
    enriched = sorted(enriched, key=lambda x: x.get('timestamp',''), reverse=True)
    # collect unique scenario names
    scen_names: list[str] = []
    for e in enriched:
        for n in e.get('scenario_names', []) or []:
            if n not in scen_names:
                scen_names.append(n)
    return render_template('reports.html', history=enriched, scenarios=scen_names)

@app.route('/reports_data')
def reports_data():
    raw = _load_run_history()
    enriched = []
    scen_names: set[str] = set()
    for entry in raw:
        e = dict(entry)
        # Keep xml_path as stored (session xml only if available)
        if 'scenario_names' not in e:
            src_xml = e.get('scenario_xml_path') or e.get('xml_path')
            e['scenario_names'] = _scenario_names_from_xml(src_xml)
        session_xml = e.get('session_xml_path') or e.get('post_xml_path')
        if session_xml:
            e['session_xml_path'] = session_xml
        if not e.get('summary_path'):
            derived_summary = _derive_summary_from_report(e.get('report_path'))
            if derived_summary:
                e['summary_path'] = derived_summary
        # Hardening: normalize scenario_names to list
        sn = e.get('scenario_names')
        if not isinstance(sn, list):
            if sn is None:
                e['scenario_names'] = []
            elif isinstance(sn, str):
                if '||' in sn:
                    e['scenario_names'] = [s for s in sn.split('||') if s]
                else:
                    e['scenario_names'] = [s.strip() for s in sn.split(',') if s.strip()]
            else:
                e['scenario_names'] = []
        for n in e.get('scenario_names', []) or []:
            scen_names.add(n)
        enriched.append(e)
    enriched = sorted(enriched, key=lambda x: x.get('timestamp',''), reverse=True)
    return jsonify({ 'history': enriched, 'scenarios': sorted(list(scen_names)) })

@app.route('/reports/delete', methods=['POST'])
def reports_delete():
    """Delete run history entries by run_id and remove associated artifacts under outputs/.
    Does not delete files under ./reports (reports are preserved by policy).
    Body: { "run_ids": ["...", ...] }
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        run_ids = payload.get('run_ids') or []
        if not isinstance(run_ids, list):
            return jsonify({ 'error': 'run_ids must be a list' }), 400
        run_ids_set = set([str(x) for x in run_ids if x])
        if not run_ids_set:
            return jsonify({ 'deleted': 0 })
        history = _load_run_history()
        kept = []
        deleted_count = 0
        outputs_dir = _outputs_dir()
        for entry in history:
            rid = str(entry.get('run_id') or '')
            # fallback composite id to support entries without run_id
            rid_fallback = "|".join([
                str(entry.get('timestamp') or ''),
                str(entry.get('scenario_xml_path') or entry.get('xml_path') or ''),
                str(entry.get('report_path') or ''),
                str(entry.get('full_scenario_path') or ''),
            ])
            if (rid and rid in run_ids_set) or (rid_fallback and rid_fallback in run_ids_set):
                # Delete artifacts scoped to outputs/ only
                for key in ('full_scenario_path','scenario_xml_path','pre_xml_path','post_xml_path','xml_path','single_scenario_xml_path'):
                    p = entry.get(key)
                    if not p: continue
                    try:
                        ap = os.path.abspath(p)
                        if ap.startswith(os.path.abspath(outputs_dir)) and os.path.exists(ap):
                            try:
                                os.remove(ap)
                                app.logger.info("[reports.delete] removed %s", ap)
                            except IsADirectoryError:
                                # just in case, do not remove directories recursively here
                                app.logger.warning("[reports.delete] skipping directory %s", ap)
                    except Exception as e:
                        app.logger.warning("[reports.delete] error removing %s: %s", p, e)
                deleted_count += 1
            else:
                kept.append(entry)
        # Persist pruned history
        os.makedirs(os.path.dirname(RUN_HISTORY_PATH), exist_ok=True)
        tmp = RUN_HISTORY_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(kept, f, indent=2)
        os.replace(tmp, RUN_HISTORY_PATH)
        return jsonify({ 'deleted': deleted_count })
    except Exception as e:
        app.logger.exception("[reports.delete] failed: %s", e)
        return jsonify({ 'error': 'internal error' }), 500


@app.route('/run_cli_async', methods=['POST'])
def run_cli_async():
    seed = None
    xml_path = None
    preview_plan_path = None
    # Prefer form fields (existing UI) but fall back to JSON
    if request.form:
        xml_path = request.form.get('xml_path')
        raw_seed = request.form.get('seed')
        if raw_seed:
            try: seed = int(raw_seed)
            except Exception: seed = None
        preview_plan_path = request.form.get('preview_plan') or preview_plan_path
    if not xml_path:
        try:
            j = request.get_json(silent=True) or {}
            xml_path = j.get('xml_path')
            if 'seed' in j:
                try: seed = int(j.get('seed'))
                except Exception: seed = None
            if 'preview_plan' in j and not preview_plan_path:
                preview_plan_path = j.get('preview_plan')
        except Exception:
            pass
    if not xml_path:
        return jsonify({"error": "XML path missing. Save XML first."}), 400
    xml_path = os.path.abspath(xml_path)
    if not os.path.exists(xml_path) and '/outputs/' in xml_path:
        try:
            alt = xml_path.replace('/app/outputs', '/app/webapp/outputs')
            if alt != xml_path and os.path.exists(alt):
                app.logger.info("[async] Remapped XML path %s -> %s", xml_path, alt)
                xml_path = alt
        except Exception:
            pass
    if not os.path.exists(xml_path):
        return jsonify({"error": f"XML path not found: {xml_path}"}), 400
    preview_plan_path = (preview_plan_path or '').strip() or None
    if preview_plan_path:
        try:
            preview_plan_path = os.path.abspath(preview_plan_path)
            plans_dir = os.path.abspath(os.path.join(_outputs_dir(), 'plans'))
            if os.path.commonpath([preview_plan_path, plans_dir]) != plans_dir:
                app.logger.warning('[async] preview plan outside allowed directory: %s', preview_plan_path)
                preview_plan_path = None
            elif not os.path.exists(preview_plan_path):
                app.logger.warning('[async] preview plan path missing: %s', preview_plan_path)
                preview_plan_path = None
        except Exception:
            preview_plan_path = None
    # Skip schema validation: format differs from CORE XML
    run_id = str(uuid.uuid4())
    out_dir = os.path.dirname(xml_path)
    log_path = os.path.join(out_dir, f'cli-{run_id}.log')
    env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
    # Redirect output directly to log file for easy tailing
    # Open log file in line-buffered mode so subprocess logging (stdout+stderr) flushes promptly for UI streaming
    try:
        log_f = open(log_path, 'w', encoding='utf-8', buffering=1)
    except Exception:
        # Fallback to default buffering if line buffering not available
        log_f = open(log_path, 'w', encoding='utf-8')
    try:
        app.logger.debug("[async] Opened CLI log (line-buffered) at %s", log_path)
    except Exception:
        pass
    app.logger.info("[async] Starting CLI; log: %s", log_path)
    # derive core host/port (best-effort) from synchronous parse
    core_host = '127.0.0.1'
    core_port = 50051
    try:
        payload = _parse_scenarios_xml(xml_path)
        ch = payload.get('core', {}).get('host') if isinstance(payload.get('core'), dict) else None
        cp = payload.get('core', {}).get('port') if isinstance(payload.get('core'), dict) else None
        if ch: core_host = str(ch)
        if cp: core_port = int(cp)
    except Exception:
        pass
    # Attempt pre-save of current CORE session xml (best-effort) using derived host/port
    pre_saved = None
    try:
        pre_dir = os.path.join(out_dir or _outputs_dir(), 'core-pre')
        pre_saved = _grpc_save_current_session_xml(core_host, core_port, pre_dir)
    except Exception:
        pre_saved = None
    if pre_saved:
        app.logger.debug("[async] Pre-run session XML saved to %s", pre_saved)
    # Capture scenario names from the editor XML now (CORE post XML will not be parsable by our scenarios parser)
    scen_names = _scenario_names_from_xml(xml_path)
    repo_root = _get_repo_root()
    # Use package CLI module invocation
    py_exec = _select_python_interpreter()
    app.logger.info("[async] Using python interpreter: %s", py_exec)
    # Determine active scenario name and pass to CLI
    active_scenario_name = scen_names[0] if (scen_names and len(scen_names) > 0) else None
    args = [py_exec, '-u', '-m', 'core_topo_gen.cli', '--xml', xml_path, '--host', core_host, '--port', str(core_port), '--verbose']
    if seed is not None:
        args.extend(['--seed', str(seed)])
    if active_scenario_name:
        args.extend(['--scenario', active_scenario_name])
    if preview_plan_path:
        args.extend(['--preview-plan', preview_plan_path])
    proc = subprocess.Popen(args, cwd=repo_root, stdout=log_f, stderr=subprocess.STDOUT, env=env)
    RUNS[run_id] = {
        'proc': proc,
        'log_path': log_path,
        'xml_path': xml_path,
        'done': False,
        'returncode': None,
        'pre_xml_path': pre_saved,
        'repo_root': repo_root,
        'core_host': core_host,
        'core_port': core_port,
        'scenario_names': scen_names,
        'post_xml_path': None,
        'history_added': False,
        'preview_plan_path': preview_plan_path,
        'summary_path': None,
    }
    # Start a background finalizer so history is appended even if the UI does not poll /run_status
    def _wait_and_finalize_async(run_id_local: str):
        try:
            meta = RUNS.get(run_id_local)
            if not meta:
                return
            p = meta.get('proc')
            if not p:
                return
            rc = p.wait()
            meta['done'] = True
            meta['returncode'] = rc
            # mirror the logic in run_status to extract artifacts and append history
            try:
                xml_path_local = meta.get('xml_path')
                report_md = None
                txt = ''
                try:
                    lp = meta.get('log_path')
                    if lp and os.path.exists(lp):
                        with open(lp, 'r', encoding='utf-8', errors='ignore') as f:
                            txt = f.read()
                        report_md = _extract_report_path_from_text(txt)
                except Exception:
                    report_md = None
                if not report_md:
                    report_md = _find_latest_report_path()
                if report_md:
                    app.logger.info("[async-finalizer] Detected report path: %s", report_md)
                summary_json = _extract_summary_path_from_text(txt)
                if not summary_json:
                    summary_json = _derive_summary_from_report(report_md)
                if not summary_json and not report_md:
                    summary_json = _find_latest_summary_path()
                if summary_json and not os.path.exists(summary_json):
                    summary_json = None
                if summary_json:
                    meta['summary_path'] = summary_json
                    app.logger.info("[async-finalizer] Detected summary path: %s", summary_json)
                # Best-effort: capture post-run CORE session XML
                post_saved = None
                try:
                    out_dir = os.path.dirname(xml_path_local or '')
                    post_dir = os.path.join(out_dir, 'core-post') if out_dir else os.path.join(_outputs_dir(), 'core-post')
                    sid = _extract_session_id_from_text(txt)
                    post_saved = _grpc_save_current_session_xml(meta.get('core_host') or CORE_HOST, int(meta.get('core_port') or CORE_PORT), post_dir, session_id=sid)
                except Exception:
                    post_saved = None
                if post_saved:
                    meta['post_xml_path'] = post_saved
                    app.logger.debug("[async-finalizer] Post-run session XML saved to %s", post_saved)
                # Build single-scenario XML, then a Full Scenario bundle including scripts
                single_xml = None
                try:
                    single_xml = _write_single_scenario_xml(xml_path_local, active_scenario_name, out_dir=os.path.dirname(xml_path_local or ''))
                except Exception:
                    single_xml = None
                bundle_xml = single_xml or xml_path_local
                full_bundle = _build_full_scenario_archive(
                    os.path.dirname(bundle_xml or ''),
                    bundle_xml,
                    (report_md if (report_md and os.path.exists(report_md)) else None),
                    meta.get('pre_xml_path'),
                    post_saved,
                    summary_path=summary_json,
                    run_id=run_id_local,
                )
                if full_bundle:
                    meta['full_scenario_path'] = full_bundle
                session_xml_path = post_saved if (post_saved and os.path.exists(post_saved)) else None
                _append_run_history({
                    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                    'mode': 'async',
                    'xml_path': xml_path_local,
                    'post_xml_path': session_xml_path,
                    'session_xml_path': session_xml_path,
                    'scenario_xml_path': xml_path_local,
                    'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                    'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
                    'pre_xml_path': meta.get('pre_xml_path'),
                    'full_scenario_path': full_bundle,
                    'single_scenario_xml_path': single_xml,
                    'returncode': rc,
                    'run_id': run_id_local,
                    'scenario_names': meta.get('scenario_names') or [],
                    'preview_plan_path': meta.get('preview_plan_path'),
                })
                meta['history_added'] = True
            except Exception as e_final:
                try:
                    app.logger.exception("[async-finalizer] failed finalizing run %s: %s", run_id_local, e_final)
                except Exception:
                    pass
        except Exception:
            # swallow all exceptions to avoid crashing the web server
            try:
                app.logger.exception("[async-finalizer] unexpected error for run %s", run_id_local)
            except Exception:
                pass

    try:
        t = threading.Thread(target=_wait_and_finalize_async, args=(run_id,), daemon=True)
        t.start()
        app.logger.debug("[async] Finalizer thread started for run_id=%s", run_id)
    except Exception:
        pass
    return jsonify({"run_id": run_id})


@app.route('/run_status/<run_id>', methods=['GET'])
def run_status(run_id: str):
    meta = RUNS.get(run_id)
    if not meta:
        return jsonify({"error": "not found"}), 404
    proc = meta.get('proc')
    if proc and meta.get('returncode') is None:
        rc = proc.poll()
        if rc is not None:
            meta['done'] = True
            meta['returncode'] = rc
            # Append history once (success or failure)
            if not meta.get('history_added'):
                try:
                    active_scenario_name = None
                    try:
                        sns = meta.get('scenario_names') or []
                        if isinstance(sns, list) and sns:
                            active_scenario_name = sns[0]
                    except Exception:
                        active_scenario_name = None
                    xml_path_local = meta.get('xml_path')
                    # Parse report path from log contents; fallback to latest under reports/
                    report_md = None
                    txt = ''
                    try:
                        lp = meta.get('log_path')
                        if lp and os.path.exists(lp):
                            with open(lp, 'r', encoding='utf-8', errors='ignore') as f:
                                txt = f.read()
                            report_md = _extract_report_path_from_text(txt)
                    except Exception:
                        report_md = None
                    if not report_md:
                        report_md = _find_latest_report_path()
                    if report_md:
                        app.logger.info("[async] Detected report path: %s", report_md)
                    summary_json = _extract_summary_path_from_text(txt)
                    if not summary_json:
                        summary_json = _derive_summary_from_report(report_md)
                    if not summary_json and not report_md:
                        summary_json = _find_latest_summary_path()
                    if summary_json and not os.path.exists(summary_json):
                        summary_json = None
                    if summary_json:
                        meta['summary_path'] = summary_json
                        app.logger.info("[async] Detected summary path: %s", summary_json)
                    # Best-effort: capture post-run CORE session XML
                    post_saved = None
                    try:
                        out_dir = os.path.dirname(xml_path_local or '')
                        post_dir = os.path.join(out_dir, 'core-post') if out_dir else os.path.join(_outputs_dir(), 'core-post')
                        # Parse session id from logs if available for precise save
                        sid = _extract_session_id_from_text(txt)
                        post_saved = _grpc_save_current_session_xml(meta.get('core_host') or CORE_HOST, int(meta.get('core_port') or CORE_PORT), post_dir, session_id=sid)
                    except Exception:
                        post_saved = None
                    if post_saved:
                        meta['post_xml_path'] = post_saved
                        app.logger.debug("[async] Post-run session XML saved to %s", post_saved)
                    # Build single-scenario XML, then a Full Scenario bundle including scripts
                    single_xml = None
                    try:
                        single_xml = _write_single_scenario_xml(xml_path_local, active_scenario_name, out_dir=os.path.dirname(xml_path_local or ''))
                    except Exception:
                        single_xml = None
                    bundle_xml = single_xml or xml_path_local
                    full_bundle = _build_full_scenario_archive(
                        os.path.dirname(bundle_xml or ''),
                        bundle_xml,
                        (report_md if (report_md and os.path.exists(report_md)) else None),
                        meta.get('pre_xml_path'),
                        post_saved,
                        summary_path=summary_json,
                        run_id=run_id,
                    )
                    if full_bundle:
                        meta['full_scenario_path'] = full_bundle
                    session_xml_path = post_saved if (post_saved and os.path.exists(post_saved)) else None
                    _append_run_history({
                        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                        'mode': 'async',
                        'xml_path': xml_path_local,
                        'post_xml_path': session_xml_path,
                        'session_xml_path': session_xml_path,
                        'scenario_xml_path': xml_path_local,
                        'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                        'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
                        'pre_xml_path': meta.get('pre_xml_path'),
                        'full_scenario_path': full_bundle,
                        'single_scenario_xml_path': single_xml,
                        'returncode': rc,
                        'run_id': run_id,
                        'scenario_names': meta.get('scenario_names') or [],
                        'preview_plan_path': meta.get('preview_plan_path'),
                    })
                except Exception as e_hist:
                    try:
                        app.logger.exception("[async] failed appending run history: %s", e_hist)
                    except Exception:
                        pass
                finally:
                    meta['history_added'] = True
    # Determine report path
    xml_path = meta.get('xml_path', '')
    out_dir = os.path.dirname(xml_path)
    # Determine report path (attempt to parse log each time so UI can link it without refresh)
    report_md = None
    txt = ''
    try:
        lp = meta.get('log_path')
        if lp and os.path.exists(lp):
            with open(lp, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            report_md = _extract_report_path_from_text(txt)
    except Exception:
        report_md = None
    summary_json = _extract_summary_path_from_text(txt)
    if not summary_json:
        summary_json = _derive_summary_from_report(report_md)
    if not summary_json:
        summary_json = meta.get('summary_path')
    if not summary_json and not report_md:
        summary_json = _find_latest_summary_path()
    if summary_json and not os.path.exists(summary_json):
        summary_json = None
    if summary_json:
        meta['summary_path'] = summary_json
    return jsonify({
        'done': bool(meta.get('done')),
        'returncode': meta.get('returncode'),
        'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
        'summary_path': summary_json if (summary_json and os.path.exists(summary_json)) else None,
        'xml_path': (meta.get('post_xml_path') if meta.get('post_xml_path') and os.path.exists(meta.get('post_xml_path')) else None),
        'log_path': meta.get('log_path'),
        'scenario_xml_path': xml_path,
        'pre_xml_path': meta.get('pre_xml_path'),
        'full_scenario_path': (lambda p: p if (p and os.path.exists(p)) else None)(meta.get('full_scenario_path')),
    })


@app.route('/upload_base', methods=['POST'])
def upload_base():
    f = request.files.get('base_xml')
    if not f or f.filename == '':
        flash('No base scenario file selected.')
        return redirect(url_for('index'))
    filename = secure_filename(f.filename)
    base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'base')
    os.makedirs(base_dir, exist_ok=True)
    unique = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    saved_path = os.path.join(base_dir, f"{unique}-{filename}")
    f.save(saved_path)
    ok, errs = _validate_core_xml(saved_path)
    payload = _default_scenarios_payload()
    payload['base_upload'] = {
        'path': saved_path,
        'valid': bool(ok),
        'display_name': filename,
        'exists': True,
    }
    if not ok:
        flash('Base scenario XML is INVALID. See details link for errors.')
    else:
        flash('Base scenario uploaded and validated.')
        try:
            # set the base scenario file path on the first scenario for convenience
            payload['scenarios'][0]['base']['filepath'] = saved_path
            payload['scenarios'][0]['base']['display_name'] = filename
        except Exception:
            pass
    _attach_base_upload(payload)
    if payload.get('base_upload'):
        _save_base_upload_state(payload['base_upload'])
    payload = _prepare_payload_for_index(payload)
    return render_template('index.html', payload=payload, logs=(errs if not ok else ''), xml_preview='')

@app.route('/remove_base', methods=['POST'])
def remove_base():
    """Clear the base scenario file reference from the first scenario."""
    try:
        payload = _default_scenarios_payload()
        # If scenarios_json posted, honor that to keep user edits
        data_str = request.form.get('scenarios_json')
        if data_str:
            try:
                data = json.loads(data_str)
                if isinstance(data, dict) and 'scenarios' in data:
                    payload['scenarios'] = data['scenarios']
            except Exception:
                pass
        # Clear the base filepath of first scenario
        try:
            if payload['scenarios'] and isinstance(payload['scenarios'][0], dict):
                payload['scenarios'][0].setdefault('base', {}).update({'filepath': '', 'display_name': ''})
        except Exception:
            pass
        flash('Base scenario removed.')
        _clear_base_upload_state()
        payload.pop('base_upload', None)
        # Do not attach base upload (cleared)
        payload = _prepare_payload_for_index(payload)
        return render_template('index.html', payload=payload, logs='', xml_preview='')
    except Exception as e:
        flash(f'Failed to remove base: {e}')
        return redirect(url_for('index'))


@app.route('/base_details')
def base_details():
    xml_path = request.args.get('path')
    if not xml_path or not os.path.exists(xml_path):
        return "File not found", 404
    ok, errs = _validate_core_xml(xml_path)
    summary = _analyze_core_xml(xml_path) if ok else {'error': errs}
    return render_template('base_details.html', xml_path=xml_path, valid=ok, errors=errs, summary=summary)


# ---------------- CORE Management (sessions and XMLs) ----------------

def _core_sessions_store_path() -> str:
    return os.path.join(_outputs_dir(), 'core_sessions.json')


def _load_core_sessions_store() -> dict:
    p = _core_sessions_store_path()
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def _save_core_sessions_store(d: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_core_sessions_store_path()), exist_ok=True)
        tmp = _core_sessions_store_path() + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _core_sessions_store_path())
    except Exception:
        pass


def _update_xml_session_mapping(xml_path: str, session_id: int | None) -> None:
    try:
        store = _load_core_sessions_store()
        key = os.path.abspath(xml_path)
        if session_id is None:
            if key in store:
                store.pop(key, None)
        else:
            store[key] = int(session_id)
        _save_core_sessions_store(store)
    except Exception:
        pass


def _list_active_core_sessions(host: str, port: int) -> list[dict]:
    """Return list of active CORE sessions via gRPC. Best-effort if gRPC missing."""
    items: list[dict] = []
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        return items
    address = f"{host}:{port}"
    try:
        client = CoreGrpcClient(address=address)
        try:
            from core_topo_gen.utils.grpc_logging import wrap_core_client  # type: ignore
            client = wrap_core_client(client, app.logger)
        except Exception:
            pass
        client.connect()
        try:
            sessions = client.get_sessions()
            for s in sessions:
                try:
                    sid = getattr(s, 'id', None)
                    state = getattr(getattr(s, 'state', None), 'name', None) or getattr(s, 'state', None)
                    file_path = getattr(s, 'file', None)
                    sess_dir = getattr(s, 'dir', None)
                    # Fallback: attempt lookup from stored mapping if file_path not provided by gRPC
                    if (not file_path) and sid is not None:
                        try:
                            store_map = _load_core_sessions_store()
                            # reverse lookup: session id -> first path
                            for pth, stored_sid in store_map.items():
                                try:
                                    if int(stored_sid) == int(sid):
                                        file_path = pth
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            pass
                    # Second fallback: scan session directory for xml
                    if (not file_path) and sess_dir and os.path.isdir(sess_dir):
                        try:
                            for fn in os.listdir(sess_dir):
                                if fn.lower().endswith('.xml'):
                                    file_path = os.path.join(sess_dir, fn)
                                    break
                        except Exception:
                            pass
                    # Prefer provided nodes count; if missing or zero, attempt to derive via gRPC
                    nodes_count = getattr(s, 'nodes', None)
                    if nodes_count is None or (isinstance(nodes_count, int) and nodes_count == 0):
                        try:
                            # Try get_nodes(session_id) -> list
                            if sid is not None and hasattr(client, 'get_nodes'):
                                try:
                                    nlist = client.get_nodes(int(sid))  # type: ignore[attr-defined]
                                    if nlist is not None:
                                        # Some clients return dicts or objects; len() is sufficient
                                        nodes_count = len(nlist)
                                except Exception:
                                    pass
                            # Fallback to fetching session detail if available
                            if (nodes_count is None or nodes_count == 0) and sid is not None and hasattr(client, 'get_session'):
                                try:
                                    sdet = client.get_session(int(sid))  # type: ignore[attr-defined]
                                    maybe_nodes = getattr(sdet, 'nodes', None)
                                    if isinstance(maybe_nodes, int):
                                        nodes_count = maybe_nodes
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    items.append({
                        'id': sid,
                        'state': state,
                        'nodes': nodes_count if nodes_count is not None else None,
                        'file': file_path,
                        'dir': sess_dir,
                    })
                except Exception:
                    continue
        finally:
            try: client.close()
            except Exception: pass
    except Exception:
        pass
    return items


def _scan_core_xmls(max_count: int = 200) -> list[dict]:
    """Scan for runnable CORE XMLs and exclude scenario editor saves.

    Include only:
      - uploads/core/*.xml (user-uploaded CORE XMLs)
      - outputs/core-sessions/**/*.xml (saved via gRPC from running sessions)

    Exclude:
      - outputs/scenarios-*/** (scenario editor saves)

    Returns list of dicts: { path, name, size, mtime, valid } sorted by mtime desc.
    """
    uploads_core = os.path.join(_uploads_dir(), 'core')
    outputs_sessions = os.path.join(_outputs_dir(), 'core-sessions')
    allowed_roots = [uploads_core, outputs_sessions]
    paths: list[str] = []
    for root in allowed_roots:
        try:
            if not root or not os.path.exists(root):
                continue
            for dp, _dn, files in os.walk(root):
                for fn in files:
                    if fn.lower().endswith('.xml'):
                        paths.append(os.path.join(dp, fn))
        except Exception:
            continue
    # Dedup and sort by mtime desc
    seen = set()
    recs: list[tuple[float, dict]] = []
    for p in paths:
        ap = os.path.abspath(p)
        if ap in seen:
            continue
        seen.add(ap)
        try:
            st = os.stat(ap)
            mt = st.st_mtime
            size = st.st_size
        except Exception:
            mt = 0.0
            size = -1
        valid = False
        ok, _errs = _validate_core_xml(ap)
        valid = bool(ok)
        recs.append((mt, {'path': ap, 'name': os.path.basename(ap), 'size': size, 'mtime': mt, 'valid': valid}))
    recs.sort(key=lambda x: x[0], reverse=True)
    return [r for _mt, r in recs[:max_count]]


@app.route('/core')
def core_page():
    # Determine CORE host/port from defaults
    host = CORE_HOST
    port = CORE_PORT
    # Active sessions via gRPC
    sessions = _list_active_core_sessions(host, port)
    # Known XMLs
    xmls = _scan_core_xmls()
    # Map running by file path, with fallback to local store
    mapping = _load_core_sessions_store()
    file_to_sid: dict[str, int] = {}
    # From gRPC session summaries (file path may be absolute)
    for s in sessions:
        f = s.get('file')
        sid = s.get('id')
        if f and sid is not None:
            file_to_sid[os.path.abspath(f)] = int(sid)
    # Merge with prior mappings
    for k, v in mapping.items():
        file_to_sid.setdefault(os.path.abspath(k), int(v))
    # Annotate xmls
    for x in xmls:
        sid = file_to_sid.get(x['path'])
        x['session_id'] = sid
        x['running'] = sid is not None
    return render_template('core.html', sessions=sessions, xmls=xmls, host=host, port=port)


@app.route('/core/data')
def core_data():
    host = CORE_HOST
    port = CORE_PORT
    sessions = _list_active_core_sessions(host, port)
    xmls = _scan_core_xmls()
    # annotate xmls with running/session_id best-effort mapping, as in core_page
    mapping = _load_core_sessions_store()
    file_to_sid: dict[str, int] = {}
    for s in sessions:
        f = s.get('file')
        sid = s.get('id')
        if f and sid is not None:
            file_to_sid[os.path.abspath(f)] = int(sid)
    for k, v in mapping.items():
        file_to_sid.setdefault(os.path.abspath(k), int(v))
    for x in xmls:
        sid = file_to_sid.get(x['path'])
        x['session_id'] = sid
        x['running'] = sid is not None
    return jsonify({ 'sessions': sessions, 'xmls': xmls })


@app.route('/core/upload', methods=['POST'])
def core_upload():
    f = request.files.get('xml_file')
    if not f or f.filename == '':
        flash('No file selected.')
        return redirect(url_for('core_page'))
    filename = secure_filename(f.filename)
    if not filename.lower().endswith('.xml'):
        flash('Only .xml allowed.')
        return redirect(url_for('core_page'))
    dest_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'core')
    os.makedirs(dest_dir, exist_ok=True)
    unique = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    path = os.path.join(dest_dir, f"{unique}-{filename}")
    f.save(path)
    ok, errs = _validate_core_xml(path)
    if not ok:
        try: os.remove(path)
        except Exception: pass
        flash(f'Invalid CORE XML: {errs}')
        return redirect(url_for('core_page'))
    flash('XML uploaded and validated.')
    return redirect(url_for('core_page'))


@app.route('/core/start', methods=['POST'])
def core_start():
    xml_path = request.form.get('path')
    if not xml_path:
        flash('Missing XML path')
        return redirect(url_for('core_page'))
    ap = os.path.abspath(xml_path)
    if not os.path.exists(ap):
        flash('File not found')
        return redirect(url_for('core_page'))
    ok, errs = _validate_core_xml(ap)
    if not ok:
        flash(f'Invalid CORE XML: {errs}')
        return redirect(url_for('core_page'))
    # Start via gRPC open_xml(start=True)
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        flash('CORE gRPC client not available in this environment.')
        return redirect(url_for('core_page'))
    address = f"{CORE_HOST}:{CORE_PORT}"
    try:
        client = CoreGrpcClient(address=address)
        try:
            from core_topo_gen.utils.grpc_logging import wrap_core_client  # type: ignore
            client = wrap_core_client(client, app.logger)
        except Exception:
            pass
        client.connect()
        try:
            # open_xml requires pathlib.Path
            sid = None
            try:
                from pathlib import Path as _P
                res, new_sid = client.open_xml(_P(ap), start=True)
                if not res:
                    flash('CORE did not accept the XML file.')
                    return redirect(url_for('core_page'))
                sid = int(new_sid) if new_sid is not None else None
            except Exception as e:
                flash(f'Failed to open XML: {e}')
                return redirect(url_for('core_page'))
            if sid is not None:
                _update_xml_session_mapping(ap, sid)
                flash(f'Started session {sid}.')
        finally:
            try: client.close()
            except Exception: pass
    except Exception as e:
        flash(f'gRPC error: {e}')
    return redirect(url_for('core_page'))


@app.route('/core/stop', methods=['POST'])
def core_stop():
    sid = request.form.get('session_id')
    if not sid:
        flash('Missing session id')
        return redirect(url_for('core_page'))
    try:
        sid_int = int(sid)
    except Exception:
        flash('Invalid session id')
        return redirect(url_for('core_page'))
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        flash('CORE gRPC client not available in this environment.')
        return redirect(url_for('core_page'))
    address = f"{CORE_HOST}:{CORE_PORT}"
    try:
        client = CoreGrpcClient(address=address)
        try:
            from core_topo_gen.utils.grpc_logging import wrap_core_client  # type: ignore
            client = wrap_core_client(client, app.logger)
        except Exception:
            pass
        client.connect()
        try:
            client.stop_session(sid_int)
            flash(f'Stopped session {sid_int}.')
        finally:
            try: client.close()
            except Exception: pass
    except Exception as e:
        flash(f'gRPC error: {e}')
    return redirect(url_for('core_page'))


@app.route('/core/start_session', methods=['POST'])
def core_start_session():
    sid = request.form.get('session_id')
    if not sid:
        flash('Missing session id')
        return redirect(url_for('core_page'))
    try:
        sid_int = int(sid)
    except Exception:
        flash('Invalid session id')
        return redirect(url_for('core_page'))
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        flash('CORE gRPC client not available in this environment.')
        return redirect(url_for('core_page'))
    address = f"{CORE_HOST}:{CORE_PORT}"
    try:
        client = CoreGrpcClient(address=address)
        client.connect()
        try:
            client.start_session(sid_int)
            flash(f'Started session {sid_int}.')
        finally:
            try: client.close()
            except Exception: pass
    except Exception as e:
        flash(f'gRPC error: {e}')
    return redirect(url_for('core_page'))


@app.route('/core/delete', methods=['POST'])
def core_delete():
    # Delete session (if provided) and/or delete XML file under uploads/ or outputs/
    sid = request.form.get('session_id')
    xml_path = request.form.get('path')
    if sid:
        try:
            sid_int = int(sid)
            from core.api.grpc.client import CoreGrpcClient  # type: ignore
            client = CoreGrpcClient(address=f"{CORE_HOST}:{CORE_PORT}")
            try:
                from core_topo_gen.utils.grpc_logging import wrap_core_client  # type: ignore
                client = wrap_core_client(client, app.logger)
            except Exception:
                pass
            client.connect()
            try:
                client.delete_session(sid_int)
                flash(f'Deleted session {sid_int}.')
            finally:
                try: client.close()
                except Exception: pass
        except Exception as e:
            flash(f'Failed to delete session: {e}')
    if xml_path:
        ap = os.path.abspath(xml_path)
        # Safety: only delete inside uploads/ or outputs/
        try:
            allowed = [os.path.abspath(_uploads_dir()), os.path.abspath(_outputs_dir())]
            if any(ap.startswith(a + os.sep) or ap == a for a in allowed):
                try:
                    os.remove(ap)
                    flash('Deleted XML file.')
                except FileNotFoundError:
                    pass
                except Exception as e:
                    flash(f'Failed deleting XML: {e}')
                # clear mapping
                _update_xml_session_mapping(ap, None)
            else:
                flash('Refusing to delete file outside outputs/ or uploads/.')
        except Exception:
            pass
    return redirect(url_for('core_page'))


@app.route('/core/details')
def core_details():
    xml_path = request.args.get('path')
    sid = request.args.get('session_id')
    xml_summary = None
    xml_valid = False
    errors = ''
    classification = None  # 'scenario' | 'session' | 'unknown'
    container_flag = False
    # If no XML path given but we have a session id, attempt to export the session XML so we can show details
    if (not xml_path or not os.path.exists(xml_path)) and sid:
        try:
            out_dir = os.path.join(_outputs_dir(), 'core-sessions')
            os.makedirs(out_dir, exist_ok=True)
            saved = _grpc_save_current_session_xml(CORE_HOST, CORE_PORT, out_dir, session_id=str(sid))
            if saved and os.path.exists(saved):
                xml_path = saved
        except Exception:
            pass
    if xml_path and os.path.exists(xml_path):
        try:
            # Lightweight classification: scenario XML should have <Scenarios>, session XML will have <session> and possibly <container>
            import xml.etree.ElementTree as _ET
            with open(xml_path, 'rb') as f:
                data_head = f.read(4096)
            try:
                root = _ET.fromstring(data_head + b"</dummy>")
            except Exception:
                try:
                    tree = _ET.parse(xml_path)
                    root = tree.getroot()
                except Exception:
                    root = None
            if root is not None:
                tag_lower = root.tag.lower()
                if 'scenarios' in tag_lower:
                    classification = 'scenario'
                elif 'session' in tag_lower:
                    classification = 'session'
                else:
                    classification = 'unknown'
                if root.find('.//container') is not None:
                    container_flag = True
                    if classification != 'scenario':
                        classification = 'session'
            ok, errs = _validate_core_xml(xml_path)
            if ok:
                xml_valid = True
            else:
                if classification == 'session':
                    xml_valid = True
                    # Suppress schema errors for session exports; treat as advisory only.
                else:
                    xml_valid = False
                    if errs and not errors:
                        errors = errs
            # Always attempt analysis so graph can render even for invalid/session XML; mark summary with invalid flag
            try:
                xml_summary = _analyze_core_xml(xml_path)
                if xml_summary is None:
                    xml_summary = {}
                if classification == 'session':
                    xml_summary['__session_export'] = True
                if not xml_valid:
                    xml_summary['__invalid'] = True
            except Exception:
                # On total failure keep prior xml_summary (None)
                xml_summary = xml_summary or None
        except Exception as _e:
            errors = errors or f'XML inspection failed: {_e}'
    session_info = None
    if sid:
        try:
            sid_int = int(sid)
            # lookup session info via gRPC
            sessions = _list_active_core_sessions(CORE_HOST, CORE_PORT)
            for s in sessions:
                if int(s.get('id')) == sid_int:
                    session_info = s
                    break
        except Exception:
            session_info = None
    try:
        if xml_summary is not None:
            app.logger.debug(
                "[core_details] xml_path=%s classification=%s valid=%s nodes=%s switch_nodes=%s links_detail=%s",
                xml_path, classification, xml_valid,
                len(xml_summary.get('nodes') or []),
                len(xml_summary.get('switch_nodes') or []),
                len(xml_summary.get('links_detail') or [])
            )
        else:
            app.logger.debug(
                "[core_details] xml_path=%s classification=%s valid=%s (no summary)",
                xml_path, classification, xml_valid
            )
    except Exception:
        pass
    # Render without legacy approved-plan context
    return render_template(
        'core_details.html',
        xml_path=xml_path,
        valid=xml_valid,
        errors=errors,
        summary=xml_summary,
        session=session_info,
        classification=classification,
        container_flag=container_flag,
    )


@app.route('/admin/cleanup_pycore', methods=['POST'])
def admin_cleanup_pycore():
    """Remove stale /tmp/pycore.* directories not associated with active sessions.

    Returns JSON summary: {removed: [...], kept: [...]}"""
    try:
        active_ids = set()
        try:
            sessions = _list_active_core_sessions(CORE_HOST, CORE_PORT)
            for s in sessions:
                try:
                    active_ids.add(int(s.get('id')))
                except Exception:
                    continue
        except Exception:
            pass
        removed = []
        kept = []
        for p in Path('/tmp').glob('pycore.*'):
            try:
                sid = int(p.name.split('.')[-1])
            except Exception:
                kept.append(str(p))
                continue
            if sid in active_ids:
                kept.append(str(p))
                continue
            # Only remove if directory exists and not recently modified (older than 30s) to avoid race with creation
            try:
                age = time.time() - p.stat().st_mtime
            except Exception:
                age = 999
            if age < 30:
                kept.append(str(p))
                continue
            try:
                shutil.rmtree(p)
                removed.append(str(p))
            except Exception:
                kept.append(str(p))
        return jsonify({'ok': True, 'removed': removed, 'kept': kept, 'active_session_ids': sorted(active_ids)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/core/save_xml', methods=['POST'])
def core_save_xml():
    sid = request.form.get('session_id')
    try:
        sid_int = int(sid) if sid is not None else None
    except Exception:
        sid_int = None
    out_dir = os.path.join(_outputs_dir(), 'core-sessions')
    os.makedirs(out_dir, exist_ok=True)
    try:
        saved = _grpc_save_current_session_xml(CORE_HOST, CORE_PORT, out_dir, session_id=str(sid_int) if sid_int is not None else None)
        if not saved or not os.path.exists(saved):
            return Response('Failed to save session XML', status=500)
        # Stream back as a download so frontend can save via blob
        return send_file(saved, as_attachment=True, download_name=os.path.basename(saved), mimetype='application/xml')
    except Exception as e:
        return Response(f'Error saving session XML: {e}', status=500)


@app.route('/core/session/<int:sid>')
def core_session(sid: int):
    """Convenience route to view a specific session's details.
    Attempts to look up the session and its file path, then reuses the core_details template.
    """
    session_info = None
    xml_path = None
    try:
        sessions = _list_active_core_sessions(CORE_HOST, CORE_PORT)
        for s in sessions:
            if int(s.get('id')) == int(sid):
                session_info = s
                xml_path = s.get('file')
                break
    except Exception:
        session_info = None
    xml_valid = False
    errors = ''
    xml_summary = None
    if xml_path and os.path.exists(xml_path):
        ok, errs = _validate_core_xml(xml_path)
        xml_valid = bool(ok)
        errors = errs if not ok else ''
        xml_summary = _analyze_core_xml(xml_path) if ok else None
    return render_template('core_details.html', xml_path=xml_path, valid=xml_valid, errors=errors, summary=xml_summary, session=session_info)


@app.route('/test_core', methods=['POST'])
def test_core():
    try:
        data: Dict[str, Any] = {}
        if request.is_json:
            data = request.get_json(silent=True) or {}
        else:
            data = {"host": request.form.get('host'), "port": request.form.get('port')}
        host = (data.get('host') or CORE_HOST).strip()
        try:
            port = int(data.get('port') or os.environ.get('CORE_PORT', CORE_PORT))
        except Exception:
            return jsonify({"ok": False, "error": "Invalid port"}), 200
        # If inside container and user kept localhost, try environment override or host.docker.internal
        if host in ('localhost', '127.0.0.1'):
            env_host = os.environ.get('CORE_HOST')
            if env_host and env_host not in ('localhost', '127.0.0.1'):
                host = env_host
            else:
                try:
                    import socket as _s
                    _s.gethostbyname('host.docker.internal')
                    host = 'host.docker.internal'
                except Exception:
                    pass
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((host, port))
            sock.close()
            return jsonify({"ok": True, "host": host, "port": port})
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            return jsonify({"ok": False, "error": str(e)}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route('/stream/<run_id>')
def stream_logs(run_id: str):
    meta = RUNS.get(run_id)
    if not meta:
        return Response('event: error\ndata: not found\n\n', mimetype='text/event-stream')
    log_path = meta.get('log_path')

    def generate():
        # 1) Send existing backlog first for immediate context
        last_pos = 0
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f_init:
                backlog = f_init.read()
                last_pos = f_init.tell()
            if backlog:
                for line in backlog.splitlines():
                    yield f"data: {line}\n\n"
        except FileNotFoundError:
            pass
        # 2) Tail incremental additions
        while True:
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_pos)
                    chunk = f.read()
                    if chunk:
                        last_pos = f.tell()
                        # Split into lines to keep events reasonable
                        for line in chunk.splitlines():
                            yield f"data: {line}\n\n"
            except FileNotFoundError:
                pass
            # Check process status
            proc = meta.get('proc')
            rc = None
            if proc:
                rc = proc.poll()
                if rc is not None and meta.get('returncode') is None:
                    meta['returncode'] = rc
                    meta['done'] = True
            if meta.get('done'):
                # Signal end regardless; client will stop listening
                yield "event: end\ndata: done\n\n"
                break
            time.sleep(0.5)

    headers = {
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',  # for some proxies
        'Content-Type': 'text/event-stream',
        'Connection': 'keep-alive',
    }
    return Response(generate(), headers=headers)


@app.route('/cancel_run/<run_id>', methods=['POST'])
def cancel_run(run_id: str):
    meta = RUNS.get(run_id)
    if not meta:
        return jsonify({"error": "not found"}), 404
    proc = meta.get('proc')
    try:
        if proc and proc.poll() is None:
            # Append a cancel marker to log, then terminate
            lp = meta.get('log_path')
            try:
                with open(lp, 'a', encoding='utf-8') as f:
                    f.write("\n== Run cancelled by user ==\n")
            except Exception:
                pass
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        meta['done'] = True
        if meta.get('returncode') is None:
            meta['returncode'] = -1
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- Data Sources -----------------
@app.route('/data_sources')
def data_sources_page():
    state = _load_data_sources_state()
    return render_template('data_sources.html', sources=state.get('sources', []))

@app.route('/data_sources/upload', methods=['POST'])
def data_sources_upload():
    f = request.files.get('csv_file')
    if not f or f.filename == '':
        flash('No file selected.')
        return redirect(url_for('data_sources_page'))
    filename = secure_filename(f.filename)
    if not filename.lower().endswith('.csv'):
        flash('Only .csv allowed.')
        return redirect(url_for('data_sources_page'))
    unique = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    dest_dir = os.path.join(DATA_SOURCES_DIR)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, f"{unique}-{filename}")
    f.save(path)
    ok, note, norm_rows, skipped = _validate_and_normalize_data_source_csv(path, skip_invalid=True)
    if not ok:
        try: os.remove(path)
        except Exception: pass
        flash(f'Invalid CSV: {note}')
        return redirect(url_for('data_sources_page'))
    # Write back normalized CSV to ensure required/optional columns are present
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            for r in norm_rows:
                w.writerow(r)
        os.replace(tmp, path)
    except Exception:
        pass
    state = _load_data_sources_state()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "name": filename,
        "path": path,
        "enabled": True,
        "rows": note,
        "uploaded": datetime.datetime.utcnow().isoformat() + 'Z'
    }
    state['sources'].append(entry)
    _save_data_sources_state(state)
    if ok and skipped:
        flash(f'CSV imported with {len(skipped)} invalid row(s) skipped.')
    else:
        flash('CSV imported.')
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/toggle/<sid>', methods=['POST'])
def data_sources_toggle(sid):
    state = _load_data_sources_state()
    for s in state.get('sources', []):
        if s.get('id') == sid:
            s['enabled'] = not s.get('enabled', False)
            break
    _save_data_sources_state(state)
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/delete/<sid>', methods=['POST'])
def data_sources_delete(sid):
    state = _load_data_sources_state()
    new_sources = []
    for s in state.get('sources', []):
        if s.get('id') == sid:
            try:
                if os.path.exists(s.get('path','')):
                    os.remove(s['path'])
            except Exception:
                pass
            continue
        new_sources.append(s)
    state['sources'] = new_sources
    _save_data_sources_state(state)
    flash('Deleted.')
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/refresh/<sid>', methods=['POST'])
def data_sources_refresh(sid):
    state = _load_data_sources_state()
    for s in state.get('sources', []):
        if s.get('id') == sid:
            ok, note, norm_rows, skipped = _validate_and_normalize_data_source_csv(s.get('path',''), skip_invalid=True)
            if ok and norm_rows:
                # Write back normalized CSV
                try:
                    p = s.get('path','')
                    tmp = p + '.tmp'
                    with open(tmp, 'w', encoding='utf-8', newline='') as f:
                        w = csv.writer(f)
                        for r in norm_rows:
                            w.writerow(r)
                    os.replace(tmp, p)
                except Exception:
                    pass
            if ok and skipped:
                note = note + f" (skipped {len(skipped)} invalid)"
            s['rows'] = note if ok else f"ERR: {note}"
            break
    _save_data_sources_state(state)
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/download/<sid>')
def data_sources_download(sid):
    state = _load_data_sources_state()
    for s in state.get('sources', []):
        if s.get('id') == sid and os.path.exists(s.get('path','')):
            return send_file(s['path'], as_attachment=True, download_name=os.path.basename(s['name']))
    flash('Not found')
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/export_all')
def data_sources_export_all():
    import io, zipfile
    state = _load_data_sources_state()
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        for s in state.get('sources', []):
            p = s.get('path')
            if p and os.path.exists(p):
                z.write(p, arcname=os.path.basename(p))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name='data_sources.zip')

@app.route('/vuln_catalog')
def vuln_catalog():
    """Return vulnerability catalog built from enabled data source CSVs.

    Response JSON:
      {
        "types": [str],
        "vectors": [str],
        "items": [ {"Name","Path","Type","Startup","Vector","CVE","Description","References"} ]
      }
    Only includes rows from enabled data sources that validate.
    """
    try:
        state = _load_data_sources_state()
        types = set()
        vectors = set()
        items = []
        for s in state.get('sources', []):
            if not s.get('enabled'): continue
            p = s.get('path')
            if not p or not os.path.exists(p): continue
            ok, note, norm_rows, _skipped = _validate_and_normalize_data_source_csv(p, skip_invalid=True)
            if not ok or not norm_rows or len(norm_rows) < 2: continue
            header = norm_rows[0]
            idx = {name: header.index(name) for name in header if name in header}
            for r in norm_rows[1:]:
                try:
                    rec = {
                        'Name': r[idx.get('Name')],
                        'Path': r[idx.get('Path')],
                        'Type': r[idx.get('Type')],
                        'Startup': r[idx.get('Startup')],
                        'Vector': r[idx.get('Vector')],
                        'CVE': r[idx.get('CVE')] if 'CVE' in idx else 'n/a',
                        'Description': r[idx.get('Description')] if 'Description' in idx else 'n/a',
                        'References': r[idx.get('References')] if 'References' in idx else 'n/a',
                    }
                    # keep only non-empty mandatory values
                    if not rec['Name'] or not rec['Path']:
                        continue
                    items.append(rec)
                    if rec['Type']: types.add(rec['Type'])
                    if rec['Vector']: vectors.add(rec['Vector'])
                except Exception:
                    continue
        return jsonify({
            'types': sorted(types),
            'vectors': sorted(vectors),
            'items': items,
        })
    except Exception as e:
        return jsonify({'error': str(e), 'types': [], 'vectors': [], 'items': []}), 500


# ------------ Vulnerability compose helpers (GitHub-aware) ---------------
def _safe_name(s: str) -> str:
    try:
        return re.sub(r"[^a-z0-9_.-]+", "-", (s or '').strip().lower())[:80] or 'vuln'
    except Exception:
        return 'vuln'


def _parse_github_url(url: str):
    """Parse a GitHub URL. Supports formats:
    - https://github.com/owner/repo/tree/<branch>/<subpath>
    - https://github.com/owner/repo/blob/<branch>/<file_or_subpath>
    - https://github.com/owner/repo (no branch; default branch)

    Returns dict with keys:
      { 'is_github': bool, 'git_url': str|None, 'branch': str|None, 'subpath': str|None, 'mode': 'tree'|'blob'|'root' }
    """
    try:
        from urllib.parse import urlparse
        u = urlparse(url)
        if u.netloc.lower() != 'github.com':
            return {'is_github': False}
        parts = [p for p in u.path.strip('/').split('/') if p]
        if len(parts) < 2:
            return {'is_github': False}
        owner, repo = parts[0], parts[1]
        git_url = f"https://github.com/{owner}/{repo}.git"
        if len(parts) == 2:
            return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
        mode = parts[2]
        if mode not in ('tree', 'blob') or len(parts) < 4:
            # Unknown path mode; treat as root
            return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
        branch = parts[3]
        rest = '/'.join(parts[4:])
        return {'is_github': True, 'git_url': git_url, 'branch': branch, 'subpath': rest, 'mode': mode}
    except Exception:
        return {'is_github': False}


def _compose_candidates(base_dir: str):
    """Return possible compose file paths under base_dir in priority order."""
    cands = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
    out = []
    try:
        for name in cands:
            p = os.path.join(base_dir, name)
            if os.path.exists(p):
                out.append(p)
    except Exception:
        pass
    return out

@app.route('/vuln_compose/status', methods=['POST'])
def vuln_compose_status():
    """Return status for a list of catalog items: whether compose file is downloaded and images pulled.

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, exists: bool, pulled: bool, dir: str}] }
    """
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        logs: list[str] = []
        base_out = os.path.abspath(_vuln_base_dir())
        os.makedirs(base_out, exist_ok=True)
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            gh = _parse_github_url(path)
            base_dir = vdir
            compose_file = None
            if gh.get('is_github'):
                try:
                    logs.append(f"[status] {name}: Path={path}")
                    logs.append(f"[status] {name}: git_url={gh.get('git_url')} branch={gh.get('branch')} subpath={gh.get('subpath')} mode={gh.get('mode')}")
                except Exception:
                    pass
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                sub = gh.get('subpath') or ''
                # If subpath looks like a compose file, resolve directly
                is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                if is_file_sub:
                    compose_file = os.path.join(repo_dir, sub)
                    base_dir = os.path.dirname(compose_file)
                    exists = os.path.exists(compose_file)
                else:
                    base_dir = os.path.join(repo_dir, sub) if sub else repo_dir
                    exists = os.path.isdir(base_dir)
                try:
                    logs.append(f"[status] {name}: base={base_dir} exists={exists} compose={compose_name}")
                except Exception:
                    pass
                # prefer provided compose name
                if exists and compose_name and not compose_file:
                    p = os.path.join(base_dir, compose_name)
                    if os.path.exists(p):
                        compose_file = p
                # log compose candidates
                try:
                    cands = _compose_candidates(base_dir) if exists else []
                    logs.append(f"[status] {name}: compose candidates={cands[:4]}")
                except Exception:
                    pass
                if not compose_file:
                    # find compose candidates within base_dir
                    cand = _compose_candidates(base_dir)
                    compose_file = cand[0] if cand else None
            else:
                # legacy direct download to vdir/docker-compose.yml
                compose_file = os.path.join(vdir, compose_name or 'docker-compose.yml')
                exists = os.path.exists(compose_file)
                try:
                    logs.append(f"[status] {name}: non-github Path={path} compose_path={compose_file} exists={exists}")
                except Exception:
                    pass
            pulled = False
            if exists and compose_file and shutil.which('docker'):
                try:
                    proc = subprocess.run(['docker', 'compose', '-f', compose_file, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                    try:
                        logs.append(f"[status] docker compose config --images rc={proc.returncode}")
                    except Exception:
                        pass
                    if proc.returncode == 0:
                        images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
                        try:
                            logs.append(f"[status] images discovered: {len(images)}")
                            logs.append(f"[status] images sample: {images[:4]}")
                        except Exception:
                            pass
                        if images:
                            present = []
                            for img in images:
                                p2 = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                try:
                                    logs.append(f"[status] image inspect {img} rc={p2.returncode}")
                                except Exception:
                                    pass
                                present.append(p2.returncode == 0)
                            pulled = all(present)
                except Exception:
                    pulled = False
            out.append({'Name': name, 'Path': path, 'compose': compose_name, 'compose_path': compose_file, 'exists': bool(exists), 'pulled': bool(pulled), 'dir': base_dir})
        return jsonify({'items': out, 'log': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vuln_compose/download', methods=['POST'])
def vuln_compose_download():
    """Download docker-compose.yml for the given catalog items.

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, ok: bool, dir: str, message: str}] }
    """
    try:
        try:
            from core_topo_gen.utils.vuln_process import _github_tree_to_raw as _to_raw
        except Exception as _imp_err:
            # Fallback: minimal tree->raw converter for GitHub tree URLs
            def _to_raw(base_url: str, filename: str) -> str | None:
                try:
                    from urllib.parse import urlparse
                    u = urlparse(base_url)
                    if u.netloc.lower() != 'github.com':
                        return None
                    parts = [p for p in u.path.strip('/').split('/') if p]
                    if len(parts) < 4 or parts[2] != 'tree':
                        return None
                    owner, repo, _tree, branch = parts[:4]
                    rest = '/'.join(parts[4:])
                    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}/{filename}"
                except Exception:
                    return None
            try:
                app.logger.warning("[download] fallback _to_raw used due to import error: %s", _imp_err)
            except Exception:
                pass
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        logs: list[str] = []
        base_out = os.path.abspath(_vuln_base_dir())
        os.makedirs(base_out, exist_ok=True)
        import urllib.request
        import shlex
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            os.makedirs(vdir, exist_ok=True)
            gh = _parse_github_url(path)
            if gh.get('is_github'):
                # Clone the repo; use branch if provided
                if not shutil.which('git'):
                    try:
                        logs.append(f"[download] {name}: git not available in PATH")
                    except Exception:
                        pass
                    out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': 'git not available'})
                    continue
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                try:
                    logs.append(f"[download] {name}: Path={path}")
                    logs.append(f"[download] {name}: git_url={gh.get('git_url')} branch={gh.get('branch')} subpath={gh.get('subpath')} -> repo_dir={repo_dir}")
                except Exception:
                    pass
                # If already cloned and looks valid, skip re-clone
                if os.path.isdir(os.path.join(repo_dir, '.git')):
                    try:
                        logs.append(f"[download] {name}: repo exists {repo_dir}")
                    except Exception:
                        pass
                    base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                    try:
                        logs.append(f"[download] {name}: base_dir={base_dir}")
                        # limited directory listing
                        if os.path.isdir(base_dir):
                            entries = []
                            for nm in os.listdir(base_dir)[:10]:
                                p = os.path.join(base_dir, nm)
                                kind = 'dir' if os.path.isdir(p) else 'file'
                                entries.append(f"{nm}({kind})")
                            logs.append(f"[download] {name}: base_dir entries: {entries}")
                    except Exception:
                        pass
                    out.append({'Name': name, 'Path': path, 'ok': True, 'dir': base_dir, 'message': 'already downloaded'})
                    continue
                # Ensure empty directory
                try:
                    if os.path.exists(repo_dir):
                        shutil.rmtree(repo_dir)
                except Exception:
                    pass
                cmd = ['git', 'clone', '--depth', '1']
                if gh.get('branch'):
                    cmd += ['--branch', gh.get('branch')]
                cmd += [gh.get('git_url'), repo_dir]
                try:
                    try:
                        logs.append(f"[download] {name}: running: {' '.join(shlex.quote(c) for c in cmd)}")
                    except Exception:
                        pass
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                    try:
                        logs.append(f"[download] git clone rc={proc.returncode} dir={repo_dir}")
                        if proc.stdout:
                            for ln in proc.stdout.splitlines()[:100]:
                                logs.append(f"[git] {ln}")
                    except Exception:
                        pass
                    if proc.returncode == 0 and os.path.isdir(repo_dir):
                        base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                        try:
                            logs.append(f"[download] {name}: base_dir={base_dir}")
                            # limited directory listing
                            if os.path.isdir(base_dir):
                                entries = []
                                for nm in os.listdir(base_dir)[:10]:
                                    p = os.path.join(base_dir, nm)
                                    kind = 'dir' if os.path.isdir(p) else 'file'
                                    entries.append(f"{nm}({kind})")
                                logs.append(f"[download] {name}: base_dir entries: {entries}")
                        except Exception:
                            pass
                        out.append({'Name': name, 'Path': path, 'ok': True, 'dir': base_dir, 'message': 'downloaded'})
                    else:
                        msg = (proc.stdout or '').strip()
                        out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': msg[-1000:] if msg else 'git clone failed'})
                except Exception as e:
                    out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': str(e)})
            else:
                # Legacy: direct download of compose file (use provided compose name)
                raw = _to_raw(path, compose_name) or (path.rstrip('/') + '/' + compose_name)
                yml_path = os.path.join(vdir, compose_name)
                try:
                    try:
                        logs.append(f"[download] {name}: Path={path}")
                        logs.append(f"[download] {name}: GET {raw}")
                    except Exception:
                        pass
                    with urllib.request.urlopen(raw, timeout=30) as resp:
                        status = getattr(resp, 'status', None) or getattr(resp, 'code', None)
                        data_bin = resp.read(1_000_000)
                        try:
                            logs.append(f"[download] {name}: HTTP {status} bytes={len(data_bin) if data_bin else 0}")
                        except Exception:
                            pass
                    with open(yml_path, 'wb') as f:
                        f.write(data_bin)
                    out.append({'Name': name, 'Path': path, 'ok': True, 'dir': vdir, 'message': 'downloaded', 'compose': compose_name})
                except Exception as e:
                    out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': str(e), 'compose': compose_name})
        return jsonify({'items': out, 'log': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vuln_compose/pull', methods=['POST'])
def vuln_compose_pull():
    """Run docker compose pull for the given catalog items (assumes docker-compose.yml is present).

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, ok: bool, message: str}] }
    """
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        logs: list[str] = []
        base_out = os.path.abspath(_vuln_base_dir())
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            gh = _parse_github_url(path)
            if gh.get('is_github'):
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                sub = gh.get('subpath') or ''
                # blob file path -> direct compose path
                is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                base_dir = os.path.join(repo_dir, os.path.dirname(sub)) if is_file_sub else (os.path.join(repo_dir, sub) if sub else repo_dir)
                try:
                    logs.append(
                        f"[pull] {name}: git_url={gh.get('git_url')} branch={gh.get('branch')} subpath={gh.get('subpath')} base_dir={base_dir}"
                    )
                except Exception:
                    pass
                # prefer provided compose name
                yml_path = os.path.join(repo_dir, sub) if is_file_sub else os.path.join(base_dir, compose_name)
                if not os.path.exists(yml_path):
                    cand = _compose_candidates(base_dir)
                    yml_path = cand[0] if cand else None
                try:
                    logs.append(f"[pull] {name}: yml_path={yml_path}")
                except Exception:
                    pass
            else:
                yml_path = os.path.join(vdir, compose_name)
                try:
                    logs.append(f"[pull] {name}: non-github base_dir={vdir}")
                except Exception:
                    pass
            if not yml_path or not os.path.exists(yml_path):
                out.append({'Name': name, 'Path': path, 'ok': False, 'message': 'compose file missing', 'compose': compose_name})
                continue
            if not shutil.which('docker'):
                out.append({'Name': name, 'Path': path, 'ok': False, 'message': 'docker not available', 'compose': compose_name})
                continue
            try:
                proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'pull'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    logs.append(f"[pull] {name}: docker compose pull rc={proc.returncode} file={yml_path}")
                    if proc.stdout:
                        for ln in proc.stdout.splitlines()[:200]:
                            logs.append(f"[docker] {ln}")
                except Exception:
                    pass
                ok = proc.returncode == 0
                msg = 'ok' if ok else ((proc.stdout or '')[-1000:] if proc.stdout else 'failed')
                out.append({'Name': name, 'Path': path, 'ok': ok, 'message': msg, 'compose': compose_name})
            except Exception as e:
                out.append({'Name': name, 'Path': path, 'ok': False, 'message': str(e), 'compose': compose_name})
        return jsonify({'items': out, 'log': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vuln_compose/remove', methods=['POST'])
def vuln_compose_remove():
    """Remove docker-compose assets and containers/images for the given catalog items.

    Steps per item:
    - Resolve compose file path (like status/pull)
    - docker compose down --volumes --remove-orphans
    - Optionally remove images referenced by compose (best-effort)
    - Remove downloaded directories (repo dir or compose file directory) under outputs

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, ok: bool, message: str}] }
    """
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        logs: list[str] = []
        base_out = os.path.abspath(_vuln_base_dir())
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            gh = _parse_github_url(path)
            yml_path = None
            base_dir = vdir
            try:
                logs.append(f"[remove] {name}: Path={path}")
            except Exception:
                pass
            if gh.get('is_github'):
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                sub = gh.get('subpath') or ''
                is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
                base_dir = os.path.join(repo_dir, os.path.dirname(sub)) if is_file_sub else (os.path.join(repo_dir, sub) if sub else repo_dir)
                yml_path = os.path.join(repo_dir, sub) if is_file_sub else os.path.join(base_dir, compose_name)
                if not os.path.exists(yml_path):
                    cand = _compose_candidates(base_dir)
                    yml_path = cand[0] if cand else None
            else:
                yml_path = os.path.join(vdir, compose_name)
            # Bring down compose stack
            if yml_path and os.path.exists(yml_path) and shutil.which('docker'):
                try:
                    logs.append(f"[remove] {name}: docker compose down file={yml_path}")
                except Exception:
                    pass
                try:
                    proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'down', '--volumes', '--remove-orphans'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    try:
                        logs.append(f"[remove] docker compose down rc={proc.returncode}")
                        if proc.stdout:
                            for ln in proc.stdout.splitlines()[:200]:
                                logs.append(f"[docker] {ln}")
                    except Exception:
                        pass
                except Exception as e:
                    try: logs.append(f"[remove] compose down error: {e}")
                    except Exception: pass
                # Attempt to remove images referenced by compose (best-effort)
                try:
                    proc2 = subprocess.run(['docker', 'compose', '-f', yml_path, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    if proc2.returncode == 0:
                        images = [ln.strip() for ln in (proc2.stdout or '').splitlines() if ln.strip()]
                        for img in images:
                            p3 = subprocess.run(['docker', 'image', 'rm', '-f', img], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            try: logs.append(f"[remove] image rm {img} rc={p3.returncode}")
                            except Exception: pass
                except Exception:
                    pass
            # Remove downloaded files/dirs under outputs for this item
            try:
                if gh.get('is_github'):
                    repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                    if os.path.isdir(repo_dir):
                        shutil.rmtree(repo_dir, ignore_errors=True)
                        logs.append(f"[remove] {name}: deleted {repo_dir}")
                else:
                    # legacy direct compose path
                    yml = os.path.join(vdir, compose_name)
                    if os.path.exists(yml):
                        try:
                            os.remove(yml)
                            logs.append(f"[remove] {name}: deleted {yml}")
                        except Exception:
                            pass
                # Remove vdir if empty
                try:
                    if os.path.isdir(vdir) and not os.listdir(vdir):
                        os.rmdir(vdir)
                        logs.append(f"[remove] {name}: cleaned empty {vdir}")
                except Exception:
                    pass
            except Exception as e:
                try: logs.append(f"[remove] cleanup error: {e}")
                except Exception: pass
            out.append({'Name': name, 'Path': path, 'ok': True, 'message': 'removed', 'compose': compose_name})
        return jsonify({'items': out, 'log': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data_sources/edit/<sid>')
def data_sources_edit(sid):
    """Render an editable view of the CSV source in a simple table.
    """
    state = _load_data_sources_state()
    target = None
    for s in state.get('sources', []):
        if s.get('id') == sid:
            target = s
            break
    if not target:
        flash('Source not found')
        return redirect(url_for('data_sources_page'))
    path = target.get('path')
    if not path or not os.path.exists(path):
        flash('File missing')
        return redirect(url_for('data_sources_page'))
    # Read CSV safely
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace', newline='') as f:
        rdr = csv.reader(f)
        for r in rdr:
            rows.append(r)
    name = target.get('name') or os.path.basename(path)
    return render_template('data_source_edit.html', sid=sid, name=name, path=path, rows=rows)

@app.route('/data_sources/save/<sid>', methods=['POST'])
def data_sources_save(sid):
    """Save edited CSV content coming from the editor page.
    Expects JSON payload: { rows: string[][] }
    """
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or 'rows' not in data:
            return jsonify({"ok": False, "error": "Invalid payload"}), 400
        rows = data.get('rows')
        if not isinstance(rows, list) or any(not isinstance(r, list) for r in rows):
            return jsonify({"ok": False, "error": "Rows must be a list of lists"}), 400
        # Basic row length normalization (pad shorter rows to header length)
        maxw = max((len(r) for r in rows), default=0)
        norm = []
        for r in rows:
            if len(r) < maxw:
                r = r + [''] * (maxw - len(r))
            norm.append([str(c) if c is not None else '' for c in r])
        state = _load_data_sources_state()
        target = None
        for s in state.get('sources', []):
            if s.get('id') == sid:
                target = s
                break
        if not target:
            return jsonify({"ok": False, "error": "Source not found"}), 404
        path = target.get('path')
        if not path:
            return jsonify({"ok": False, "error": "Missing file path"}), 400
        # Validate and normalize according to schema
        # Write temp to validate with the same function used for uploads
        tmp_preview = path + '.editpreview'
        try:
            with open(tmp_preview, 'w', encoding='utf-8', newline='') as f:
                w = csv.writer(f)
                for r in norm:
                    w.writerow(r)
            ok2, note2, norm_rows2, skipped2 = _validate_and_normalize_data_source_csv(tmp_preview, skip_invalid=True)
        finally:
            try: os.remove(tmp_preview)
            except Exception: pass
        if not ok2:
            return jsonify({"ok": False, "error": note2}), 200
        # Atomic write normalized rows
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            for r in (norm_rows2 or norm):
                w.writerow(r)
        os.replace(tmp, path)
        # Update state row count
        ok, note = _validate_csv(path)
        if ok2 and skipped2:
            note_extra = f" (skipped {len(skipped2)} invalid)"
        else:
            note_extra = ''
        target['rows'] = (note if ok else f"ERR: {note}") + note_extra
        _save_data_sources_state(state)
        return jsonify({"ok": True, "skipped": len(skipped2) if ok2 else 0})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

def _purge_run_history_for_scenario(scenario_name: str, delete_artifacts: bool = True) -> int:
    """Remove any run history entries whose scenario_names contains scenario_name.
    Optionally delete associated artifact files (xml/report/pre-session xml) under outputs/.
    Returns number of entries removed.
    """
    try:
        if not os.path.exists(RUN_HISTORY_PATH):
            return 0
        with open(RUN_HISTORY_PATH, 'r', encoding='utf-8') as f:
            hist = json.load(f)
        if not isinstance(hist, list):
            return 0
        kept = []
        removed = 0
        for entry in hist:
            scen_list = []
            try:
                if 'scenario_names' in entry:
                    scen_list = entry.get('scenario_names') or []
                else:
                    scen_list = _scenario_names_from_xml(entry.get('xml_path'))
            except Exception:
                scen_list = []
            if scenario_name in scen_list:
                removed += 1
                if delete_artifacts:
                    for key in ('xml_path','report_path','pre_xml_path','post_xml_path','scenario_xml_path'):
                        p = entry.get(key)
                        if p and isinstance(p,str) and os.path.exists(p):
                            # Only delete if inside outputs directory for safety
                            try:
                                out_abs = os.path.abspath('outputs')
                                p_abs = os.path.abspath(p)
                                if p_abs.startswith(out_abs):
                                    try: os.remove(p_abs)
                                    except Exception: pass
                                    # Attempt to remove directory if empty afterwards
                                    try:
                                        parent = os.path.dirname(p_abs)
                                        if parent.startswith(out_abs) and os.path.isdir(parent) and not os.listdir(parent):
                                            os.rmdir(parent)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                continue
            kept.append(entry)
        if removed:
            tmp = RUN_HISTORY_PATH + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(kept, f, indent=2)
            os.replace(tmp, RUN_HISTORY_PATH)
        return removed
    except Exception:
        return 0

@app.route('/purge_history_for_scenario', methods=['POST'])
def purge_history_for_scenario():
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'removed': 0}), 200
        removed = _purge_run_history_for_scenario(name, delete_artifacts=True)
        return jsonify({'removed': removed})
    except Exception as e:
        return jsonify({'removed': 0, 'error': str(e)}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)
