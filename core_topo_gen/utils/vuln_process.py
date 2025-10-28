from __future__ import annotations
import logging
import os
import csv
import json
import random
import re
from typing import Iterable, Tuple, List, Dict, Optional, Set
import urllib.request
import shutil

try:
	import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency handled at runtime
	yaml = None  # type: ignore


logger = logging.getLogger(__name__)

_COMPOSE_PORT_CACHE: Dict[Tuple[str, str], List[Dict[str, object]]] = {}


def _read_csv(path: str) -> List[Dict[str, str]]:
	rows: List[Dict[str, str]] = []
	try:
		with open(path, newline='', encoding='utf-8', errors='ignore') as f:
			r = csv.DictReader(f)
			for row in r:
				# Normalize keys we care about; ignore rows without mandatory fields
				name = (row.get('Name') or '').strip()
				path_val = (row.get('Path') or '').strip()
				if not name or not path_val:
					continue
				rows.append({
					'Name': name,
					'Path': path_val,
					'Type': (row.get('Type') or '').strip(),
					'Vector': (row.get('Vector') or '').strip(),
					'Startup': (row.get('Startup') or '').strip(),
					'CVE': (row.get('CVE') or '').strip(),
					'Description': (row.get('Description') or '').strip(),
					'References': (row.get('References') or '').strip(),
				})
	except Exception:
		return []
	return rows


def load_vuln_catalog(repo_root: str) -> List[Dict[str, str]]:
	"""Load a vulnerability catalog for CLI selection.

	Best-effort: prefer raw_datasources CSVs shipped with the repo.
	Returns a list of dicts with at least Name, Path, and optional Type/Vector.
	"""
	candidates = [
		os.path.join(repo_root, 'raw_datasources', 'vuln_list_w_url.csv'),
		os.path.join(repo_root, 'raw_datasources', 'vuln_list.csv'),
	]
	items: List[Dict[str, str]] = []
	for p in candidates:
		if os.path.exists(p):
			items.extend(_read_csv(p))
	# Deduplicate by (Name, Path)
	seen = set()
	out: List[Dict[str, str]] = []
	for it in items:
		key = (it.get('Name'), it.get('Path'))
		if key in seen:
			continue
		seen.add(key)
		out.append(it)
	return out


def _norm_type(s: str) -> str:
	s = (s or '').strip().lower()
	if s in ("docker", "compose", "docker compose", "docker-compose", "docker_compose"):
		return "docker-compose"
	return s


def _filter_by_type_vector(catalog: Iterable[Dict[str, str]], v_type: str | None, v_vector: str | None) -> List[Dict[str, str]]:
	vt = _norm_type(v_type or '')
	vv = (v_vector or '').strip().lower()
	out: List[Dict[str, str]] = []
	for it in catalog:
		it_vt = _norm_type(it.get('Type') or '')
		it_vv = (it.get('Vector') or '').strip().lower()
		if vt and it_vt != vt:
			continue
		if vv and it_vv != vv:
			continue
		out.append(it)
	return out


def select_vulnerabilities(density: float, items_cfg: List[dict], catalog: List[Dict[str, str]]) -> List[Dict[str, str]]:
	"""Select vulnerabilities from catalog based on density and config items.

	- density in [0..1] scales the total number of selections.
	- items_cfg is a list of entries with 'selected' and optional fields:
	  * 'Random': use entire catalog
	  * 'Type/Vector': filter by keys 'v_type' and 'v_vector'
	  * 'Specific': use provided 'v_name' and 'v_path'
	"""
	# Even if catalog is empty, we can still honor 'Specific' selections by returning them directly
	dens = max(0.0, min(1.0, float(density or 0.0)))
	total_target = int(round(dens * len(catalog))) if catalog else 0
	if dens > 0.0 and total_target == 0 and len(catalog) > 0:
		total_target = 1
	# Determine per-item allocations based on factors
	factors: List[float] = []
	s_items = items_cfg or []
	if s_items:
		total_factor = 0.0
		for it in s_items:
			try:
				total_factor += float(it.get('factor') or 0.0)
			except Exception:
				continue
		if total_factor <= 0:
			factors = [1.0 / len(s_items) for _ in s_items]
		else:
			factors = [max(0.0, float((it.get('factor') or 0.0))) / total_factor for it in s_items]
	else:
		s_items = [{'selected': 'Random', 'factor': 1.0}]
		factors = [1.0]

	selected: List[Dict[str, str]] = []
	used = set()
	remaining = total_target
	for it, frac in zip(s_items, factors):
		sel = (it.get('selected') or 'Random').strip()
		# Accept UI synonym 'Category' for 'Type/Vector'
		if sel == 'Category':
			sel = 'Type/Vector'
		# Specific selections bypass density allocation and are always included
		if sel == 'Specific':
			name = (it.get('v_name') or '').strip()
			path = (it.get('v_path') or '').strip()
			if name and path:
				key = (name, path)
				if key not in used:
					selected.append({'Name': name, 'Path': path})
					used.add(key)
			continue
		# Determine candidate pool
		pool = catalog
		if sel == 'Type/Vector':
			pool = _filter_by_type_vector(catalog, it.get('v_type'), it.get('v_vector'))
		# Allocate count
		alloc = int(round(frac * total_target)) if total_target > 0 else 0
		alloc = min(max(0, alloc), max(0, remaining))
		if alloc <= 0:
			continue
		# Random sample without replacement respecting already used items
		pool2 = [p for p in pool if (p.get('Name'), p.get('Path')) not in used] if pool else []
		if not pool2:
			continue
		if alloc >= len(pool2):
			picks = pool2
		else:
			picks = random.sample(pool2, alloc)
		for p in picks:
			key = (p.get('Name'), p.get('Path'))
			if key in used:
				continue
			used.add(key)
			selected.append(p)
		remaining = max(0, remaining - len(picks))
		if remaining <= 0:
			break
	return selected


# ---------------- docker-compose assignment helpers ----------------

def _parse_github_url(url: str) -> dict:
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
			return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
		branch = parts[3]
		rest = '/'.join(parts[4:])
		return {'is_github': True, 'git_url': git_url, 'branch': branch, 'subpath': rest, 'mode': mode}
	except Exception:
		return {'is_github': False}


def _compose_candidates(base_dir: str) -> List[str]:
	cands = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
	out: List[str] = []
	try:
		if not os.path.isdir(base_dir):
			return out
		for nm in cands:
			p = os.path.join(base_dir, nm)
			if os.path.exists(p):
				out.append(p)
	except Exception:
		pass
	return out


def _compose_path_from_download(rec: Dict[str, str], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> Optional[str]:
	"""Resolve local compose path for a previously downloaded catalog item (webapp stores under /tmp/vulns).

	Returns a file path if found, else None.
	"""
	try:
		name = (rec.get('Name') or '').strip()
		path = (rec.get('Path') or '').strip()
		safe = _safe_name(name or 'vuln')
		vdir = os.path.join(out_base, safe)
		gh = _parse_github_url(path)
		if gh.get('is_github'):
			repo_dir = os.path.join(vdir, '_repo')
			sub = gh.get('subpath') or ''
			is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
			if is_file_sub:
				p = os.path.join(repo_dir, sub)
				return p if os.path.exists(p) else None
			base = os.path.join(repo_dir, sub) if sub else repo_dir
			pref = os.path.join(base, compose_name)
			if os.path.exists(pref):
				return pref
			cand = _compose_candidates(base)
			return cand[0] if cand else None
		else:
			p = os.path.join(vdir, compose_name)
			return p if os.path.exists(p) else None
	except Exception:
		return None


def _images_pulled_for_compose(yml_path: str) -> bool:
	try:
		import subprocess
		import shutil as _sh
		if not _sh.which('docker'):
			return False
		proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
		if proc.returncode != 0:
			return False
		images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
		if not images:
			return False
		for img in images:
			p2 = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			if p2.returncode != 0:
				return False
		return True
	except Exception:
		return False


def _eligible_compose_items(catalog: Iterable[Dict[str, str]], v_type: Optional[str], v_vector: Optional[str], out_base: str = "/tmp/vulns") -> List[Dict[str, str]]:
	"""Filter catalog to docker-compose items matching type/vector and with local compose pulled.
	v_type/v_vector may be 'Random' or falsy to indicate no filtering on that dimension.
	"""
	vt = (v_type or '').strip().lower()
	vv = (v_vector or '').strip().lower()
	items: List[Dict[str, str]] = []
	for it in catalog:
		t = (it.get('Type') or '').strip().lower()
		if t != 'docker-compose':
			continue
		if vt and vt != 'random' and t != vt:
			# type mismatch; note vt would be 'docker-compose' normally
			continue
		vec = (it.get('Vector') or '').strip().lower()
		if vv and vv != 'random' and vec != vv:
			continue
		yml = _compose_path_from_download(it, out_base=out_base)
		if not yml or not os.path.exists(yml):
			continue
		if not _images_pulled_for_compose(yml):
			continue
		items.append(it)
	return items


def assign_compose_to_nodes(node_names: List[str], density: float, items_cfg: List[dict], catalog: List[Dict[str, str]], out_base: str = "/tmp/vulns", require_pulled: bool = True, base_host_pool: int | None = None) -> Dict[str, Dict[str, str]]:
	"""Assign docker-compose vulnerabilities to nodes.

	Rules (updated semantics):
	- Weight-based vulnerability rows (v_metric == Weight or default) allocate up to
	  round(density * base_host_pool) nodes, where base_host_pool is the scenario
	  "Count for Density". Additive Count rows (v_metric == Count or Specific with
	  explicit v_count) do NOT contribute to the density base and are applied in
	  addition to the density-derived allocation.
	- Count rows are allocated first (absolute), consuming nodes from the pool.
	- Weight rows then allocate from remaining nodes up to the density target.
	- 'Category' is treated as 'Type/Vector' for normalization.
	- If require_pulled is True, only locally pulled compose items are eligible.

	Returns: mapping of node_name -> catalog record (docker-compose entries only).
	"""
	if not node_names or not items_cfg:
		return {}

	# Determine base for density (fallback to total nodes if missing)
	try:
		base_for_density = int(base_host_pool) if (base_host_pool is not None and int(base_host_pool) >= 0) else len(node_names)
	except Exception:
		base_for_density = len(node_names)
	dens = max(0.0, min(1.0, float(density or 0.0)))
	# Use floor (not round) to align with router density semantics and avoid over-allocation
	import math as _math
	density_target = int(_math.floor(dens * base_for_density + 1e-9))

	# Logging (best-effort)
	try:
		import logging as _logging
		_logging.getLogger(__name__).debug(
			"assign_compose_to_nodes: base_for_density=%d total_nodes=%d dens=%.3f density_target=%d",
			base_for_density, len(node_names), dens, density_target
		)
	except Exception:
		pass

	rng = random.Random()
	nodes_pool = list(node_names)
	rng.shuffle(nodes_pool)
	assigned: Dict[str, Dict[str, str]] = {}

	# Normalize and classify items
	norm_items: List[dict] = []
	for it in items_cfg:
		it2 = dict(it)
		if (it2.get('selected') or '') == 'Category':
			it2['selected'] = 'Type/Vector'
		norm_items.append(it2)

	count_items: List[dict] = []
	weight_items: List[dict] = []
	for it in norm_items:
		sel = (it.get('selected') or '').strip()
		metric = (it.get('v_metric') or '').strip()  # optional
		has_count = False
		if metric.lower() == 'count':
			has_count = True
		# Specific with v_count provided is also treated as count-based
		if sel == 'Specific':
			try:
				if int(it.get('v_count') or 0) > 0:
					has_count = True
			except Exception:
				pass
		if has_count:
			count_items.append(it)
		else:
			weight_items.append(it)

	def pop_nodes(k: int) -> List[str]:
		nonlocal nodes_pool
		k = max(0, min(k, len(nodes_pool)))
		taken = nodes_pool[:k]
		nodes_pool = nodes_pool[k:]
		return taken

	# 1) Allocate Count items (absolute, additive)
	for it in count_items:
		try:
			req = int(it.get('v_count') or 0)
		except Exception:
			req = 0
		if req <= 0 or not nodes_pool:
			continue
		sel = (it.get('selected') or 'Type/Vector').strip()
		pool: List[Dict[str, str]] = []
		if sel == 'Specific':
			nm = (it.get('v_name') or '').strip()
			pp = (it.get('v_path') or '').strip()
			rec: Optional[Dict[str, str]] = None
			for r in catalog:
				if r.get('Name') == nm and r.get('Path') == pp and _norm_type(r.get('Type') or '') == 'docker-compose':
					rec = r
					break
			if rec is None and pp:
				# synthetic fallback
				rec = {"Name": nm or 'vuln', "Path": pp, "Type": 'docker-compose', "Vector": it.get('v_vector') or ''}
			if rec:
				pool = [rec]
		else:  # Type/Vector
			if require_pulled:
				pool = _eligible_compose_items(catalog, it.get('v_type'), it.get('v_vector'), out_base=out_base)
			else:
				vt = _norm_type(it.get('v_type') or '')
				vv = (it.get('v_vector') or '').strip().lower()
				for r in catalog:
					if _norm_type(r.get('Type') or '') != 'docker-compose':
						continue
					if vt and vt != 'random' and _norm_type(r.get('Type') or '') != vt:
						continue
					if vv and vv != 'random' and (r.get('Vector') or '').strip().lower() != vv:
						continue
					pool.append(r)
		if not pool:
			continue
		take_nodes = pop_nodes(req)
		if not take_nodes:
			break
		# choose (with replacement if needed) for each node
		for nn in take_nodes:
			rec = rng.choice(pool)
			# ensure compose is present if required (only matters for Specific synthetic)
			if require_pulled:
				pth = _compose_path_from_download(rec, out_base=out_base)
				if not pth or not _images_pulled_for_compose(pth):
					continue
			assigned[nn] = rec
			try:
				logger.info(
					"[vuln-assign] count allocation node=%s name=%s path=%s",
					nn,
					rec.get('Name'),
					rec.get('Path'),
				)
			except Exception:
				pass

	# 2) Allocate Weight items up to density_target (independent of how many count nodes consumed)
	if density_target <= 0 or not weight_items or not nodes_pool:
		return assigned
	remaining = min(density_target, len(nodes_pool))

	# Gather weights
	weights: List[Tuple[dict, float]] = []
	total_w = 0.0
	for it in weight_items:
		try:
			w = float(it.get('v_weight') or it.get('factor') or 0.0)
		except Exception:
			w = 0.0
		if w > 0:
			weights.append((it, w))
			total_w += w
	if total_w <= 0:
		# even split
		weights = [(it, 1.0) for it in weight_items]
		total_w = float(len(weight_items))

	# Compute integer allocations with remainder distribution
	allocs: List[Tuple[dict, int]] = []
	remainders: List[Tuple[float, int]] = []  # (fractional_part, index)
	for idx, (it, w) in enumerate(weights):
		exact = (w / total_w) * remaining
		base_cnt = int(exact)
		allocs.append((it, base_cnt))
		remainders.append((exact - base_cnt, idx))
	used = sum(c for _, c in allocs)
	left = remaining - used
	# sort by largest fractional remainder
	remainders.sort(key=lambda x: x[0], reverse=True)
	ri = 0
	while left > 0 and ri < len(remainders):
		_, idx = remainders[ri]
		it, c = allocs[idx]
		allocs[idx] = (it, c + 1)
		left -= 1
		ri += 1

	# Perform allocations
	for it, cnt in allocs:
		if cnt <= 0 or not nodes_pool:
			continue
		sel = (it.get('selected') or '').strip()
		pool: List[Dict[str, str]] = []
		if sel == 'Type/Vector':
			v_type = (it.get('v_type') or 'docker-compose').strip()
			v_vec = (it.get('v_vector') or 'Random').strip()
			if require_pulled:
				pool = _eligible_compose_items(catalog, v_type, v_vec, out_base=out_base)
			else:
				# lenient filter (no file/image checks)
				vt = _norm_type(v_type)
				vv = v_vec.strip().lower()
				for r in catalog:
					if _norm_type(r.get('Type') or '') != 'docker-compose':
						continue
					if vt and vt != 'random' and _norm_type(r.get('Type') or '') != vt:
						continue
					if vv and vv != 'random' and (r.get('Vector') or '').strip().lower() != vv:
						continue
					pool.append(r)
		elif sel == 'Specific':
			# Specific without count behaves like Type/Vector random
			if require_pulled:
				pool = _eligible_compose_items(catalog, 'docker-compose', 'Random', out_base=out_base)
			else:
				pool = [r for r in catalog if _norm_type(r.get('Type') or '') == 'docker-compose']
		else:
			# Default: any docker-compose
			if require_pulled:
				pool = _eligible_compose_items(catalog, 'docker-compose', 'Random', out_base=out_base)
			else:
				pool = [r for r in catalog if _norm_type(r.get('Type') or '') == 'docker-compose']
		if not pool:
			continue
		take_nodes = pop_nodes(cnt)
		if not take_nodes:
			break
		# sample with replacement if pool smaller than cnt
		for nn in take_nodes:
			rec = rng.choice(pool)
			assigned[nn] = rec
			try:
				logger.info(
					"[vuln-assign] weight allocation node=%s name=%s path=%s",
					nn,
					rec.get('Name'),
					rec.get('Path'),
				)
			except Exception:
				pass

	return assigned


def _safe_name(s: str) -> str:
	s = s.strip().lower()
	s = re.sub(r'[^a-z0-9._-]+', '-', s)
	s = s.strip('-_.')
	return s or 'vuln'


def _github_tree_to_raw(base_url: str, filename: str) -> str | None:
	"""Convert a GitHub tree/blob URL to a raw file URL if possible."""
	try:
		m = re.match(r'^https?://github.com/([^/]+)/([^/]+)/(tree|blob)/([^/]+)/(.*)$', base_url.strip())
		if not m:
			return None
		user, repo, _kind, branch, path = m.groups()
		# Use provided filename under that path
		path = path.strip('/')
		file_part = filename.strip('/')
		raw = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}/{file_part}"
		return raw
	except Exception:
		return None


def _guess_compose_raw_url(path: str, compose_name: str = 'docker-compose.yml') -> Optional[str]:
	"""Best-effort: given a catalog Path, try to produce a raw URL to a compose file.

	Supports:
	- GitHub tree URLs pointing to a directory: append compose_name via raw content endpoint
	- GitHub blob URLs pointing directly to a .yml/.yaml file
	- Direct HTTP(S) URLs ending with .yml/.yaml
	"""
	try:
		p = (path or '').strip()
		if not p:
			return None
		# direct raw file
		if p.lower().endswith(('.yml', '.yaml')):
			# If it's a github blob URL, convert to raw
			m = re.match(r'^https?://github.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$', p)
			if m:
				user, repo, branch, rest = m.groups()
				return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
			return p
		# GitHub tree URL to a directory
		raw = _github_tree_to_raw(p, compose_name)
		if raw:
			return raw
		# Otherwise, append compose_name naively
		p2 = p.rstrip('/') + '/' + compose_name
		return p2
	except Exception:
		return None


def _download_to(path: str, dest_path: str, timeout: float = 30.0) -> bool:
	"""Download a URL or copy a local file to dest_path. Returns True on success."""
	try:
		if not path:
			return False
		if re.match(r'^https?://', path, re.IGNORECASE):
			with urllib.request.urlopen(path, timeout=timeout) as resp:
				data = resp.read(5_000_000)
			os.makedirs(os.path.dirname(dest_path), exist_ok=True)
			with open(dest_path, 'wb') as f:
				f.write(data)
			return True
		# Local file path
		if os.path.exists(path):
			os.makedirs(os.path.dirname(dest_path), exist_ok=True)
			shutil.copy2(path, dest_path)
			return True
		return False
	except Exception:
		return False


def _strip_port_mapping_value(port_value: str) -> str:
	"""Return only the container-side port component from a port mapping string."""
	text = str(port_value).strip()
	if ':' not in text:
		return text
	parts = text.split(':')
	if not parts:
		return text
	container_segment = parts[-1].strip()
	return container_segment or text


def _prune_service_ports(service: Dict[str, object]) -> None:
	"""Update a docker-compose service entry to drop published host ports."""
	if not isinstance(service, dict):
		return
	ports = service.get('ports')
	if not ports or not isinstance(ports, list):
		return
	changed = False
	new_ports: List[object] = []
	for entry in ports:
		if isinstance(entry, str):
			value = entry.strip()
			if ':' in value and not value.startswith('{'):
				new_value = _strip_port_mapping_value(value)
				if new_value != value:
					changed = True
					new_ports.append(new_value)
				continue
		elif isinstance(entry, dict):
			entry_copy = dict(entry)
			removed = False
			if 'published' in entry_copy:
				entry_copy.pop('published', None)
				removed = True
			if 'host_ip' in entry_copy:
				entry_copy.pop('host_ip', None)
				removed = True
			if removed:
				changed = True
			new_ports.append(entry_copy)
			continue
		new_ports.append(entry)
	if changed:
		service['ports'] = new_ports


def _strip_port_mappings_from_text(text: str) -> str:
	"""Best-effort removal of host->container port mappings in compose YAML text."""
	lines = text.splitlines()
	result: List[str] = []
	in_ports = False
	ports_indent: Optional[int] = None
	for line in lines:
		stripped = line.lstrip()
		indent = len(line) - len(stripped)
		if in_ports:
			if stripped and indent <= (ports_indent or 0) and not stripped.startswith('-'):
				in_ports = False
			if not in_ports:
				pass
			else:
				if stripped.startswith('-'):
					raw_entry = stripped[1:].strip()
					body = raw_entry
					comment = ''
					if '#' in raw_entry:
						hash_index = raw_entry.find('#')
						body = raw_entry[:hash_index].rstrip()
						comment = raw_entry[hash_index:].strip()
					if body and not body.startswith('{'):
						quote_char = ''
						closing_quote = ''
						content = body
						if len(body) >= 2 and body[0] in ("'", '"') and body[-1] == body[0]:
							quote_char = body[0]
							closing_quote = body[-1]
							content = body[1:-1]
						if ':' in content and ' ' not in content.split(':', 1)[0]:
							new_content = _strip_port_mapping_value(content)
							if quote_char:
								body = f"{quote_char}{new_content}{closing_quote}"
							else:
								body = new_content
							line = f"{' ' * indent}- {body}"
							if comment:
								line = f"{line} {comment}"
							result.append(line)
							continue
				if stripped.startswith('published:') or stripped.startswith('host_ip:'):
					continue
		if not in_ports and stripped.startswith('ports:'):
			in_ports = True
			ports_indent = indent
			result.append(line)
			continue
		result.append(line)
	if text.endswith('\n'):
		return '\n'.join(result) + '\n'
	return '\n'.join(result)


def _set_container_name_one_service(compose_obj: dict, container_name: str, prefer_service: Optional[str] = None) -> dict:
	"""Set container_name on one service in the compose file.

	Preference order:
	1) Service whose name matches `prefer_service` (case-insensitive substring)
	2) The first service in the mapping

	Returns the mutated object. If services are missing, no changes are made.
	"""
	try:
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict) or not services:
			return compose_obj
		target_key: Optional[str] = None
		if prefer_service:
			pref = prefer_service.strip().lower()
			for svc_key in services.keys():
				if pref in str(svc_key).strip().lower():
					target_key = svc_key
					break
		if target_key is None:
			target_key = next(iter(services.keys()))
		svc = services.get(target_key)
		if isinstance(svc, dict):
			svc['container_name'] = container_name
		return compose_obj
	except Exception:
		return compose_obj


def _parse_compose_ports_entry(entry: object) -> List[Tuple[str, int]]:
	"""Convert a docker-compose ports entry into one or more (protocol, port) tuples."""
	results: List[Tuple[str, int]] = []
	try:
		if isinstance(entry, int):
			if entry > 0:
				results.append(("tcp", int(entry)))
			return results
		if isinstance(entry, str):
			text = entry.strip()
			if not text:
				return results
			if '#' in text:
				text = text.split('#', 1)[0].strip()
			if not text:
				return results
			if text.startswith('{'):
				return results
			proto = 'tcp'
			if ':' in text:
				parts = text.split(':')
				text = parts[-1].strip()
			if '/' in text:
				value, proto_part = text.split('/', 1)
				text = value.strip()
				proto = (proto_part or 'tcp').strip().lower() or 'tcp'
			else:
				proto = 'tcp'
			port = int(text)
			if port > 0:
				results.append((proto, port))
			return results
		if isinstance(entry, dict):
			proto = str(entry.get('protocol') or entry.get('mode') or 'tcp').strip().lower() or 'tcp'
			for key in ('target', 'container_port', 'port'):
				value = entry.get(key)
				if value in (None, ''):
					continue
				text = str(value).strip()
				if '/' in text:
					text = text.split('/', 1)[0].strip()
				try:
					port = int(text)
				except Exception:
					continue
				if port > 0:
					results.append((proto, port))
					break
	except Exception:
		return []
	return results


def extract_compose_ports(rec: Dict[str, str], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> List[Dict[str, object]]:
	"""Best-effort extraction of container ports for a docker-compose vulnerability record."""
	if not rec:
		return []
	name_key = (rec.get('Name') or rec.get('name') or '').strip()
	path_key = (rec.get('Path') or rec.get('path') or '').strip()
	cache_key = (name_key, path_key)
	if cache_key in _COMPOSE_PORT_CACHE:
		return list(_COMPOSE_PORT_CACHE[cache_key])

	ports: List[Dict[str, object]] = []
	compose_path = rec.get('compose_path')
	if compose_path and not os.path.isabs(compose_path):
		compose_path = os.path.abspath(compose_path)
	if not compose_path or not os.path.exists(compose_path):
		safe = _safe_name(name_key or 'vuln') or 'vuln'
		base_dir = os.path.join(out_base, safe)
		os.makedirs(base_dir, exist_ok=True)
		if path_key and os.path.exists(path_key):
			compose_path = path_key
		else:
			candidates = _compose_candidates(base_dir)
			if candidates:
				compose_path = candidates[0]
			else:
				raw_url = _guess_compose_raw_url(path_key, compose_name=compose_name)
				if raw_url:
					dest = os.path.join(base_dir, compose_name)
					if _download_to(raw_url, dest):
						compose_path = dest
				elif path_key:
					dest = os.path.join(base_dir, compose_name)
					if _download_to(path_key, dest):
						compose_path = dest
	if not compose_path or not os.path.exists(compose_path):
		logger.debug("extract_compose_ports: compose file unavailable for %s (path=%s)", cache_key, compose_path)
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []

	if yaml is None:
		logger.debug("extract_compose_ports: PyYAML unavailable; skipping port extraction for %s", cache_key)
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []

	try:
		with open(compose_path, 'r', encoding='utf-8') as f:
			compose_obj = yaml.safe_load(f) or {}
	except Exception as exc:
		logger.debug("extract_compose_ports: failed to parse %s: %s", compose_path, exc)
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []

	services = compose_obj.get('services') if isinstance(compose_obj, dict) else None
	if not isinstance(services, dict):
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []
	seen: Set[Tuple[str, int]] = set()
	for svc_name, svc_body in services.items():
		if not isinstance(svc_body, dict):
			continue
		ports_field = svc_body.get('ports')
		if not ports_field:
			continue
		if not isinstance(ports_field, list):
			ports_field = [ports_field]
		for entry in ports_field:
			for proto, port in _parse_compose_ports_entry(entry):
				key = (proto, port)
				if key in seen:
					continue
				seen.add(key)
				ports.append({"protocol": proto, "port": port, "service": svc_name})

	_COMPOSE_PORT_CACHE[cache_key] = ports
	if ports and 'compose_ports' not in rec:
		try:
			rec['compose_ports'] = list(ports)
		except Exception:
			pass
	return list(ports)


def prepare_compose_for_nodes(selected: List[Dict[str, str]], node_names: List[str], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> List[str]:
	"""Prepare per-node docker-compose files for selected docker-compose vulnerabilities.

	Steps:
	- Identify the first selected item that appears to reference a docker-compose catalog entry
	- Download its compose file to out_base/<safe_name>/<compose_name> (best-effort)
	- For each node name, copy to out_base/docker-compose-<node>.yml and set `container_name: <node>` for all services

 	Returns a list of per-node compose file paths created.
	"""
	created: List[str] = []
	if not selected or not node_names:
		return created


def prepare_compose_for_assignments(name_to_vuln: Dict[str, Dict[str, str]], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> List[str]:
	"""Backward compatible helper used by CLI to build per-node compose files.

	Accepts a mapping of node name -> vulnerability record and produces
	docker-compose-<node>.yml for each record whose Type is docker-compose.
	"""
	created: List[str] = []
	if not name_to_vuln:
		return created
	os.makedirs(out_base, exist_ok=True)
	cache: Dict[Tuple[str, str], Tuple[Optional[dict], Optional[str]]] = {}
	for node_name, rec in name_to_vuln.items():
		vtype = (rec.get('Type') or '').strip().lower()
		if vtype != 'docker-compose':
			continue
		try:
			logger.info(
				"[vuln] preparing docker-compose for node=%s name=%s path=%s",
				node_name,
				rec.get('Name'),
				rec.get('Path'),
			)
		except Exception:
			pass
		key = ((rec.get('Name') or '').strip(), (rec.get('Path') or '').strip())
		base_compose_obj: Optional[dict]
		src_path: Optional[str]
		if key in cache:
			base_compose_obj, src_path = cache[key]
			try:
				logger.debug(
					"[vuln] compose cache hit key=%s src=%s has_yaml=%s",
					key,
					src_path,
					base_compose_obj is not None,
				)
			except Exception:
				pass
		else:
			safe = _safe_name(key[0] or 'vuln') or 'vuln'
			base_dir = os.path.join(out_base, safe)
			os.makedirs(base_dir, exist_ok=True)
			raw_url = _guess_compose_raw_url(key[1], compose_name=compose_name)
			src_path = os.path.join(base_dir, compose_name)
			ok = False
			if raw_url:
				logger.info("[vuln] fetching compose url=%s dest=%s", raw_url, src_path)
				ok = _download_to(raw_url, src_path)
			if not ok and key[1] and os.path.exists(key[1]):
				logger.info("[vuln] copying compose from local path=%s dest=%s", key[1], src_path)
				ok = _download_to(key[1], src_path)
			if not ok:
				cache[key] = (None, None)
				try:
					logger.warning("[vuln] unable to retrieve compose for key=%s", key)
				except Exception:
					pass
				continue
			base_compose_obj = None
			if yaml is not None:
				try:
					with open(src_path, 'r', encoding='utf-8') as f:
						base_compose_obj = yaml.safe_load(f) or {}
					logger.debug(
						"[vuln] parsed compose yaml key=%s services=%s",
						key,
						list((base_compose_obj.get('services') or {}).keys()),
					)
				except Exception:
					logger.exception("[vuln] yaml parse error for compose path=%s", src_path)
					base_compose_obj = None
			cache[key] = (base_compose_obj, src_path)
		out_path = os.path.join(out_base, f"docker-compose-{node_name}.yml")
		wrote = False
		if base_compose_obj is not None and yaml is not None:
			prefer = key[0]
			obj = _set_container_name_one_service(dict(base_compose_obj), node_name, prefer_service=prefer)
			try:
				with open(out_path, 'w', encoding='utf-8') as f:
					yaml.safe_dump(obj, f, sort_keys=False)
				services_keys = list((obj.get('services') or {}).keys()) if isinstance(obj, dict) else []
				logger.info("[vuln] wrote compose yaml node=%s services=%s dest=%s", node_name, services_keys, out_path)
				wrote = True
			except Exception:
				logger.exception("[vuln] failed writing compose yaml for node=%s", node_name)
		elif src_path and os.path.exists(src_path):
			try:
				shutil.copy2(src_path, out_path)
			except Exception:
				logger.exception("[vuln] failed copying compose for node=%s", node_name)
			else:
				try:
					with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
						txt = f.read()
					if 'container_name:' in txt:
						import re as _re
						txt = _re.sub(r'container_name\s*:\s*[^\n]+', f'container_name: {node_name}', txt, count=1)
					else:
						txt = txt.rstrip() + f"\n\n# injected container_name\ncontainer_name: {node_name}\n"
					text_sanitized = _strip_port_mappings_from_text(txt)
					logger.debug(
						"[vuln] sanitized compose text node=%s original_len=%s new_len=%s",
						node_name,
						len(txt),
						len(text_sanitized),
					)
					with open(out_path, 'w', encoding='utf-8') as f2:
						f2.write(text_sanitized)
				except Exception:
					logger.exception("[vuln] failed sanitizing compose text for node=%s", node_name)
				wrote = True
		if wrote:
			created.append(out_path)
			try:
				rec['compose_path'] = out_path
				logger.info("[vuln] compose file ready for node=%s compose=%s", node_name, out_path)
			except Exception:
				pass
		else:
			try:
				logger.warning("[vuln] compose not generated for node=%s", node_name)
			except Exception:
				pass
	return created


def process_vulnerabilities(selected: List[Dict[str, str]], out_dir: str) -> List[Tuple[Dict[str, str], str, bool, str]]:
	"""Process selected vulnerabilities.

	Minimal implementation: create a directory per item and write an info.json.
	Returns list of tuples: (record, action, ok, directory)
	"""
	os.makedirs(out_dir, exist_ok=True)
	results: List[Tuple[Dict[str, str], str, bool, str]] = []
	for rec in selected:
		name = (rec.get('Name') or '').strip() or 'vuln'
		safe = _safe_name(name)
		vdir = os.path.join(out_dir, safe)
		ok = False
		action = 'write-meta'
		try:
			os.makedirs(vdir, exist_ok=True)
			meta = {
				'Name': rec.get('Name'),
				'Path': rec.get('Path'),
				'Type': rec.get('Type'),
				'Vector': rec.get('Vector'),
			}
			with open(os.path.join(vdir, 'info.json'), 'w', encoding='utf-8') as f:
				json.dump(meta, f, indent=2)
			ok = True
		except Exception:
			ok = False
		results.append((rec, action, ok, vdir))
	return results


def start_compose_files(paths: List[str]) -> int:
	"""Start docker compose stacks for the given file paths on the host.

	Returns the number of successful "up -d" operations.
	"""
	ok = 0
	if not paths:
		return ok
	try:
		import subprocess, shutil as _sh
		if not _sh.which('docker'):
			return 0
		for p in paths:
			try:
				if not p or not os.path.exists(p):
					continue
				proc = subprocess.run(['docker', 'compose', '-f', p, 'up', '-d'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
				if proc.returncode == 0:
					ok += 1
			except Exception:
				continue
	except Exception:
		return ok
	return ok
