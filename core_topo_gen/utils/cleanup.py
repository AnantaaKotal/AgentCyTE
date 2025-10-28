from __future__ import annotations
"""Utility helpers for housekeeping (preview artifact cleanup).

These helpers remove old preview segmentation / traffic directories that are
created under the system temporary directory (see full_preview). Without
cleanup, repeated previews (different seeds) can accumulate and waste disk
space.

Policy (default):
  - Match directories whose names start with a known prefix
  - Keep the most recent `max_keep` per prefix (by mtime)
  - Always keep any directory younger than `max_age_hours`
  - Never delete the directory names explicitly listed in `protect` (e.g. the
    directories produced by the current preview invocation)
  - Best-effort only; all failures are swallowed after logging
"""

from typing import Iterable, List, Dict
import os
import time
import logging
import tempfile
import shutil

logger = logging.getLogger(__name__)


def clean_stale_preview_dirs(
    prefixes: Iterable[str] = ("core-topo-preview-seg-", "core-topo-preview-traffic-"),
    max_keep: int = 5,
    max_age_hours: float = 24.0,
    protect: Iterable[str] | None = None,
    temp_dir: str | None = None,
) -> Dict[str, int]:
    """Remove stale preview directories.

    Returns a dict summarizing deletions per prefix.
    All errors are non-fatal; if something cannot be removed it's skipped.
    """
    temp_dir = temp_dir or tempfile.gettempdir()
    now = time.time()
    protect_set = {os.path.abspath(p) for p in (protect or []) if p}
    deleted: Dict[str, int] = {}
    try:
        entries = os.listdir(temp_dir)
    except Exception:
        return deleted

    for prefix in prefixes:
        # Collect candidate dirs for this prefix
        candidates: List[str] = []
        for name in entries:
            if not name.startswith(prefix):
                continue
            path = os.path.join(temp_dir, name)
            if not os.path.isdir(path):
                continue
            if os.path.abspath(path) in protect_set:
                continue
            candidates.append(path)
        if not candidates:
            continue
        # Sort by mtime descending (newest first)
        try:
            candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        except Exception:
            # If mtime fetch fails for any, leave order as-is
            pass
        keep: List[str] = []
        remove: List[str] = []
        age_cutoff = now - max(0.0, max_age_hours) * 3600.0
        for idx, path in enumerate(candidates):
            try:
                mt = os.path.getmtime(path)
            except Exception:
                mt = 0
            if idx < max_keep:
                keep.append(path); continue
            if mt >= age_cutoff:
                keep.append(path); continue
            remove.append(path)
        removed_count = 0
        for path in remove:
            try:
                shutil.rmtree(path, ignore_errors=True)
                removed_count += 1
            except Exception:
                pass
        if removed_count:
            deleted[prefix] = removed_count
            try:
                logger.info("Preview cleanup: removed %d stale '%s*' dirs", removed_count, prefix)
            except Exception:
                pass
    return deleted


__all__ = ["clean_stale_preview_dirs"]
