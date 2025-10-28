from __future__ import annotations
import logging
import re
from typing import Any, Optional
import time
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _call_create_session(core: Any, session_id: Optional[int] = None) -> Any:
    """Call CoreGrpcClient.create_session with best-effort compatibility.

    Tries different keyword names across CORE client versions, falling back to no-arg.
    Returns the created session object or raises the exception from the client.
    """
    # Some test stubs only expose add_session(); support that.
    if not hasattr(core, 'create_session') and hasattr(core, 'add_session'):
        return core.add_session()
    if session_id is None:
        return core.create_session()
    # Try known kwarg names first; fall back to no-arg if unsupported
    try:
        return core.create_session(session_id=session_id)
    except TypeError:
        try:
            return core.create_session(id=session_id)
        except TypeError:
            logger.debug("create_session does not accept a session id kwarg; falling back to no-arg")
            return core.create_session()


def _extract_pycore_id_from_error(err: BaseException) -> Optional[int]:
    try:
        msg = str(err)
    except Exception:
        return None
    m = re.search(r"pycore\.(\d+)", msg)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None


def safe_create_session(core: Any, max_attempts: int = 5) -> Any:
    """Create a CORE session robustly, avoiding 'File exists: /tmp/pycore.N' errors.

    Strategy:
    - Pre-scan existing sessions to propose next id.
    - Attempt create_session with that id when supported; on failure with a pycore.N collision, retry with N+1.
    - Fall back to plain create_session when kwargs are not supported.
    """
    # Pre-scan to propose a candidate id
    candidate: Optional[int] = None
    try:
        sessions = core.get_sessions()
        existing_ids: list[int] = []
        for s in (sessions or []):
            sid = getattr(s, 'id', None) or getattr(s, 'session_id', None)
            if sid is not None:
                try:
                    existing_ids.append(int(sid))
                except Exception:
                    continue
        if existing_ids:
            candidate = max(existing_ids) + 1
    except Exception:
        candidate = None

    attempts = 0
    last_err: Optional[BaseException] = None
    next_try = candidate
    while attempts < max_attempts:
        attempts += 1
        try:
            sess = _call_create_session(core, next_try)
            # Validate that the underlying /tmp/pycore.<id> directory is unique / not pre-existing leftover.
            try:
                sid = getattr(sess, 'id', None) or getattr(sess, 'session_id', None)
                if sid is not None:
                    p = Path(f"/tmp/pycore.{sid}")
                    # If directory already exists (stale), pick next id and retry after slight delay.
                    if p.exists() and len(list(p.glob('*'))) > 0 and attempts < max_attempts:
                        logger.info("Detected pre-existing non-empty %s; retrying with next id", p)
                        next_try = int(sid) + 1
                        time.sleep(0.2)
                        continue
            except Exception:
                pass
            return sess
        except BaseException as e:  # noqa: BLE001
            last_err = e
            # Detect pycore.N collision and choose a higher id
            py_id = _extract_pycore_id_from_error(e)
            if py_id is not None:
                next_try = py_id + 1
                logger.info("[grpc] create_session collided with /tmp/pycore.%s; retrying with session_id=%s (attempt %s/%s)", py_id, next_try, attempts, max_attempts)
                time.sleep(0.2)
                continue
            # Any other error: break and raise
            break
    if last_err is not None:
        raise last_err
    # Should not reach here; fallback to no-arg call
    # Final fallback: if create_session missing but add_session present (test stubs)
    if hasattr(core, 'add_session'):
        return core.add_session()
    return core.create_session()
