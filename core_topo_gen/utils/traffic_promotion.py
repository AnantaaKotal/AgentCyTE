from __future__ import annotations
import os, shutil, logging
from typing import Optional

logger = logging.getLogger(__name__)

def promote_preview_traffic(preview_dir: str, final_dir: str = '/tmp/traffic', replace: bool = False) -> dict:
    """Move (or copy) preview-generated traffic scripts into the runtime directory.

    Parameters:
      preview_dir: temp directory holding preview scripts
      final_dir: runtime destination (/tmp/traffic by convention)
      replace: when True, existing destination files are removed first

    Returns: summary dict { 'moved': int, 'skipped': int, 'final_dir': str }
    """
    summary = {'moved': 0, 'skipped': 0, 'final_dir': final_dir}
    if not preview_dir or not os.path.exists(preview_dir):
        return summary
    os.makedirs(final_dir, exist_ok=True)
    if replace:
        try:
            for name in os.listdir(final_dir):
                p = os.path.join(final_dir, name)
                if os.path.isfile(p) and name.startswith('traffic_'):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
        except Exception:
            logger.warning('Failed cleaning existing traffic dir %s', final_dir)
    for name in os.listdir(preview_dir):
        if not name.startswith('traffic_'):
            summary['skipped'] += 1
            continue
        src = os.path.join(preview_dir, name)
        dst = os.path.join(final_dir, name)
        try:
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            summary['moved'] += 1
        except Exception as e:
            logger.warning('Failed promoting %s -> %s: %s', src, dst, e)
    return summary
