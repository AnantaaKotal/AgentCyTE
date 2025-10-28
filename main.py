"""Convenience entry point for running the Flask Web UI."""

from __future__ import annotations

import os
from typing import Final

from webapp.app_backend import app


def _env_flag(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def main() -> None:
    """Start the Web UI using the in-repo Flask application."""

    default_host: Final[str] = os.environ.get("CORETG_HOST", "0.0.0.0")
    port_str = os.environ.get("CORETG_PORT", "9090")
    debug = _env_flag(os.environ.get("CORETG_DEBUG"))

    try:
        port = int(port_str)
    except ValueError:
        raise SystemExit(f"Invalid CORETG_PORT value: {port_str!r}")

    app.run(host=default_host, port=port, debug=debug)


if __name__ == "__main__":
    main()