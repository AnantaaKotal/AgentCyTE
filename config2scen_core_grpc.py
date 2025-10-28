#!/usr/bin/env python3
"""
Thin entrypoint shim that preserves the original script name while delegating
to the refactored package CLI.
"""

from core_topo_gen.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
