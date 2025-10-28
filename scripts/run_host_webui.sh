#!/usr/bin/env bash
set -euo pipefail

# Start the Web UI on the host at 127.0.0.1:9090 using a preferred Python interpreter.
# Priority: $WEBUI_PY -> core-python -> python3 -> python

choose_python() {
  if [[ -n "${WEBUI_PY:-}" ]]; then
    echo "$WEBUI_PY"; return 0
  fi
  if command -v core-python >/dev/null 2>&1; then
    echo "core-python"; return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    echo "python3"; return 0
  fi
  echo "python"
}

PY_CMD=$(choose_python)

# Move to repo root if script run from elsewhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT/webapp"

export PYTHONUNBUFFERED=1

echo "[host-web] Using interpreter: $PY_CMD"
echo "[host-web] Starting Web UI on http://127.0.0.1:9090"

# Start the server in background and write its PID to repo root server.pid
cd "$REPO_ROOT/webapp"
"$PY_CMD" app_backend.py &
SERVER_PID=$!
echo "$SERVER_PID" > "$REPO_ROOT/server.pid"
echo "[host-web] Server PID: $SERVER_PID (written to $REPO_ROOT/server.pid)"
wait "$SERVER_PID"
