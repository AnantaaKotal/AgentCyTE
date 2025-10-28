#!/usr/bin/env bash
set -euo pipefail

# Fast remove/recreate for docker-compose to test updates quickly.
# Usage:
#   scripts/dev-reload.sh [-c] [-l] [-p] [-V] [service ...]
# Options:
#   -c  Rebuild with --no-cache
#   -l  Follow logs after starting
#   -p  Prune dangling images after rebuild
#   -V  Remove volumes too (passes -v to docker compose down)
# If services are provided, only those services are built/started.

NO_CACHE=0
FOLLOW_LOGS=0
PRUNE_IMAGES=0
REMOVE_VOLUMES=0

while getopts ":clpV" opt; do
  case "$opt" in
    c) NO_CACHE=1 ;;
    l) FOLLOW_LOGS=1 ;;
    p) PRUNE_IMAGES=1 ;;
    V) REMOVE_VOLUMES=1 ;;
    :) echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1))

SERVICES=("$@")

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required but not found in PATH." >&2
  exit 1
fi

COMPOSE_CMD=(docker compose)

# Bring down stack
DOWN_ARGS=(down --remove-orphans)
if [[ "$REMOVE_VOLUMES" -eq 1 ]]; then
  DOWN_ARGS+=(-v)
fi

echo "[dev-reload] Stopping and removing containers..."
"${COMPOSE_CMD[@]}" "${DOWN_ARGS[@]}"

# Build
BUILD_ARGS=(build)
if [[ "$NO_CACHE" -eq 1 ]]; then
  BUILD_ARGS+=(--no-cache)
fi
if [[ ${#SERVICES[@]} -gt 0 ]]; then
  BUILD_ARGS+=("${SERVICES[@]}")
fi

echo "[dev-reload] Rebuilding images ${NO_CACHE:+(no-cache)}..."
"${COMPOSE_CMD[@]}" "${BUILD_ARGS[@]}"

# Optional prune dangling images
if [[ "$PRUNE_IMAGES" -eq 1 ]]; then
  echo "[dev-reload] Pruning dangling images..."
  docker image prune -f || true
fi

# Up
UP_ARGS=(up -d)
if [[ ${#SERVICES[@]} -gt 0 ]]; then
  UP_ARGS+=("${SERVICES[@]}")
fi

echo "[dev-reload] Starting containers..."
"${COMPOSE_CMD[@]}" "${UP_ARGS[@]}"

echo "[dev-reload] Done. Containers are running."

if [[ "$FOLLOW_LOGS" -eq 1 ]]; then
  echo "[dev-reload] Following logs. Press Ctrl+C to stop tailing."
  LOG_ARGS=(logs -f)
  if [[ ${#SERVICES[@]} -gt 0 ]]; then
    LOG_ARGS+=("${SERVICES[@]}")
  fi
  "${COMPOSE_CMD[@]}" "${LOG_ARGS[@]}"
fi
