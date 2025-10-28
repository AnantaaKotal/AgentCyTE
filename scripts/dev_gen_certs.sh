#!/usr/bin/env bash
# dev_gen_certs.sh - generate a local self-signed TLS certificate for nginx (development only)
# Idempotent: does nothing if cert/key already exist unless FORCE_REGEN=1.
# Customize via env vars:
#   CERT_DAYS     (default 365)
#   CERT_SUBJECT  (default /CN=localhost)
#   CERT_SANS     (comma-separated, e.g. "DNS:localhost,IP:127.0.0.1")
#   FORCE_REGEN=1 (force re-generation even if existing files found)
# Usage:
#   bash scripts/dev_gen_certs.sh
#   CERT_DAYS=30 CERT_SUBJECT="/C=US/ST=CA/L=Local/O=Dev/CN=localhost" bash scripts/dev_gen_certs.sh

set -euo pipefail

CERT_DIR="nginx/certs"
CRT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"
DAYS="${CERT_DAYS:-365}"
SUBJECT="${CERT_SUBJECT:-/CN=localhost}"

if [[ -f "$CRT" && -f "$KEY" && "${FORCE_REGEN:-0}" != "1" ]]; then
  echo "[dev_gen_certs] Existing cert + key found (\n  $CRT\n  $KEY\n) - skipping generation."
  # Show brief details
  if command -v openssl >/dev/null 2>&1; then
    echo "[dev_gen_certs] Certificate summary:";
    openssl x509 -noout -subject -enddate -in "$CRT" || true
  fi
  exit 0
fi

echo "[dev_gen_certs] Generating new self-signed development certificate ..."
mkdir -p "$CERT_DIR"

# Generate 4096-bit RSA key + cert
if [[ -n "${CERT_SANS:-}" ]]; then
  echo "[dev_gen_certs] Using subjectAltName(s): $CERT_SANS"
  CFG="$(mktemp)"
  cat > "$CFG" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_req
[dn]
CN = ${SUBJECT#/CN=}
[v3_req]
subjectAltName = ${CERT_SANS//,/ , }
EOF
  # shellcheck disable=SC2086
  openssl req -x509 -nodes -newkey rsa:4096 -days "$DAYS" -keyout "$KEY" -out "$CRT" -config "$CFG" -extensions v3_req -subj "$SUBJECT"
  rm -f "$CFG"
else
  openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "$KEY" \
    -out "$CRT" \
    -days "$DAYS" -subj "$SUBJECT"
fi

# Restrict key perms (best effort on non-Windows)
chmod 600 "$KEY" 2>/dev/null || true

echo "[dev_gen_certs] Created files:"
ls -l "$CRT" "$KEY"

echo "[dev_gen_certs] Done. Launch with: docker compose up --build"
