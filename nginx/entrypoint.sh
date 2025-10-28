#!/bin/sh
set -eu

log() { printf '[nginx-init] %s\n' "$*"; }
err() { printf '[nginx-init][error] %s\n' "$*" >&2; }

CERT_DIR="/etc/nginx/certs"
CRT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"
DAYS="${CERT_DAYS:-365}"
SUBJECT="${CERT_SUBJECT:-/CN=localhost}"
SANS="${CERT_SANS:-}"

mkdir -p "$CERT_DIR"

# openssl is pre-installed in custom image (see nginx/Dockerfile)

if [ -f "$CRT" ] && [ -f "$KEY" ]; then
  log "existing certificate found; skipping generation"
else
  log "no certificate present; generating self-signed cert"
  if [ -n "$SANS" ]; then
    log "using subjectAltName list: $SANS"
    TMP_CFG="$(mktemp)"
    # Convert comma-separated SANS into proper openssl config syntax
    SAN_LINE="subjectAltName=${SANS}"
    cat > "$TMP_CFG" <<EOF
[req]
distinguished_name=dn
prompt=no
x509_extensions=v3_req
[v3_req]
${SAN_LINE}
[dn]
CN=${SUBJECT#/CN=}
EOF
    openssl req -x509 -nodes -newkey rsa:4096 -days "$DAYS" \
      -keyout "$KEY" -out "$CRT" -config "$TMP_CFG" -extensions v3_req -subj "$SUBJECT"
    rm -f "$TMP_CFG"
  else
    openssl req -x509 -nodes -newkey rsa:4096 -days "$DAYS" \
      -keyout "$KEY" -out "$CRT" -subj "$SUBJECT"
  fi
  chmod 600 "$KEY" || true
fi

log "final cert directory listing:";
ls -l "$CERT_DIR" || true

# Do not start nginx here; this script runs under /docker-entrypoint.d
return 0 2>/dev/null || true