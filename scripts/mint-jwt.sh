#!/usr/bin/env bash
# Mint a scoped JWT from trust's mTLS OAuth2 token endpoint.
#
#   ./scripts/mint-jwt.sh "anthropic github:pitorg/pit-ts"
#
# Env overrides:
#   TOKEN_URL  (default https://localhost:8443/token)
#   CERT_DIR   (default certs)   -- expects client.crt/client.key + server.crt
set -euo pipefail

SCOPE="${1:-}"
TOKEN_URL="${TOKEN_URL:-https://localhost:8443/token}"
CERT_DIR="${CERT_DIR:-certs}"

if [[ -z "$SCOPE" ]]; then
  echo "usage: $0 \"<space-separated scopes>\"   e.g. \"anthropic github:pitorg/*\"" >&2
  exit 2
fi

resp="$(curl -fsS \
  --cert   "$CERT_DIR/client.crt" \
  --key    "$CERT_DIR/client.key" \
  --cacert "$CERT_DIR/server.crt" \
  "$TOKEN_URL" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=$SCOPE")"

# Print just the token if jq is available, else the full JSON.
if command -v jq >/dev/null 2>&1; then
  echo "$resp" | jq -r '.access_token'
else
  echo "$resp"
fi
