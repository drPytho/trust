#!/usr/bin/env bash
# Generate local-dev TLS material for trust:
#   - server.crt/key      : the [tls] server cert (reverse proxy, CONNECT, and issuance)
#   - client-ca.crt/key   : the CA that signs client certs ([issuance].client_ca_path)
#   - client.crt/key      : a client cert with a SPIFFE URI SAN (the caller identity)
#
# The SPIFFE id defaults to spiffe://pit/dev/local — add a matching
# [[issuance.clients]] entry granting the scopes that identity may mint.
#
# NOT for production. In prod, server certs come from your PKI/ACME and client
# certs/SPIFFE SVIDs from SPIRE or your mesh.
set -euo pipefail

DIR="${1:-certs}"
SPIFFE="${SPIFFE_ID:-spiffe://pit/dev/local}"
mkdir -p "$DIR"
cd "$DIR"

ec() { openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "$@"; }

# --- server cert (self-signed; used for [tls] and as the issuance server cert) ---
ec -x509 -nodes -days 365 \
   -keyout server.key -out server.crt \
   -subj "/CN=localhost" \
   -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# --- client CA (self-signed) ---
ec -x509 -nodes -days 365 \
   -keyout client-ca.key -out client-ca.crt \
   -subj "/CN=trust-dev-client-ca"

# --- client cert with SPIFFE URI SAN, signed by the client CA ---
ec -nodes -keyout client.key -out client.csr -subj "/CN=dev-client"
openssl x509 -req -in client.csr \
   -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
   -out client.crt -days 365 \
   -extfile <(printf "subjectAltName=URI:%s" "$SPIFFE")
rm -f client.csr client-ca.srl

echo >&2
echo "Wrote to $DIR/: server.{crt,key} client-ca.{crt,key} client.{crt,key}" >&2
echo "Client SPIFFE identity: $SPIFFE" >&2
echo "Verify: openssl x509 -in $DIR/client.crt -noout -text | grep -A1 'Subject Alternative Name'" >&2
