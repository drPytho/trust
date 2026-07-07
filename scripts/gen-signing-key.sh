#!/usr/bin/env bash
# Generate an ES256 (P-256) signing key for trust, in PKCS#8 PEM (what
# jsonwebtoken / p256 require). Upload the result to GCP Secret Manager and
# point [auth.signing].key_secret_ref at it.
set -euo pipefail

OUT="${1:-signing-key.pem}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# SEC1 EC key, then convert to unencrypted PKCS#8.
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp"
openssl pkcs8 -topk8 -nocrypt -in "$tmp" -out "$OUT"

echo "Wrote ES256 signing key (PKCS#8): $OUT" >&2
cat <<EOF >&2

Next: store it in GCP Secret Manager and reference it in config.toml:

  gcloud secrets create trust-signing-key --data-file="$OUT" --project=YOUR_PROJECT
  # then in [auth.signing]:
  #   key_secret_ref = "projects/YOUR_PROJECT/secrets/trust-signing-key/versions/latest"

To rotate: add a new version, and set previous_key_secret_ref to the old
version so in-flight tokens keep validating:

  gcloud secrets versions add trust-signing-key --data-file=new-key.pem --project=YOUR_PROJECT
EOF
