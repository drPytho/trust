#!/usr/bin/env sh
# Generate development-only TLS interception CA material.
#
# The root key stays in the output directory and must never be mounted into
# Trust or a workload. Trust receives only intermediate-chain.pem and
# intermediate.key; opted-in workloads receive only egress-root-ca.pem.
set -eu

output_dir=${1:-dev-egress-mitm-ca}

if [ -e "$output_dir" ]; then
  echo "refusing to overwrite existing path: $output_dir" >&2
  exit 1
fi

umask 077
mkdir -p "$output_dir/root" "$output_dir/intermediate"
tmp_ext=$(mktemp)
trap 'rm -f "$tmp_ext"' EXIT HUP INT TERM

openssl ecparam -name prime256v1 -genkey -noout \
  -out "$output_dir/root/egress-root-ca.key"
openssl req -x509 -new -sha256 -days 3650 \
  -key "$output_dir/root/egress-root-ca.key" \
  -out "$output_dir/root/egress-root-ca.crt" \
  -subj '/CN=Trust development sandbox egress root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'

openssl ecparam -name prime256v1 -genkey -noout \
  -out "$output_dir/intermediate/intermediate.key"
openssl req -new -sha256 \
  -key "$output_dir/intermediate/intermediate.key" \
  -out "$output_dir/intermediate/intermediate.csr" \
  -subj '/CN=Trust development sandbox egress intermediate'

printf '%s\n' \
  'basicConstraints=critical,CA:TRUE,pathlen:0' \
  'keyUsage=critical,keyCertSign,cRLSign' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid,issuer' >"$tmp_ext"
openssl x509 -req -sha256 -days 825 \
  -in "$output_dir/intermediate/intermediate.csr" \
  -CA "$output_dir/root/egress-root-ca.crt" \
  -CAkey "$output_dir/root/egress-root-ca.key" \
  -CAcreateserial \
  -extfile "$tmp_ext" \
  -out "$output_dir/intermediate/intermediate.crt"

# This is intentionally the intermediate only. Do not append the root: Trust
# serves leaf + intermediates, while the workload already trusts the root.
cp "$output_dir/intermediate/intermediate.crt" \
  "$output_dir/intermediate/intermediate-chain.pem"
cp "$output_dir/root/egress-root-ca.crt" "$output_dir/egress-root-ca.pem"
rm "$output_dir/intermediate/intermediate.csr" "$output_dir/root/egress-root-ca.srl"

cat <<EOF
Generated development egress MITM CA material in $output_dir

Trust-only signer Secret:
  $output_dir/intermediate/intermediate-chain.pem
  $output_dir/intermediate/intermediate.key

Opt-in workload public trust anchor:
  $output_dir/egress-root-ca.pem

Never mount or distribute:
  $output_dir/root/egress-root-ca.key
EOF
