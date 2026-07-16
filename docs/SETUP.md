# trust — Setup & Operations Guide

How to build, configure, run, and use `trust`, the policy-enforcing egress
proxy. Covers a local-dev quickstart and production notes, including mTLS token
issuance, credential injection, authenticated passthrough, and HTTP CONNECT.

## What you're running

trust exposes up to five listeners:

| Port (default) | Listener | Purpose |
|---|---|---|
| `6191` | reverse proxy (plain HTTP) | optional development listener; avoid for JWT-bearing production traffic |
| `6443` | reverse proxy (TLS) | credential injection and authenticated passthrough |
| `6180` | CONNECT proxy (TLS by default) | authenticated tunnels to exact allowlisted `host:port` origins |
| `8443` | issuance (**mTLS**) | `POST /token` — OAuth2 `client_credentials`, mints scoped JWTs |
| `8080` | management (plain HTTP) | JWKS, `/healthz`, `/readyz`, and `/metrics` |

A client authenticates to the **issuance** endpoint with an mTLS client cert
(its SPIFFE identity), receives a short-lived scoped JWT, then uses that JWT on
the proxy. trust verifies the JWT and authorizes by scope. A reverse-proxy
upstream can inject a server-side credential or pass the caller's credential
through; a CONNECT upstream opens an opaque tunnel only to an exact configured
destination.

## Prerequisites

- Docker (to build/run the image).
- `openssl`, `curl`, `jq` (for the helper scripts).
- A GCP project + `gcloud`, with a service account that has
  `roles/secretmanager.secretAccessor` for the ES256 signing key and static
  secrets. Dynamic GitHub App credentials additionally require the App private
  key; Artifact Registry uses ADC/Workload Identity rather than a stored access
  token. There is no offline signing-key backend today, so local dev still
  points at a development GCP project.

## 1. Build the image

```bash
docker build -t trust:dev .
```

The multi-stage image compiles with the Rust toolchain and runs on
`debian:bookworm-slim` with CA certificates, OpenSSL, and `git`. The runtime
`git` binary is required by the implemented git smart-HTTP cache.

## 2. Secrets in GCP Secret Manager

Create the signing key and each upstream credential:

```bash
# ES256 signing key (used to sign + verify JWTs)
./scripts/gen-signing-key.sh signing-key.pem
gcloud secrets create trust-signing-key --data-file=signing-key.pem --project=$PROJECT

# an upstream credential, e.g. an Anthropic API key
printf '%s' "sk-ant-…" | gcloud secrets create anthropic-key --data-file=- --project=$PROJECT
```

Grant the runtime identity access: `roles/secretmanager.secretAccessor` on each
secret (or project-wide for dev).

## 3. TLS & mTLS material

**Local dev** — generate everything with one script:

```bash
SPIFFE_ID=spiffe://example/dev/local ./scripts/dev-certs.sh certs
# → certs/server.{crt,key}  (the [tls] server cert)
#   certs/client-ca.{crt,key} (the [issuance].client_ca_path)
#   certs/client.{crt,key}  (your caller cert, SAN URI:spiffe://example/dev/local)
```

**Production** — server certs come from your PKI/ACME; client certs are SPIFFE
SVIDs issued by SPIRE or your service mesh. trust only needs: a server cert/key
for `[tls]`, and the client CA bundle at `[issuance].client_ca_path` that signs
your callers' certs.

## 4. Configuration

trust reads a TOML file (`TRUST_CONFIG`, default `/etc/trust/config.toml` in the
image). It holds **no plaintext secrets** — only GCP references + the mTLS policy.

```toml
[listen]
tcp = "0.0.0.0:6191"

[tls]                                   # required; also the issuance server cert
addr = "0.0.0.0:6443"
cert_path = "/etc/trust/certs/server.crt"
key_path  = "/etc/trust/certs/server.key"

[forward_proxy]                         # optional CONNECT-only listener
addr = "0.0.0.0:6180"
tls = true                              # reuses the [tls] certificate/key
connect_timeout = "10s"
idle_timeout = "5m"
max_tunnel_duration = "1h"
max_concurrent_tunnels = 1024
allow_private_ips = false

[auth]
issuer   = "https://trust.local/"
audience = "trust-proxy"

[auth.signing]
algorithm = "ES256"
token_ttl = "7d"
key_secret_ref = "projects/PROJECT/secrets/trust-signing-key/versions/latest"
# previous_key_secret_ref = ".../versions/1"   # verify-only during rotation

[issuance]
mtls_addr      = "0.0.0.0:8443"
client_ca_path = "/etc/trust/certs/client-ca.crt"
jwks_addr      = "0.0.0.0:8080"

# Which SPIFFE identity may mint which scopes (exact, or trailing '*' prefix).
[[issuance.clients]]
spiffe = "spiffe://example/dev/local"
allowed_scopes = ["anthropic", "github:example-org/*", "public-api"]

[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "anthropic.proxy.internal"     # Host header routes here
origin = "https://api.anthropic.com"
secret_ref = "projects/PROJECT/secrets/anthropic-key/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }

# Straight-through reverse proxy and CONNECT destination. CONNECT is opaque,
# so it cannot use injection, resource extraction, or allowed_methods.
[[upstreams]]
name = "public-api"
kind = "api"
mode = "passthrough"
listen_host = "public.proxy.internal"
origin = "https://api.example.com"
allow_connect = true
```

Scope grammar: `anthropic` (whole upstream); `github:owner/repo` (exact repo);
`github:owner/*` (one wildcard segment — end prefix grants with `/*`). Injection
schemes: `raw` (verbatim), `bearer` (`Bearer <s>`), `basic` (`Basic base64(s)`).

## 5. Run

```bash
docker run --rm \
  -p 6191:6191 -p 6443:6443 -p 6180:6180 -p 8443:8443 -p 8080:8080 \
  -v "$PWD/config.toml:/etc/trust/config.toml:ro" \
  -v "$PWD/certs:/etc/trust/certs:ro" \
  -v "$HOME/.config/gcloud/application_default_credentials.json:/gcp/adc.json:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/gcp/adc.json \
  -e RUST_LOG=info \
  trust:dev
```

(Prod: use a service-account key or workload identity instead of the ADC file.)
trust blocks on the first signing-key load, then serves — if it exits at startup,
check GCP creds/IAM and that `[tls]` cert/key + `client_ca_path` exist.

## 6. Mint a JWT

```bash
JWT=$(./scripts/mint-jwt.sh "anthropic")
echo "$JWT"
```

Under the hood that's an mTLS `client_credentials` call; the requested scopes are
**capped** to what the caller's SPIFFE identity is allowed:

```bash
curl --cert certs/client.crt --key certs/client.key --cacert certs/server.crt \
  https://localhost:8443/token \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "scope=anthropic github:example-org/example-repo"
# → {"access_token":"<jwt>","token_type":"Bearer","expires_in":604800,"scope":"..."}
```

Responses: `401` no/invalid client cert, `403` identity not in policy,
`400 invalid_scope` requested beyond the allowed set.

## 7. Use the JWT

**API upstream** (route by Host; `--resolve` maps the listen_host to the proxy):

```bash
curl https://anthropic.proxy.internal:6443/v1/messages \
  --resolve anthropic.proxy.internal:6443:127.0.0.1 \
  --cacert certs/server.crt \
  -H "Authorization: Bearer $JWT" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-4-8","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}'
```

trust validates the JWT, authorizes `anthropic`, strips your `Authorization`,
injects the real `x-api-key`, and forwards. Your JWT never reaches the upstream;
the real key never reaches you.

**CONNECT forward proxy** (the JWT needs the `public-api` scope):

```bash
JWT=$(./scripts/mint-jwt.sh "public-api")
curl --proxy https://localhost:6180 \
  --proxy-cacert certs/server.crt \
  --proxy-header "Proxy-Authorization: Bearer $JWT" \
  https://api.example.com/resource
```

For clients limited to proxy URL authentication, use Basic username `jwt` and
the JWT as password: `HTTPS_PROXY=https://jwt:${JWT}@localhost:6180`. The
listener accepts CONNECT only, so plain HTTP sent through `HTTP_PROXY` receives
`405 Method Not Allowed`. Unknown destinations or ports receive `403`.

**git smart-HTTP cache:**

```bash
JWT=$(./scripts/mint-jwt.sh "github:example-org/example-repo")
git -c http.extraHeader="Authorization: Bearer $JWT" \
  clone https://github-git.proxy.internal/example-org/example-repo.git
```

## 8. Local-dev quickstart (end to end)

```bash
docker build -t trust:dev .
./scripts/dev-certs.sh certs
./scripts/gen-signing-key.sh signing-key.pem
gcloud secrets create trust-signing-key --data-file=signing-key.pem --project=$PROJECT
printf '%s' "sk-ant-…" | gcloud secrets create anthropic-key --data-file=- --project=$PROJECT
# write config.toml (section 4), then:
docker run --rm -p 6443:6443 -p 6180:6180 -p 8443:8443 -p 8080:8080 \
  -v "$PWD/config.toml:/etc/trust/config.toml:ro" -v "$PWD/certs:/etc/trust/certs:ro" \
  -v "$HOME/.config/gcloud/application_default_credentials.json:/gcp/adc.json:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/gcp/adc.json trust:dev &
JWT=$(./scripts/mint-jwt.sh "anthropic")
curl -sS https://anthropic.proxy.internal:6443/v1/models \
  --resolve anthropic.proxy.internal:6443:127.0.0.1 --cacert certs/server.crt \
  -H "Authorization: Bearer $JWT" -H "anthropic-version: 2023-06-01"
```

## 9. Production notes

- **Secrets/keys:** real GCP Secret Manager + workload identity (no key files).
  Rotate the signing key by adding a version and setting `previous_key_secret_ref`
  — trust serves current+previous in JWKS so live 7-day tokens survive.
- **mTLS identities:** issue client SVIDs via SPIRE / your mesh; map each
  `spiffe://…` (exact or `…/*` prefix) to the minimal scopes in
  `[[issuance.clients]]`. End prefix scopes with `/*` at a path boundary.
- **TLS:** terminate the reverse proxy at `[tls]` with real certs. The CONNECT
  listener reuses that certificate when `forward_proxy.tls = true`; include both
  proxy DNS names in its SANs. JWKS (`8080`) is safe to expose to verifiers, but
  `/metrics` may reveal operational metadata. The issuance endpoint (`8443`)
  must stay mTLS-only.
- **CONNECT:** only passthrough API upstreams with `allow_connect = true` are
  reachable, matched by exact origin `host:port`. Private, loopback, link-local,
  and other non-public targets are rejected unless explicitly enabled. Tunnels
  end at JWT expiry, idle timeout, maximum duration, or process shutdown.
- **Token TTL:** `token_ttl` (configured as 7d in this local example) trades
  revocation latency for fewer mints. Shorten it in production if you need
  tighter revocation.

## 10. Troubleshooting

| Symptom | Likely cause |
|---|---|
| container exits at startup | GCP creds/IAM, missing `[tls]` cert/key, or bad `client_ca_path` |
| `/token` → 401 | client cert missing/not signed by `client_ca_path`, or no SPIFFE SAN |
| `/token` → 403 | SPIFFE identity has no `[[issuance.clients]]` entry |
| `/token` → 400 invalid_scope | requested scope beyond the identity's `allowed_scopes` |
| proxy → 401 | missing/expired/invalid JWT |
| proxy → 403 | JWT scope doesn't cover this upstream/repo |
| proxy → 404 | `Host` header matches no upstream `listen_host` |
| proxy → 502 | upstream secret fetch failed (GCP) or upstream unreachable |
| CONNECT → 407 | missing, expired, or invalid `Proxy-Authorization` JWT |
| CONNECT → 403 | destination is not allowlisted or JWT scope does not cover it |
| CONNECT → 405 | client sent a non-CONNECT method (commonly plain `HTTP_PROXY` traffic) |
| CONNECT → 502 | DNS resolution, private-address policy, or target connection failed |
| CONNECT → 503 | signing keys unavailable or concurrent tunnel capacity exhausted |
