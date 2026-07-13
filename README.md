# trust

A credential-injection egress proxy built on [Pingora](https://github.com/cloudflare/pingora).

Clients authenticate to `trust` with a **short-lived JWT** they mint against their own mTLS identity.
`trust` validates the JWT, checks the client is authorized for the requested upstream, fetches the
**real** upstream secret from a secret manager, injects it, and forwards the request. The upstream
credential is never handed to clients, and the client's JWT is never forwarded upstream.

> **Status:** API proxying and git smart-HTTP caching are implemented. API credentials may be
> static Secret Manager values, repository-scoped GitHub App installation tokens, or Google ADC
> access tokens for services such as Artifact Registry.

## Why

You have shared upstream credentials (Anthropic, Mistral, GitHub API, …) that you don't
want to distribute to every client, script, or CI job. Instead:

- Each client is identified by its **SPIFFE URI** (in its mTLS certificate SAN).
- The client mints a **scoped JWT** from the `/token` endpoint; the JWT is short-lived and
  never carries real upstream keys.
- The real key lives in a secret manager and is injected at the edge.
- Access is per-upstream and per-repo: a token scoped to `github:pitorg/pit-ts` cannot
  reach `anthropic` or any other GitHub repo.
- Rotating an upstream key is a secret-manager change — clients are untouched.

## How it works

### Minting a token (mTLS OAuth2)

The issuance endpoint runs on a separate mTLS listener. The client presents its certificate
(containing a `spiffe://` URI SAN), and the server mints an ES256 JWT capped to the scopes
allowed for that identity in the `[[issuance.clients]]` policy.

```
  client (mTLS)          trust :8443
  POST /token            ──────────────────────────────────────────
  grant_type=client_credentials
  &scope=github:pitorg/pit-ts
                         1. verify client cert → extract SPIFFE URI
                         2. look up allowed scopes for that identity
                         3. cap requested scopes to allowed set
                         4. sign ES256 JWT (iss/aud/exp/sub/scope)
                         ──────────────────────────────────────────
                         {"access_token": "<jwt>", "token_type": "Bearer", ...}
```

JWKS (public keys for verification) is served at `/.well-known/jwks.json` on a plain HTTP
listener (`jwks_addr`). Key rotation (current + previous) is backed by GCP Secret Manager;
the server refreshes keys every 10 minutes without restarting.

The same listener exposes `/healthz` for liveness, `/readyz` for readiness, and `/metrics`
in Prometheus text format. Readiness requires the proxy lifecycle to be started and a signing
key to be loaded. The exported proxy metrics are:

- `trust_proxy_requests_total{upstream,status}`
- `trust_proxy_rejections_total{upstream,reason,status}`
- `trust_proxy_request_duration_seconds{upstream}`
- `trust_proxy_in_flight_requests`
- `trust_credential_resolutions_total{upstream,provider,result}`
- `trust_credential_resolution_duration_seconds{provider}`

Rejected proxy calls are also logged at `WARN` with bounded reasons (`missing_host`,
`unknown_host`, `missing_token`, `signing_keys_unavailable`, `invalid_token`, or
`forbidden_scope`) and safe request metadata. Credentials and authorization headers are never
logged.

### Proxying a request

Each upstream owns a proxy **hostname**; the incoming `Host` header selects it.

```
                         ┌───────────────────────── trust ─────────────────────────┐
  client                 │                                                          │
  Authorization:  ─────▶ │  request_filter                                          │
  Bearer <jwt>           │   ├─ route by Host ......................... 404 if none │
                         │   ├─ verify JWT (ES256, iss/aud/exp) ....... 401 if bad  │
                         │   ├─ authorize scope → upstream/resource ... 403 if not  │
                         │   └─ fetch upstream secret (cached) ........ 502 on error│
                         │  upstream_request_filter                                 │
                         │   ├─ strip client Authorization                          │
                         │   ├─ inject upstream secret (per scheme)                 │      Authorization:
                         │   └─ rewrite Host → real origin           ───────────────┼────▶ Bearer <real-key>
                         └──────────────────────────────────────────────────────────┘     api.anthropic.com
```

Reject responses (404/401/403/502) short-circuit inside the proxy; only authorized,
credential-injected requests ever reach an upstream.

## Scope grammar

A scope is either a bare upstream name or a resource-scoped token:

| Scope                  | Meaning                                                  |
|------------------------|----------------------------------------------------------|
| `anthropic`            | Full access to the `anthropic` upstream                  |
| `mistral`              | Full access to the `mistral` upstream                    |
| `github:owner/repo`    | Exact repo match on the `github` upstream                |
| `github:owner/*`       | All repos under `owner` (one wildcard segment)           |

Rules:
- A bare upstream scope (`anthropic`) covers any resource under that upstream.
- A wildcard (`github:owner/*`) covers any exact repo under that owner but not a nested path.
- Only one-segment wildcards are supported — `*` must be the entire repo component.
- Operators should end prefix grants with `/*` (segment boundary) to avoid unintended prefix
  leakage; the parser rejects tokens with more than one `/`.

## Features

- **JWT client auth** — clients send `Authorization: Bearer <jwt>`; `trust` verifies ES256,
  `iss`, `aud`, and `exp`.
- **mTLS token issuance** — OAuth2 `client_credentials` on a dedicated mTLS listener; client
  identity = SPIFFE URI SAN.
- **Scope-capped issuance** — requested scopes are intersected against the per-identity policy;
  uncovered scopes → 403.
- **Key rotation** — current + previous ES256 keys loaded from GCP Secret Manager, refreshed
  in the background every 10 minutes; JWKS served for external verification.
- **Single Pingora `ProxyHttp` service** — TLS termination, connection pooling, graceful restart.
- **Per-upstream host routing** via the `Host` header.
- **GCP Secret Manager** backend behind a swappable `SecretProvider` trait, with an
  in-memory TTL cache (default 5 min).
- **Dynamic GitHub App credentials** — selects an installation by repository owner, mints a token
  restricted to the exact repository and configured permissions, and caches it until five minutes
  before expiry.
- **Artifact Registry credentials via ADC** — obtains Google access tokens through Application
  Default Credentials/Workload Identity, without placing Google tokens in worker `.npmrc` files.
- **Configurable injection** per upstream: header name + scheme (`bearer` / `basic` / `raw`).
- **Repo-scoped authz** for `github-repo` upstreams — the request path is parsed for
  `owner/repo`; the JWT scope must cover it.
- **git-cache upstream** — serves `git clone`/`fetch` from a local bare mirror (fresh refs,
  cached objects; incremental `git fetch` per read, no TTL); passes `git push` through to
  the origin. Reuses JWT auth and repo-scoped authz (`git-repo` resource).
- **Client JWT never leaks** — `Authorization` is stripped before forwarding; secrets are
  never logged (redacted `Debug`, no `Display`).
- **Health and metrics** — the management listener exposes Kubernetes-compatible liveness and
  readiness probes plus Prometheus proxy metrics.

## Configuration

`trust` reads a TOML file (path from `TRUST_CONFIG`, default `./config.toml`). The file
holds **no plaintext secrets** — only secret-manager references.

```toml
# Plain HTTP listener (use [tls] below for TLS termination).
[listen]
tcp = "0.0.0.0:6191"

# TLS listener (required by the issuance server for its cert/key).
[tls]
addr = "0.0.0.0:6443"
cert_path = "/etc/trust/server.crt"
key_path  = "/etc/trust/server.key"

# JWT auth: issuer/audience embedded in minted tokens and verified on every request.
[auth]
issuer   = "https://trust.pit.internal/"
audience = "trust-proxy"

[auth.signing]
algorithm              = "ES256"
token_ttl              = "7d"
# GCP Secret Manager reference for the current signing key (P-256 PEM).
key_secret_ref          = "projects/my-proj/secrets/trust-signing-key/versions/latest"
# Optional: previous key (verify-only during rotation).
# previous_key_secret_ref = "projects/my-proj/secrets/trust-signing-key/versions/3"

# mTLS token-issuance server + plain JWKS/health/metrics management server.
[issuance]
mtls_addr       = "0.0.0.0:8443"
client_ca_path  = "/etc/trust/client-ca.pem"
jwks_addr       = "0.0.0.0:8080"

# Per-identity issuance policy.  spiffe may end with `*` for a prefix match.
[[issuance.clients]]
spiffe         = "spiffe://pit/ci/pit-ts"
allowed_scopes = ["github:pitorg/pit-ts"]

[[issuance.clients]]
spiffe         = "spiffe://pit/team/platform/*"
allowed_scopes = ["anthropic", "github:pitorg/*", "npm-artifacts:my-proj/npm-private"]

# One GitHub App can have a different installation in each organization. Owner matching is
# case-insensitive and requests for an unmapped owner fail closed.
[github_app]
app_id = 123456
private_key_secret_ref = "projects/my-proj/secrets/github-app-key/versions/latest"

[[github_app.installations]]
owner = "pitorg"
installation_id = 111111

[[github_app.installations]]
owner = "pit-customer"
installation_id = 222222

# Upstreams. Each owns a listen_host; the Host header routes to it.
[[upstreams]]
name        = "anthropic"
kind        = "api"
listen_host = "anthropic.proxy.internal"
origin      = "https://api.anthropic.com"
secret_ref  = "projects/my-proj/secrets/anthropic-key/versions/latest"
injection   = { header = "x-api-key", scheme = "raw" }

[[upstreams]]
name        = "github"
kind        = "api"
listen_host = "github.proxy.internal"
origin      = "https://api.github.com"
credential  = { kind = "github-app", permissions = { contents = "read", pull_requests = "read" } }
injection   = { header = "authorization", scheme = "bearer" }
resource    = { kind = "github-repo" }   # enables per-repo scope authz

# Read-only npm access through GCP Artifact Registry. The proxy obtains the upstream token via
# ADC; grant its workload identity Artifact Registry Reader on only this repository.
[[upstreams]]
name            = "npm-artifacts"
kind            = "api"
listen_host     = "npm.proxy.internal"
origin          = "https://europe-north1-npm.pkg.dev"
credential      = { kind = "gcp-adc", rewrite_registry_to = "https://npm.proxy.internal" }
injection       = { header = "authorization", scheme = "bearer" }
resource        = { kind = "artifact-registry-repo" }
allowed_methods = ["GET", "HEAD"]

# git-cache upstream: bare mirror + pass-through push.
# Requires `git` in PATH where trust runs.
[[upstreams]]
name        = "git-mirror"
kind        = "git-cache"
listen_host = "git.proxy.internal"
origin      = "https://github.com"
credential  = { kind = "github-app", permissions = { contents = "read" }, basic_username = "x-access-token" }
# GitHub receives `Authorization: Basic base64(x-access-token:<installation-token>)`.
injection   = { header = "authorization", scheme = "basic" }
resource    = { kind = "git-repo" }
git         = { storage_path = "/var/lib/trust/mirrors" }
```

Note: `[[tokens]]` (static token map from Phase 1) is **gone**. All client authentication
is now JWT-based via the issuance endpoint.

### Injection schemes

| Scheme   | Header value written               | Use for                                   |
|----------|------------------------------------|-------------------------------------------|
| `raw`    | `<secret>` verbatim                | API-key headers, e.g. `x-api-key`         |
| `bearer` | `Bearer <secret>`                  | OAuth/PAT bearer auth                      |
| `basic`  | `Basic base64(<secret>)`           | HTTP Basic (secret is the `user:pass` string) |

Config is validated at startup: duplicate upstream names/listen hosts and malformed origins
are rejected before the server binds. `secret_ref = "..."` remains supported as shorthand for
`credential = { kind = "static-secret", secret_ref = "..." }`.

### npm client configuration

Workers need only non-secret routing configuration and their short-lived `trust` JWT. The npm CLI
expands the environment variable at runtime:

```ini
@company:registry=https://npm.proxy.internal/my-proj/npm-private/
//npm.proxy.internal/my-proj/npm-private/:_authToken=${TRUST_TOKEN}
always-auth=true
```

No `gcloud` CLI or `google-artifactregistry-auth` invocation is required in the worker. The
`rewrite_registry_to` setting rewrites absolute Artifact Registry tarball URLs and redirects back
through the proxy. Existing lockfiles should still be regenerated against the proxy, or tested
with `replace-registry-host=always`, so previously stored direct `*.pkg.dev` URLs cannot bypass it.
Publishing should use a separate upstream, workload identity, and method policy with Artifact
Registry Writer access.

## Running

### Prerequisites

- Rust (edition 2024) toolchain.
- `cmake` — required by Pingora's `zlib-ng`. This repo pins it via [`mise`](https://mise.jdx.dev);
  `mise install` provides it, or install `cmake` yourself.
- GCP credentials via [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials):
  `gcloud auth application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, or workload
  identity on GCP. The identity needs `secretmanager.versions.access` on the referenced secrets.
- A CA certificate for client mTLS, and certificates for each client with a `spiffe://` URI SAN.

### Build & run

```bash
cargo build --release
TRUST_CONFIG=./config.toml RUST_LOG=info cargo run --release
```

### Minting a token (client side)

```bash
# Mint a JWT for a specific repo scope:
JWT=$(curl -s --cert client.crt --key client.key \
  --cacert server-ca.pem \
  https://trust.pit.internal:8443/token \
  -d "grant_type=client_credentials&scope=github:pitorg/pit-ts" \
  | jq -r .access_token)
```

### Using the token

```bash
# API call through the proxy:
curl -H "Authorization: Bearer $JWT" \
  -H "Host: anthropic.proxy.internal" \
  https://trust.pit.internal:6443/v1/messages

# git clone via the git-cache upstream (cached mirror, fresh refs):
git -c http.extraHeader="Authorization: Bearer $JWT" \
  clone https://git.proxy.internal/pitorg/pit-ts.git

# git push via the git-cache upstream (passed through to origin):
git -c http.extraHeader="Authorization: Bearer $JWT" \
  push https://git.proxy.internal/pitorg/pit-ts.git HEAD:main
```

### git-cache behaviour

- **Clone / fetch:** trust serves objects from a local bare mirror. On every read request, it
  runs `git fetch` to pull fresh refs and any new objects from the origin (no TTL — always
  up-to-date). Objects already in the mirror are served without hitting the origin.
- **Push:** classified as passthrough; trust injects the upstream PAT and forwards to the real
  origin. The mirror is refreshed on the next read.
- **Auth:** same JWT flow as `api` upstreams. The client's `Authorization` header is stripped;
  the upstream credential is injected via the configured injection scheme.
- **Requirement:** `git` must be installed where trust runs (`git http-backend` serves reads;
  `git fetch` syncs the mirror).

## Security model

- The client's `Authorization` header is **removed before** the upstream secret is injected —
  so even when injecting into `authorization`, the client JWT cannot leak upstream.
- Upstream secrets are fetched server-side, held only in memory with a TTL, and **never logged**
  (`Secret` has a redacted `Debug` and no `Display`).
- No request reaches an upstream without a valid, authorized JWT (verified ES256, `iss`, `aud`,
  `exp`, and scope).
- The issuance server is mTLS-only — unauthenticated clients cannot reach the `/token` endpoint.
- Scopes are capped at issuance to the per-identity policy; clients cannot self-escalate.
- The config file contains no plaintext secrets — only secret-manager references. Keep your
  local `config.toml` out of version control (it is `.gitignore`d).

## Testing

```bash
cargo test                                 # 102 unit + 3 end-to-end integration tests (105 total)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`tests/jwt_egress.rs` spins the real Pingora service against a mock upstream and asserts:
- issuance policy + grant decisions (scope coverage, capping, rejection)
- end-to-end proxy authz with JWT: unknown host → 404, missing/invalid JWT → 401,
  wrong scope → 403, and on success the upstream received the injected secret with the
  client JWT stripped and the Host rewritten.

`tests/git_cache.rs` spins a real `git http-backend` origin and the full Pingora proxy and asserts:
- clone through the git-cache upstream populates a local mirror and delivers objects
- incremental fetch updates the mirror after a new commit is pushed to origin
- push through the proxy lands on the origin (verified by direct clone from bare origin)
- unauthorized requests (bad JWT, wrong scope) are rejected before touching the mirror

## Project layout

```
src/
  config.rs        # TOML load + validation; [auth], [issuance], per-upstream resource
  scope.rs         # Scope/ScopeSet parse, permits, covers, grant
  resource.rs      # ResourceKind, path → Resource extraction
  router.rs        # Host → upstream
  decision.rs      # route + JWT verify + scope authz (404/401/403 / forward)
  inject.rs        # per-scheme secret injection
  jwt.rs           # ES256 Issuer + Verifier (jsonwebtoken)
  keystore.rs      # KeyMaterial, Keystore (current + previous), JWKS JSON
  secrets/
    mod.rs         # SecretProvider trait, redacted Secret, TTL cache
    gcp.rs         # GCP Secret Manager provider (lazy client)
    fake.rs        # in-memory provider for tests
  issuance/
    mod.rs
    mtls.rs        # SPIFFE URI SAN extraction from client certs
    policy.rs      # ClientPolicy: exact/prefix identity → ScopeSet
    server.rs      # mTLS /token endpoint + plain /.well-known/jwks.json
  git/
    mod.rs
    classify.rs    # classify HTTP path → GitRequest (Read / Push / Other)
    mirror.rs      # MirrorStore: bare-repo init, path validation, GitError
    sync.rs        # SyncManager: single-flight git fetch per repo
    backend.rs     # CGI env builder + cgi-head parser for git http-backend
  proxy.rs         # ProxyHttp: strip → inject → rewrite Host; git-cache serve/push
  main.rs          # server bootstrap (proxy + issuance + JWKS + key rotation)
tests/
  jwt_egress.rs    # JWT egress e2e
  git_cache.rs     # git-cache e2e (clone, incremental fetch, push, authz rejection)
```

## Roadmap

- **Metrics / observability** — Prometheus scrape endpoint; per-upstream latency and error counters.
- **Hot config reload** — SIGHUP reloads `config.toml` without dropping connections.
- **Mirror pre-warming** — optional background task to keep mirrors warm before any client request.
