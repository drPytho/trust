# trust

A policy-enforcing egress proxy built on [Pingora](https://github.com/cloudflare/pingora) and
Hyper.

Clients authenticate to `trust` with a **short-lived JWT** they mint against their own mTLS identity.
`trust` validates the JWT, checks the client is authorized for the requested upstream, fetches the
**real** upstream secret from a secret manager, injects it, and forwards the request. Explicit
destinations can instead pass caller credentials through or accept authenticated HTTP CONNECT
tunnels. The upstream credential is never handed to clients, and the client's JWT is never
forwarded upstream.

> **Status:** credential-injected API proxying, authenticated passthrough, HTTP CONNECT forwarding,
> and git smart-HTTP caching are implemented. API credentials may be static Secret Manager values,
> repository-scoped GitHub App installation tokens, or Google ADC access tokens for services such
> as Artifact Registry.

## Why

You have shared upstream credentials (Anthropic, Linear, Mistral, GitHub API, …) that you don't
want to distribute to every client, script, or CI job. Instead:

- Each client is identified by its **SPIFFE URI** (in its mTLS certificate SAN).
- The client mints a **scoped JWT** from the `/token` endpoint; the JWT is short-lived and
  never carries real upstream keys.
- The real key lives in a secret manager and is injected at the edge.
- Access is per-upstream and per-repo: a token scoped to `github:example-org/example-repo` cannot
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
  &scope=github:example-org/example-repo
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
- `trust_connect_attempts_total{upstream,result}`
- `trust_connect_active_tunnels{upstream}`
- `trust_connect_duration_seconds{upstream}`
- `trust_connect_bytes_total{upstream,direction}`

Rejected reverse-proxy and CONNECT calls are also logged at `WARN` with bounded reason labels and
safe request metadata. CONNECT distinguishes invalid authorities, unknown destinations, missing or
invalid tokens, forbidden scopes, private destinations, connection failures, and tunnel-capacity
exhaustion. Credentials and authorization headers are never logged.

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

Reject responses (404/401/403/502) short-circuit inside the proxy; only authorized requests ever
reach an upstream.

## Scope grammar

A scope is either a bare upstream name or a resource-scoped token:

| Scope                  | Meaning                                                  |
|------------------------|----------------------------------------------------------|
| `anthropic`            | Full access to the `anthropic` upstream                  |
| `linear`               | Full access to the `linear` GraphQL upstream             |
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

- **JWT client auth** — clients send `Authorization: Bearer <jwt>` for injected upstreams or
  `Proxy-Authorization: Bearer <jwt>` when their own `Authorization` must pass through; `trust`
  verifies ES256, `iss`, `aud`, and `exp`.
- **mTLS token issuance** — OAuth2 `client_credentials` on a dedicated mTLS listener; client
  identity = SPIFFE URI SAN.
- **Scope-capped issuance** — requested scopes are intersected against the per-identity policy;
  uncovered scopes → 403.
- **Key rotation** — current + previous ES256 keys loaded from GCP Secret Manager, refreshed
  in the background every 10 minutes; JWKS served for external verification.
- **Pingora reverse proxy plus optional Hyper CONNECT listener** — both reuse the same upstream
  configuration, JWT verifier, signing keys, scopes, metrics registry, and process lifecycle.
- **Per-upstream host routing** via the `Host` header.
- **GCP Secret Manager** backend behind a swappable `SecretProvider` trait, with an
  in-memory TTL cache (default 5 min).
- **Dynamic GitHub App credentials** — selects an installation by repository owner, mints a token
  restricted to the exact repository and configured permissions, and caches it until five minutes
  before expiry.
- **Artifact Registry credentials via ADC** — obtains Google access tokens through Application
  Default Credentials/Workload Identity, without placing Google tokens in worker `.npmrc` files.
- **Configurable injection** per upstream: header name + scheme (`bearer` / `basic` / `raw`).
- **Authenticated passthrough** — explicitly allowlisted hosts can proxy without credential
  injection while retaining scoped JWT authorization and preserving the caller's headers.
- **Authenticated CONNECT forwarding** — an optional forward-proxy listener supports standard
  `HTTPS_PROXY` clients. Only explicitly enabled `host:port` destinations are reachable, and every
  tunnel requires a scoped JWT.
- **Repo-scoped authz** for `github-repo` upstreams — the request path is parsed for
  `owner/repo`; the JWT scope must cover it. `github-cli-repo` additionally supports the
  GitHub Enterprise-style REST and repository-rooted GraphQL requests emitted by `gh`.
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

# Optional HTTP CONNECT forward proxy. TLS protects the JWT on the client-to-proxy hop.
# The [tls] certificate/key above are reused and must cover this listener's DNS name.
[forward_proxy]
addr = "0.0.0.0:6180"
tls = true
connect_timeout = "10s"
idle_timeout = "5m"
max_tunnel_duration = "1h"
max_concurrent_tunnels = 1024
allow_private_ips = false
# Temporary discovery mode for otherwise-unmatched CONNECT destinations:
# audit_unmatched = { scope = "outbound-audit" }

# JWT auth: issuer/audience embedded in minted tokens and verified on every request.
[auth]
issuer   = "https://trust.example.internal/"
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
spiffe         = "spiffe://example/ci/example-repo"
allowed_scopes = ["github:example-org/example-repo", "github-git:example-org/example-repo"]

[[issuance.clients]]
spiffe         = "spiffe://example/team/platform/*"
allowed_scopes = ["anthropic", "linear", "github:example-org/*", "npm-artifacts:my-proj/npm-private"]

# One GitHub App can have a different installation in each organization. Owner matching is
# case-insensitive and requests for an unmapped owner fail closed.
[github_app]
app_id = 123456
private_key_secret_ref = "projects/my-proj/secrets/github-app-key/versions/latest"

[[github_app.installations]]
owner = "example-org"
installation_id = 111111

[[github_app.installations]]
owner = "customer-org"
installation_id = 222222

# Upstreams. Each owns a listen_host; the Host header routes to it.
# Unknown hosts are denied. The default mode is "inject" for backward compatibility.
[[upstreams]]
name        = "anthropic"
kind        = "api"
listen_host = "anthropic.proxy.internal"
origin      = "https://api.anthropic.com"
secret_ref  = "projects/my-proj/secrets/anthropic-key/versions/latest"
injection   = { header = "x-api-key", scheme = "raw" }

# Linear's GraphQL API accepts personal API keys as `Authorization: <key>`
# (without a Bearer prefix). If the stored secret is an OAuth access token,
# use `scheme = "bearer"` instead.
[[upstreams]]
name            = "linear"
kind            = "api"
listen_host     = "linear.proxy.internal"
origin          = "https://api.linear.app"
secret_ref      = "projects/my-proj/secrets/linear-key/versions/latest"
injection       = { header = "authorization", scheme = "raw" }
allowed_methods = ["POST"]

[[upstreams]]
name        = "github"
kind        = "api"
listen_host = "github.proxy.internal"
origin      = "https://api.github.com"
credential  = { kind = "github-app", permissions = { contents = "read", pull_requests = "read", issues = "read" } }
injection   = { header = "authorization", scheme = "bearer" }
resource    = { kind = "github-cli-repo" } # native REST plus fail-closed gh CLI compatibility

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

# Explicitly allowlisted passthrough. No secret is fetched or injected. Clients must put their
# trust JWT in Proxy-Authorization; their normal Authorization header is forwarded unchanged.
# allow_connect additionally permits an opaque tunnel to exactly api.example.com:443.
[[upstreams]]
name          = "public-api"
kind          = "api"
mode          = "passthrough"
listen_host   = "public.proxy.internal"
origin        = "https://api.example.com"
allow_connect = true

# git-cache upstream: bare mirror + pass-through push.
# Requires `git` in PATH where trust runs.
[[upstreams]]
name        = "github-git"
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
| `raw`    | `<secret>` verbatim                | API-key headers, e.g. `x-api-key` or Linear personal keys |
| `bearer` | `Bearer <secret>`                  | OAuth/PAT bearer auth                      |
| `basic`  | `Basic base64(<secret>)`           | HTTP Basic (secret is the `user:pass` string) |

Config is validated at startup: duplicate upstream names/listen hosts, malformed origins, ambiguous
CONNECT authorities, zero tunnel capacity, and CONNECT on injection/resource/method-restricted
upstreams are rejected before the server binds. `secret_ref = "..."` remains supported as
shorthand for `credential = { kind = "static-secret", secret_ref = "..." }`.

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

### Using the CONNECT forward proxy

CONNECT is for clients that expect a conventional forward proxy, especially HTTPS clients. The
request target must exactly match the configured upstream origin's `host:port`, the upstream must
use `mode = "passthrough"` and `allow_connect = true`, and the JWT must include that upstream's
scope. Unknown destinations are denied. Because the tunneled TLS is opaque to `trust`, CONNECT
cannot inject credentials or enforce HTTP paths or methods; use the reverse-proxy host for those
policies.

Clients that can set proxy headers directly should use Bearer authentication:

```bash
curl --proxy https://trust.example.internal:6180 \
  --proxy-cacert server-ca.pem \
  --proxy-header "Proxy-Authorization: Bearer $JWT" \
  https://api.example.com/resource
```

For tools that only understand proxy URL credentials, `trust` also accepts HTTP Basic with the
fixed username `jwt` and the JWT as its password:

```bash
export HTTPS_PROXY="https://jwt:${JWT}@trust.example.internal:6180"
export NO_PROXY="trust.example.internal,.proxy.internal"
```

The `https://` proxy scheme means TLS is used between the client and `trust`; client support varies.
Setting `tls = false` and using `http://` is more widely compatible, but exposes the JWT to anyone
who can observe that network hop. Keep the listener private if plaintext is unavoidable. Avoid
putting long-lived secrets in proxy URLs; these JWTs should be short-lived and scoped.

The forward listener accepts CONNECT only. It works for `HTTPS_PROXY` clients that tunnel HTTPS,
but it is not a general absolute-form HTTP proxy: a client using `HTTP_PROXY` for plain HTTP will
receive `405 Method Not Allowed`. Route plain HTTP through an explicit reverse-proxy upstream or add
absolute-form forwarding as a separate, policy-aware feature.

The proxy resolves DNS server-side and rejects loopback, link-local, private, unique-local,
multicast, documentation, and carrier-grade NAT addresses by default. Set `allow_private_ips =
true` only when explicitly configured internal upstreams are required. Tunnels end at JWT expiry,
the idle timeout, or `max_tunnel_duration`, whichever comes first.

#### Auditing unmatched outbound destinations

During migration, the CONNECT listener can temporarily allow otherwise-unmatched destinations
while inventorying them. This is opt-in and still requires a valid JWT with a dedicated bare scope:

```toml
[forward_proxy]
addr = "0.0.0.0:6180"
tls = true
allow_private_ips = false
audit_unmatched = { scope = "outbound-audit" }

[[issuance.clients]]
spiffe = "spiffe://example/sandboxes/*"
allowed_scopes = ["outbound-audit"]
```

For an unknown CONNECT authority, trust logs the requested hostname and port at `WARN`, verifies
the JWT and `outbound-audit` scope, applies the normal DNS/private-IP checks and tunnel limits, and
then records the result under
`trust_connect_attempts_total{upstream="audit-unmatched",result="..."}`. Successful tunnels also
use `audit-unmatched` in the active, duration, and byte metrics. Destination names are kept in logs
rather than Prometheus labels to avoid unbounded metric cardinality. Authorization headers and
tokens are never logged.

Exact configured CONNECT destinations always take precedence and continue to require their named
upstream scopes. Give a sandbox its intended named scopes plus `outbound-audit` during discovery,
then convert observed destinations into explicit passthrough upstreams and remove the audit scope
and setting to return to deny-by-default behavior. The audit fallback does not apply to reverse
proxy hosts, private destinations when `allow_private_ips = false`, or plain HTTP requests sent via
`HTTP_PROXY`; the forward listener remains CONNECT-only.

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
  https://trust.example.internal:8443/token \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=github:example-org/example-repo github-git:example-org/example-repo" \
  | jq -r .access_token)
```

### Using the token

```bash
# API call through the proxy:
curl -H "Authorization: Bearer $ANTHROPIC_JWT" \
  -H "Host: anthropic.proxy.internal" \
  https://trust.example.internal:6443/v1/messages

# Linear GraphQL call. The proxy replaces the trust JWT with the stored Linear key.
curl -X POST -H "Authorization: Bearer $LINEAR_JWT" \
  -H "Content-Type: application/json" \
  -H "Host: linear.proxy.internal" \
  --data '{"query":"{ viewer { id name } }"}' \
  https://trust.example.internal:6443/graphql

# With @linear/sdk, set `accessToken` to the trust JWT and `apiUrl` to the
# complete proxy endpoint (`https://linear.proxy.internal/graphql`).
# See examples/linear-js for a runnable configuration and query.

# Authenticated passthrough. The trust JWT is consumed by the proxy while the caller's
# upstream credential is forwarded in Authorization without modification:
curl -H "Proxy-Authorization: Bearer $JWT" \
  -H "Authorization: Bearer $CALLER_UPSTREAM_TOKEN" \
  -H "Host: public.proxy.internal" \
  https://trust.example.internal:6443/resource

# git clone via the git-cache upstream (cached mirror, fresh refs):
git -c http.extraHeader="Authorization: Bearer $JWT" \
  clone https://git.proxy.internal/example-org/example-repo.git

# git push via the git-cache upstream (passed through to origin):
git -c http.extraHeader="Authorization: Bearer $JWT" \
  push https://git.proxy.internal/example-org/example-repo.git HEAD:main
```

### GitHub CLI without CONNECT

Configure the GitHub API upstream with `resource = { kind = "github-cli-repo" }`, then point
`gh` at its reverse-proxy hostname. Because `gh` treats a custom host as GitHub Enterprise,
trust rewrites `/api/v3/...` to GitHub.com's REST paths and `/api/graphql` to `/graphql`. The
value in `GH_ENTERPRISE_TOKEN` is the trust JWT, not a GitHub token:

```bash
export GH_HOST=github.proxy.internal
export GH_ENTERPRISE_TOKEN="$JWT"
export GH_REPO=github.proxy.internal/example-org/example-repo
# Or install the internal CA in the sandbox's system trust store.
export SSL_CERT_FILE=/var/run/trust/server/ca.crt

gh repo view "$GH_REPO"
gh pr list --repo "$GH_REPO"
gh issue list --repo "$GH_REPO"
gh api repos/example-org/example-repo/pulls
```

The CLI sends `Authorization: token <JWT>`; that scheme is accepted only by the explicit
`github-cli-repo` mode. trust validates the JWT, derives the exact repository, mints/caches an
installation token restricted to that repository, replaces the client header, and forwards the
request. REST calls must use `/repos/{owner}/{repo}/...`. GraphQL is limited to named query
operations whose root fields all select the same repository through variables. Mutations, global
queries, node lookups, search, multiple operations, and bodies over 64 KiB fail closed. This
supports the read paths used by `gh repo view`, `gh repo clone`, `gh pr list/view/checks/checkout`,
and `gh issue list/view`; account-level commands and write operations are not supported.

`gh repo clone` and `gh pr checkout` invoke `git` after their API query. Route that child process
to the separate git-cache reverse-proxy hostname and give the JWT both the `github:owner/repo` and
`github-git:owner/repo` scopes:

```bash
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=url.https://git.proxy.internal/.insteadOf
export GIT_CONFIG_VALUE_0=https://github.proxy.internal/
export GIT_CONFIG_KEY_1=http.https://git.proxy.internal/.extraHeader
export GIT_CONFIG_VALUE_1="Authorization: Bearer $JWT"
export GIT_SSL_CAINFO=/var/run/trust/server/ca.crt

gh repo clone example-org/example-repo
```

These inherited Git settings avoid CONNECT and ensure the git subprocess also stays behind trust.

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

- `Proxy-Authorization` is always removed before forwarding. In inject mode, the client's
  `Authorization` is also removed before the upstream secret is injected. In passthrough mode,
  the caller's `Authorization` is preserved and the trust JWT is accepted only from
  `Proxy-Authorization`.
- Upstream secrets are fetched server-side, held only in memory with a TTL, and **never logged**
  (`Secret` has a redacted `Debug` and no `Display`).
- No request reaches an upstream without a valid, authorized JWT (verified ES256, `iss`, `aud`,
  `exp`, and scope).
- Unknown hosts are denied, and passthrough must be enabled explicitly per configured upstream.
- CONNECT destinations are denied unless their exact origin `host:port` has `allow_connect = true`.
  CONNECT reuses the same JWT verifier, scope names, upstream allowlist, logs, and metrics as the
  reverse proxy, but cannot inspect or inject into the encrypted tunnel.
- The issuance server is mTLS-only — unauthenticated clients cannot reach the `/token` endpoint.
- Scopes are capped at issuance to the per-identity policy; clients cannot self-escalate.
- The config file contains no plaintext secrets — only secret-manager references. Keep your
  local `config.toml` out of version control (it is `.gitignore`d).

## Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`tests/jwt_egress.rs` spins the real Pingora service against a mock upstream and asserts:
- issuance policy + grant decisions (scope coverage, capping, rejection)
- end-to-end proxy authz with JWT: unknown host → 404, missing/invalid JWT → 401,
  wrong scope → 403, and on success the upstream received the injected secret with the
  client JWT stripped and the Host rewritten.
- GitHub CLI REST rewriting, `token`-scheme JWT auth, bounded GraphQL body replay,
  repository scope enforcement, credential replacement, and global-query rejection.

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
  github_cli.rs    # gh REST translation + repository-rooted GraphQL validation
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
