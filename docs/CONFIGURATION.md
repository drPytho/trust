# Configuration reference

`trust` reads a TOML file (path from `TRUST_CONFIG`, default `./config.toml`).
The file holds **no plaintext secrets** — only secret-manager references. It is
validated exhaustively at startup: duplicate upstream names/listen hosts,
malformed origins, ambiguous CONNECT authorities, zero tunnel capacity, and
invalid CONNECT mode combinations are rejected before the server binds.

## Secret Manager emulator

By default, Trust reads signing keys and upstream credentials from Google Secret
Manager using Application Default Credentials. To use a compatible local
emulator, set the standard endpoint variable:

```bash
SECRET_MANAGER_EMULATOR_HOST=http://127.0.0.1:4588
```

When this variable is set, Trust sends every Secret Manager request to that
endpoint with anonymous credentials. The value may also use the conventional
`host:port` form, which is interpreted as plain HTTP. Leaving it unset preserves
the production Google endpoint and ADC behavior.

## Listeners

```toml
# Plain HTTP reverse proxy (development only; avoid for JWT-bearing traffic).
[listen]
tcp = "0.0.0.0:6191"

# TLS reverse proxy. The cert/key are also used by the issuance server and,
# when forward_proxy.tls = true, by the forward proxy.
[tls]
addr = "0.0.0.0:6443"
cert_path = "/etc/trust/server.crt"
key_path  = "/etc/trust/server.key"

# Optional HTTP(S) forward proxy (absolute-form HTTP + HTTPS CONNECT).
# See docs/FORWARD_PROXY.md.
[forward_proxy]
addr = "0.0.0.0:6180"
tls = true
connect_timeout = "10s"
idle_timeout = "5m"
max_tunnel_duration = "1h"
max_concurrent_tunnels = 1024
allow_private_ips = false
# Opt-in audit fallback for otherwise-unmatched public destinations:
# audit_unmatched = { scope = "outbound-audit" }

# Optional online signer for intercept_connect routes. Mount an intermediate
# chain/key; never mount the root. See docs/FORWARD_PROXY.md.
[forward_proxy.mitm]
issuer_cert_chain_path = "/etc/trust/egress-mitm/intermediate-chain.pem"
issuer_key_path = "/etc/trust/egress-mitm/intermediate.key"
leaf_ttl = "24h"
refresh_before = "1h"
leaf_cache_capacity = 256
handshake_timeout = "10s"
```

## Auth and issuance

```toml
# Issuer/audience embedded in minted tokens and verified on every request.
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

# Per-identity issuance policy. spiffe may end with `*` for a prefix match.
[[issuance.clients]]
spiffe         = "spiffe://example/ci/example-repo"
allowed_scopes = ["github-cli:example-org/example-repo", "github-git:example-org/example-repo"]

[[issuance.clients]]
spiffe         = "spiffe://example/team/platform/*"
allowed_scopes = ["anthropic", "linear", "github-cli:example-org/*", "npm-artifacts:my-proj/npm-private"]
```

Signing keys are refreshed from Secret Manager every 10 minutes without a
restart; JWKS serves current + previous so live tokens survive rotation.

## Scope grammar

A scope is either a bare upstream name or a resource-scoped token. The prefix
is always the **configured upstream name**.

| Scope                   | Meaning                                        |
|-------------------------|------------------------------------------------|
| `anthropic`             | Full access to the `anthropic` upstream        |
| `github-cli:owner/repo` | Exact repo match on the `github-cli` upstream  |
| `github-cli:owner/*`    | All repos under `owner` (one wildcard segment) |

Rules:

- A bare upstream scope covers any resource under that upstream.
- A wildcard covers any exact repo under that owner but not a nested path.
- Only one-segment wildcards are supported — `*` must be the entire repo
  component; the parser rejects tokens with more than one `/`.
- End prefix grants with `/*` (segment boundary) to avoid unintended prefix
  leakage.

## GitHub App credentials

One GitHub App can have a different installation in each organization. Owner
matching is case-insensitive; requests for an unmapped owner fail closed.

```toml
[github_app]
app_id = 123456
private_key_secret_ref = "projects/my-proj/secrets/github-app-key/versions/latest"

[[github_app.installations]]
owner = "example-org"
installation_id = 111111

[[github_app.installations]]
owner = "customer-org"
installation_id = 222222
```

Installation tokens are minted restricted to the exact repository and
configured permissions, and cached until five minutes before expiry. A 401
from GitHub invalidates the cache entry so the next request re-mints.

## Upstreams

Each upstream owns a `listen_host`; the incoming `Host` header routes to it.
Unknown hosts are denied. The default `mode` is `"inject"`.

```toml
# Static secret injected from Secret Manager.
[[upstreams]]
name        = "anthropic"
kind        = "api"
listen_host = "anthropic.proxy.internal"
origin      = "https://api.anthropic.com"
secret_ref  = "projects/my-proj/secrets/anthropic-key/versions/latest"
injection   = { header = "x-api-key", scheme = "raw" }
# Standard HTTPS clients can also reach api.anthropic.com through HTTPS_PROXY
# with TLS interception; still requires the named `anthropic` scope.
intercept_connect = true

# Linear personal API keys go in `Authorization: <key>` without a Bearer
# prefix; use `scheme = "bearer"` for an OAuth access token instead.
[[upstreams]]
name            = "linear"
kind            = "api"
listen_host     = "linear.proxy.internal"
origin          = "https://api.linear.app"
secret_ref      = "projects/my-proj/secrets/linear-key/versions/latest"
injection       = { header = "authorization", scheme = "raw" }
allowed_methods = ["POST"]
allowed_paths   = ["/graphql"]

# Dynamic GitHub App installation token, with gh CLI compatibility.
# See docs/GITHUB.md.
[[upstreams]]
name        = "github-cli"
kind        = "api"
listen_host = "github-cli.proxy.internal"
origin      = "https://api.github.com"
credential  = { kind = "github-app", permissions = { contents = "read", pull_requests = "write", issues = "write", actions = "read", checks = "read", statuses = "read" } }
injection   = { header = "authorization", scheme = "bearer" }
resource    = { kind = "github-cli-repo" }

# npm via GCP Artifact Registry; trust obtains the token via ADC.
[[upstreams]]
name            = "npm-artifacts"
kind            = "api"
listen_host     = "npm.proxy.internal"
origin          = "https://europe-north1-npm.pkg.dev"
credential      = { kind = "gcp-adc", rewrite_registry_to = "https://npm.proxy.internal" }
injection       = { header = "authorization", scheme = "bearer" }
resource        = { kind = "artifact-registry-repo" }
allowed_methods = ["GET", "HEAD"]

# Explicit passthrough: no secret fetched or injected. The trust JWT goes in
# Proxy-Authorization; the caller's Authorization is forwarded unchanged.
# allow_connect additionally permits an opaque tunnel to api.example.com:443.
[[upstreams]]
name          = "public-api"
kind          = "api"
mode          = "passthrough"
listen_host   = "public.proxy.internal"
origin        = "https://api.example.com"
allow_connect = true

# git-cache upstream: bare mirror + pass-through push. Requires `git` in PATH.
# See docs/GITHUB.md.
[[upstreams]]
name        = "github-git"
kind        = "git-cache"
listen_host = "git.proxy.internal"
origin      = "https://github.com"
credential  = { kind = "github-app", permissions = { contents = "read" }, basic_username = "x-access-token" }
injection   = { header = "authorization", scheme = "basic" }
resource    = { kind = "git-repo" }
git         = { storage_path = "/var/lib/trust/mirrors" }
```

Notes:

- `secret_ref = "..."` is shorthand for
  `credential = { kind = "static-secret", secret_ref = "..." }`.
- `allowed_methods` and `allowed_paths` are independent allowlists applied
  before credential resolution. When either list is non-empty, a request must
  match it. Paths are matched exactly, without the query string.
- `allow_connect` is opaque passthrough only. `intercept_connect` requires an
  API inject upstream with an HTTPS, exact DNS origin and
  `[forward_proxy.mitm]`; it cannot be combined with `allow_connect`, an
  IP/wildcard origin, or a leaf cache too small to prewarm every host.

## Injection schemes

| Scheme   | Header value written     | Use for                                       |
|----------|--------------------------|-----------------------------------------------|
| `raw`    | `<secret>` verbatim      | API-key headers, e.g. `x-api-key`, Linear     |
| `bearer` | `Bearer <secret>`        | OAuth/PAT bearer auth                         |
| `basic`  | `Basic base64(<secret>)` | HTTP Basic (secret is the `user:pass` string) |

## npm client configuration

Workers need only non-secret routing configuration and their short-lived JWT;
the npm CLI expands the environment variable at runtime:

```ini
@company:registry=https://npm.proxy.internal/my-proj/npm-private/
//npm.proxy.internal/my-proj/npm-private/:_authToken=${TRUST_TOKEN}
always-auth=true
```

No `gcloud` CLI or `google-artifactregistry-auth` is required in the worker.
`rewrite_registry_to` rewrites absolute Artifact Registry tarball URLs and
redirects back through the proxy. Regenerate existing lockfiles against the
proxy (or test with `replace-registry-host=always`) so stored direct
`*.pkg.dev` URLs cannot bypass it. Publishing should use a separate upstream,
workload identity, and method policy with Artifact Registry Writer access.
