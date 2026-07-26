# trust

A policy-enforcing egress proxy for sandboxed workloads, built on
[Pingora](https://github.com/cloudflare/pingora), Hyper, and Axum.

You have shared upstream credentials (Anthropic, Linear, GitHub, Artifact
Registry, …) that you don't want to hand to every client, script, CI job, or
AI agent. With `trust`:

- Each client is identified by the **SPIFFE URI** in its mTLS certificate.
- The client mints a **short-lived, scope-capped JWT** from the `/token`
  endpoint; the JWT never carries real upstream keys.
- The real credential lives in a secret manager and is **injected at the
  edge**; clients never see it, and the client's JWT never reaches upstreams.
- Access is per-upstream and per-repo: a token scoped to
  `github-cli:example-org/example-repo` cannot reach `anthropic` or any other
  repo.
- Rotating an upstream key is a secret-manager change — clients are untouched.

## How it works

```
 1. mint (mTLS)                      2. proxy (Bearer JWT)
 client ──POST /token──▶ trust       client ──▶ trust ─────────▶ upstream
   cert SAN = spiffe://…   :8443       :6443     │                api.anthropic.com
   scope=anthropic                               ├ route by Host        404
   ◀── scoped ES256 JWT ──┘                      ├ verify JWT           401
                                                 ├ authorize scope      403
                                                 ├ fetch real secret    502
                                                 ├ strip client auth
                                                 └ inject x-api-key ──▶ 200
```

Rejects short-circuit inside the proxy; only authorized requests ever reach an
upstream.

## Features

- **mTLS token issuance** — OAuth2 `client_credentials`; requested scopes are
  capped to the per-identity policy. ES256 keys live in GCP Secret Manager,
  rotate without restarts, and are published via JWKS.
- **Credential injection** per upstream (`bearer` / `basic` / `raw` header
  schemes) from a swappable secret backend with a TTL cache.
- **Dynamic credentials** — per-repository GitHub App installation tokens and
  Google ADC access tokens (e.g. Artifact Registry npm), minted and cached
  server-side.
- **Repo-scoped authorization** — `upstream:owner/repo` scopes with one-segment
  wildcards, enforced against the request path, including fail-closed `gh` CLI
  REST/GraphQL compatibility and scoped `gh pr create`.
- **git smart-HTTP cache** — clones/fetches served from a local bare mirror
  with always-fresh refs; pushes pass through to the origin.
- **HTTP(S) forward proxy** — authenticated absolute-form HTTP and CONNECT
  tunnels: opaque passthrough per exact destination, an opt-in audit fallback
  for unmatched public hosts, and selective per-host TLS interception with
  credential injection behind a dedicated CA hierarchy.
- **Method/path allowlists** per upstream, applied before credential
  resolution.
- **Kubernetes-ready** — liveness/readiness probes, Prometheus metrics,
  bounded-cardinality audit logging.

## Quick start

Prerequisites: Rust (edition 2024), `cmake` (pinned via
[`mise`](https://mise.jdx.dev): `mise install`), and GCP Application Default
Credentials with `secretmanager.versions.access` on the referenced secrets.

```bash
# 1. Dev certs (server cert, client CA, SPIFFE client cert) + signing key
./scripts/dev-certs.sh certs
./scripts/gen-signing-key.sh signing-key.pem
gcloud secrets create trust-signing-key --data-file=signing-key.pem --project=$PROJECT
printf '%s' "sk-ant-…" | gcloud secrets create anthropic-key --data-file=- --project=$PROJECT

# 2. Write config.toml (see docs/CONFIGURATION.md), then run
TRUST_CONFIG=./config.toml RUST_LOG=info cargo run --release

# 3. Mint a scoped JWT and call the API through the proxy
JWT=$(./scripts/mint-jwt.sh anthropic)
curl https://anthropic.proxy.internal:6443/v1/messages \
  --resolve anthropic.proxy.internal:6443:127.0.0.1 --cacert certs/server.crt \
  -H "Authorization: Bearer $JWT" -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-4-8","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}'
```

The proxy validates the JWT, strips it, injects the real `x-api-key`, and
forwards. See [docs/SETUP.md](docs/SETUP.md) for the Docker-based walkthrough.

## Listeners

| Port (default) | Listener | Purpose |
|---|---|---|
| `6191` | reverse proxy (plain HTTP) | development only |
| `6443` | reverse proxy (TLS) | credential injection + authenticated passthrough |
| `6180` | HTTP(S) forward proxy | absolute-form HTTP + authenticated CONNECT |
| `8443` | issuance (mTLS) | `POST /token` mints scoped JWTs |
| `8080` | management (plain HTTP) | JWKS, `/healthz`, `/readyz`, `/metrics` |

## Documentation

| Doc | Contents |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | build, certs, secrets, run, end-to-end quickstart |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | full config reference: upstreams, scopes, injection, GitHub App, npm |
| [docs/FORWARD_PROXY.md](docs/FORWARD_PROXY.md) | CONNECT tunnels, selective TLS interception, audit fallback |
| [docs/GITHUB.md](docs/GITHUB.md) | `gh` CLI support and git-cache behaviour |
| [docs/SECURITY.md](docs/SECURITY.md) | security model, invariants, known limitations |
| [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) | metrics, logging, troubleshooting |

Runnable examples: [examples/anthropic-js](examples/anthropic-js),
[examples/linear-js](examples/linear-js),
[examples/kubernetes](examples/kubernetes) (full sandbox-egress deployment).

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Integration tests spin up the real Pingora proxy: `tests/jwt_egress.rs`
(issuance policy, authz, injection, `gh` compatibility), `tests/git_cache.rs`
(clone/fetch/push against a real `git http-backend` origin),
`tests/gcp_workload_identity.rs`, and `tests/kubernetes_examples.rs`
(validates the example manifests).

## Project layout

```
src/
  main.rs          # bootstrap: proxy + issuance + forward proxy + key rotation
  config.rs        # TOML load + exhaustive startup validation
  proxy.rs         # Pingora ProxyHttp: route → verify → authorize → inject
  router.rs        # Host / CONNECT-authority → upstream
  decision.rs      # JWT verify + scope authz (404/401/403/forward)
  scope.rs         # scope grammar: parse, permits, covers, grant
  resource.rs      # path → owner/repo resource extraction
  jwt.rs           # ES256 issuer + verifier
  keystore.rs      # current+previous signing keys, JWKS
  credentials.rs   # static / GitHub App / GCP ADC credential resolution
  inject.rs        # per-scheme header injection
  connect.rs       # forward proxy: CONNECT tunnels, DNS policy
  github_cli.rs    # gh REST translation + bounded GraphQL validation
  metrics.rs       # Prometheus metrics
  issuance/        # mTLS /token server, SPIFFE policy, JWKS/health/metrics
  git/             # smart-HTTP cache: classify, mirror, single-flight sync, CGI
  mitm/            # selective TLS interception: CA, leaf cache, runtime
  secrets/         # SecretProvider trait, GCP backend, TTL cache, fake
```
