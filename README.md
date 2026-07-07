# trust

A credential-injection egress proxy built on [Pingora](https://github.com/cloudflare/pingora).

Clients authenticate to `trust` with their **own** token. `trust` validates it, checks
the client is authorized for the requested upstream, fetches the **real** upstream secret
from a secret manager, injects it, and forwards the request. The upstream credential is
never handed to clients, and the client's own token is never forwarded upstream.

> **Status:** Phase 1 (API egress) is complete. Phase 2 (git smart-HTTP caching) is
> designed but not yet built — see [Roadmap](#roadmap).

## Why

You have shared upstream credentials (Anthropic, Mistral, GitHub API, …) that you don't
want to distribute to every client, script, or CI job. Instead:

- Each client gets a scoped **proxy token**, not the real key.
- The real key lives in a secret manager and is injected at the edge.
- Access is per-upstream: a token authorized for `anthropic` cannot reach `github`.
- Rotating an upstream key is a secret-manager change — clients are untouched.

## How it works

Each upstream owns a proxy **hostname**; the incoming `Host` header selects it.

```
                         ┌───────────────────────── trust ─────────────────────────┐
  client                 │                                                          │
  Authorization:  ─────▶ │  request_filter                                          │
  Bearer <proxy-token>   │   ├─ route by Host ......................... 404 if none │
                         │   ├─ validate proxy token (token map) ...... 401 if bad  │
                         │   ├─ authorize principal → upstream ........ 403 if not  │
                         │   └─ fetch upstream secret (cached) ........ 502 on error│
                         │  upstream_request_filter                                 │
                         │   ├─ strip client Authorization                          │
                         │   ├─ inject upstream secret (per scheme)                 │      Authorization:
                         │   └─ rewrite Host → real origin           ───────────────┼────▶ Bearer <real-key>
                         └──────────────────────────────────────────────────────────┘     api.anthropic.com
```

Reject responses (404/401/403/502) short-circuit inside the proxy; only authorized,
credential-injected requests ever reach an upstream.

## Features

- **Single Pingora `ProxyHttp` service** — TLS termination, connection pooling, graceful restart.
- **Per-upstream host routing** via the `Host` header.
- **Bearer client auth** against a static token map with per-upstream authorization.
- **GCP Secret Manager** backend behind a swappable `SecretProvider` trait, with an
  in-memory TTL cache (default 5 min).
- **Configurable injection** per upstream: header name + scheme (`bearer` / `basic` / `raw`).
- **Client token never leaks** — `Authorization` is stripped before forwarding; secrets are
  never logged (redacted `Debug`, no `Display`).

## Configuration

`trust` reads a TOML file (path from `TRUST_CONFIG`, default `./config.toml`). The file
holds **no plaintext secrets** — only secret-manager references and the client token map.

```toml
# Plain HTTP listener (use [tls] below for TLS termination).
[listen]
tcp = "0.0.0.0:6191"

# Optional TLS listener.
# [tls]
# addr = "0.0.0.0:6443"
# cert_path = "/etc/trust/server.crt"
# key_path  = "/etc/trust/server.key"

# Client proxy tokens → identity + which upstreams they may use.
[[tokens]]
token = "client-abc"          # what the client sends as: Authorization: Bearer client-abc
principal = "team-x"
allowed_upstreams = ["anthropic", "github-api"]

# Upstreams. Each owns a listen_host; the Host header routes to it.
[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "anthropic.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/my-proj/secrets/anthropic-key/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }

[[upstreams]]
name = "github-api"
kind = "api"
listen_host = "github.proxy.internal"
origin = "https://api.github.com"
secret_ref = "projects/my-proj/secrets/github-token/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
```

### Injection schemes

| Scheme   | Header value written               | Use for                                   |
|----------|------------------------------------|-------------------------------------------|
| `raw`    | `<secret>` verbatim                | API-key headers, e.g. `x-api-key`         |
| `bearer` | `Bearer <secret>`                  | OAuth/PAT bearer auth                      |
| `basic`  | `Basic base64(<secret>)`           | HTTP Basic (secret is the `user:pass` string) |

Config is validated at startup: duplicate upstream names / listen hosts, tokens referencing
unknown upstreams, and malformed origins are rejected before the server binds.

## Running

### Prerequisites

- Rust (edition 2024) toolchain.
- `cmake` — required by Pingora's `zlib-ng`. This repo pins it via [`mise`](https://mise.jdx.dev);
  `mise install` provides it, or install `cmake` yourself.
- GCP credentials via [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials):
  `gcloud auth application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, or workload
  identity on GCP. The identity needs `secretmanager.versions.access` on the referenced secrets.

### Build & run

```bash
cargo build --release

# Point clients at trust and set their proxy token; e.g. for the anthropic upstream:
#   Host: anthropic.proxy.internal
#   Authorization: Bearer client-abc
TRUST_CONFIG=./config.toml RUST_LOG=info cargo run --release
```

Clients resolve each `listen_host` to the proxy (DNS, `/etc/hosts`, or SNI for the TLS
listener) and send their proxy token as `Authorization: Bearer <token>`.

## Security model

- The client's `Authorization` header is **removed before** the upstream secret is injected —
  so even when injecting into `authorization`, the client token cannot leak upstream.
- Upstream secrets are fetched server-side, held only in memory with a TTL, and **never logged**
  (`Secret` has a redacted `Debug` and no `Display`).
- No request reaches an upstream without a valid, authorized proxy token.
- The config file contains no plaintext secrets — only secret-manager references. Keep your
  local `config.toml` out of version control (it is `.gitignore`d).

## Testing

```bash
cargo test                                 # 18 unit + 1 end-to-end integration test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`tests/api_egress.rs` spins the real Pingora service against a mock upstream and asserts the
end-to-end contract: unknown host → 404, missing/invalid token → 401, and on success the
upstream received the injected secret, with the client token stripped and the Host rewritten.

## Project layout

```
src/
  config.rs        # TOML load + validation, origin parsing
  auth.rs          # token map + Bearer extraction
  router.rs        # Host → upstream
  decision.rs      # route + auth + authz (404/401/403 / forward)
  inject.rs        # per-scheme secret injection
  secrets/
    mod.rs         # SecretProvider trait, redacted Secret, TTL cache
    gcp.rs         # GCP Secret Manager provider (lazy client)
    fake.rs        # in-memory provider for tests
  proxy.rs         # ProxyHttp: strip → inject → rewrite Host
  main.rs          # server bootstrap (TCP + TLS listeners)
tests/api_egress.rs
docs/superpowers/  # design spec + implementation plan
```

## Roadmap

**Phase 2 — git smart-HTTP caching.** Add a `git-cache` upstream kind alongside `api`: keep
local bare mirrors, serve `clone`/`fetch` from them (refreshing from upstream with injected
credentials when refs are stale), and pass pushes through to the real host. The auth /
routing / injection core is shared; the design is in
[`docs/superpowers/specs`](docs/superpowers/specs).
