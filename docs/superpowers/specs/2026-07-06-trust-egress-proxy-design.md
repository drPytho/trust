# trust — egress credential-injection proxy (design)

Date: 2026-07-06
Status: Approved (design), pending implementation planning

## 1. Overview & architecture

`trust` is an egress credential-injection proxy built on **Pingora** (Cloudflare's Rust
proxy framework) as a single `ProxyHttp` service. Clients authenticate to the proxy with
their own token; the proxy authorizes them, resolves the real upstream secret from **GCP
Secret Manager**, injects it into the forwarded request, and proxies to the upstream.

Two upstream **handler types**:

- **`api`** — transparent forward + secret injection (e.g. Anthropic, Mistral, GitHub API).
  Built in **Phase 1**.
- **`git-cache`** — local bare-mirror serving for clone/fetch, push passthrough to upstream.
  Built in **Phase 2**.

Routing is **per-upstream hostname**: each configured upstream owns a proxy hostname, and
the incoming `Host` header selects the upstream config.

One design doc; two implementation plans (API egress first, git cache second).

### Why Pingora / approach A

The API-egress path is exactly what Pingora is built for: terminate the client connection,
manipulate headers, forward to an upstream with connection pooling and TLS. The git read
path is *not* a proxy operation (it generates responses locally from a mirror), so it
short-circuits inside `request_filter` rather than proxying. A single `ProxyHttp` service
handles both: native proxy for API + push passthrough, short-circuit for git reads.

Pingora's built-in HTTP cache is intentionally **not** relied on for git — git's smart
protocol transfers data over `POST /git-upload-pack` whose body carries per-client
negotiation, so responses are not cacheable as plain HTTP. Git caching is done at the
mirror level instead.

## 2. Components (shared core)

| Component | Responsibility | Depends on |
|---|---|---|
| `Config` | Load + validate TOML at startup: listeners/TLS, token map, upstreams. | — |
| `TokenMap` | `client_token -> Principal { id, allowed_upstreams }`. Static, from config. | Config |
| `ClientAuth` | Extract client token — **Bearer** for `api`, **Basic** for git — validate -> `Principal`. | TokenMap |
| `Router` | `Host` header -> `Upstream` config. | Config |
| `Authz` | Is this `Principal` allowed to use this `Upstream`? | — |
| `SecretProvider` (trait) | `get(secret_ref) -> Secret`, in-memory TTL cache + refresh. | GCP SDK |
| `Injector` | Apply an upstream's secret per its `injection` spec (header name + scheme). | SecretProvider |
| `ProxyService` | Pingora `ProxyHttp` implementation wiring the above together. | all |

### Upstream config shape

Each `Upstream` declares:

- `name` — identifier used in the token map's `allowed_upstreams`.
- `type` — `api` | `git-cache`.
- `listen_host` — the proxy hostname that routes to this upstream.
- `origin` — the real upstream base URL (e.g. `https://api.anthropic.com`).
- `secret_ref` — GCP Secret Manager resource name for the upstream credential.
- `injection` — how to apply the secret: header name + scheme (`bearer` | `basic` | `raw`).
- git-cache only: mirror cache settings (staleness TTL, storage path).

Secrets are **never** stored in the TOML — only GCP `secret_ref`s and the client token map.

### SecretProvider

Trait so the backend is swappable and testable:

- Concrete impl: **GCP Secret Manager** (fetch via GCP SDK, in-memory cache with TTL refresh).
- Test impl: in-memory fake returning fixture secrets.

## 3. Phase 1 data flow (API egress)

Pingora `ProxyHttp` lifecycle:

1. **`request_filter`**
   - Router resolves `Host` -> upstream config (**404** if none).
   - ClientAuth extracts + validates the **Bearer** client token (**401** if invalid).
   - Authz checks the `Principal` may use this upstream (**403** if not allowed).
   - **Strip the client's `Authorization` header** so the client token never leaks upstream.
2. **`upstream_peer`**
   - Return the upstream `origin` as the peer, with TLS/SNI for `https` origins and
     connection reuse via Pingora's connection pool.
3. **`upstream_request_filter`**
   - `SecretProvider.get(secret_ref)` -> `Injector` applies it per the upstream's spec
     (e.g. `x-api-key: <secret>` for Anthropic, `Authorization: Bearer <secret>` otherwise).
   - Set the `Host` header to the upstream.
4. Response streams straight back to the client. **No response caching for `api`.**

### Security invariants

- Client token is validated then discarded; it is never forwarded upstream.
- Upstream secret is fetched server-side, held only in memory with a TTL, and **never logged**.
- Config file contains no plaintext secrets.

## 4. Phase 2 outline (git smart cache)

Reuses the same auth / routing / injection core; adds a git handler. In `request_filter`,
classify the git request by path + service:

- **Read** (`GET /info/refs?service=git-upload-pack`, `POST /git-upload-pack`)
  -> **short-circuit**: ensure the local bare mirror is fresh (single-flight `git fetch`
  from upstream, using the injected secret, when refs are stale beyond TTL), then stream
  `git http-backend` / `git upload-pack` stdout as the response body.
- **Push** (`*receive-pack`) -> **passthrough** via the normal `upstream_peer` + injection
  path to the real host; on success, mark the mirror stale / trigger a refresh.

New components (detailed in Phase 2's own plan):

- `MirrorStore` — on-disk bare repositories, one per upstream repo.
- `GitBackend` — subprocess execution of git, streaming stdout as the HTTP response body.
- `SyncManager` — staleness TTL + single-flight fetch to avoid thundering-herd refreshes.

## 5. Testing & operational notes

- **Config format:** TOML.
- **TLS:** the proxy terminates TLS; cert/key supplied via config (per-hostname or wildcard
  covering the proxy hostnames).
- **Testing:**
  - Unit tests per component using the fake `SecretProvider` and in-memory config.
  - Integration test spinning the Pingora service against a mock upstream: assert the client
    token is stripped, the correct secret is injected per scheme, and authz (401/403/404) is
    enforced.
  - Phase 2 adds tests against a local bare repository (clone/fetch served from the mirror,
    staleness-triggered refresh, push passthrough).

## Build order

1. **Phase 1** — shared core (config, token map, client auth, router, authz,
   `SecretProvider` + GCP impl, injector) + `api` handler end-to-end.
2. **Phase 2** — `git-cache` handler (mirror store, git backend, sync manager).
