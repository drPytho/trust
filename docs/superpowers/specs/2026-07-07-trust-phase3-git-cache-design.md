# trust Phase 3 — git smart-HTTP cache (design)

Date: 2026-07-07
Status: Approved (design), pending implementation planning
Depends on: Phase 1 (egress proxy) + Phase 2 (JWT auth, scoped authz). Reuses the routing,
JWT verification, scope model, and secret-injection core unchanged.

## 1. Overview

Adds a new upstream `kind = "git-cache"` that turns trust into a caching git mirror for
clone/fetch while passing pushes through to the real upstream. It reuses the existing
per-host routing, JWT verification, repo-scoped authorization (Phase 2 `scope`/`permits`),
and GCP secret injection.

For each git-cache upstream, trust keeps a **bare mirror per repo** on local disk.

### Freshness model: fresh refs, cached objects

trust does **not** cache the ref advertisement; it caches **objects**. On every read
(clone/fetch), trust performs an **incremental `git fetch` from upstream into the mirror**
(single-flighted per repo). Because git fetch is incremental, all previously-seen objects are
already local — only newly-pushed objects transfer from upstream — and the ref advertisement
served to the client is always current. There is **no staleness TTL**. trust then serves
`upload-pack` from the freshly-synced mirror, so the bulk object transfer is served locally
while refs stay authoritative.

### Serving mechanism

trust shells out to the **`git` binary**: `git http-backend` (CGI) to serve the smart-HTTP
protocol to clients, and `git fetch` to sync the mirror. gitoxide's server-side upload-pack is
not production-ready, so the git binary is used for both halves (this matches goblet /
git-cache-http-server). The `git` binary is a runtime dependency.

## 2. Components

New and extended units (each independently testable):

| Component | Responsibility |
|---|---|
| `resource::extract` (extend) | New `ResourceKind::GitRepo`: parse `owner/repo` from git smart-HTTP URL paths (`/{owner}/{repo}.git/info/refs`, `/{owner}/{repo}/git-upload-pack`, `/{owner}/{repo}.git/git-receive-pack`, etc.). Distinct from the API `github-repo` extractor. Feeds the existing Phase-2 `ScopeSet::permits`. |
| `git::classify` | Classify an incoming git request from method + path + `service` query into `Read` (info/refs?service=git-upload-pack, POST git-upload-pack) / `Push` (info/refs?service=git-receive-pack, POST git-receive-pack) / `Other` (reject). |
| `git::MirrorStore` | Bare mirrors under a configured dir; `path_for(upstream, owner, repo)`; `ensure(repo, origin_url, cred)` creates the mirror on first use (`git clone --mirror`). |
| `git::SyncManager` | `sync(repo, origin_url, cred)` = incremental `git fetch` from upstream into the mirror, **single-flighted per repo key** (concurrent callers await one in-flight fetch). No TTL. |
| `git::Backend` | Run `git http-backend` against a mirror: build the CGI environment (`GIT_PROJECT_ROOT`, `PATH_INFO`, `QUERY_STRING`, `REQUEST_METHOD`, `CONTENT_TYPE`, `CONTENT_LENGTH`, `GIT_HTTP_EXPORT_ALL=1`, `REMOTE_USER`), feed the request body to stdin, parse the CGI response headers from stdout, and stream the remaining stdout as the HTTP response body. |
| `proxy` (extend) | For a `git-cache` upstream: classify the request; **Read** → short-circuit (ensure+sync mirror, then serve via `git::Backend`); **Push** → proxy to the real upstream (existing path), then post-push sync. `api` upstreams are unchanged. |
| `config` (extend) | `UpstreamKind::GitCache`; a `git = { storage_path = "..." }` per-upstream block (required for git-cache upstreams). |

## 3. Configuration

```toml
[[upstreams]]
name = "github"
kind = "git-cache"
listen_host = "github-git.proxy.internal"
origin = "https://github.com"
secret_ref = "projects/my-proj/secrets/github-git-token/versions/latest"
# GitHub git-over-HTTPS uses Basic "x-access-token:<pat>"; store the secret in that form.
injection = { header = "authorization", scheme = "basic" }
resource = { kind = "git-repo" }
git = { storage_path = "/var/lib/trust/mirrors" }
```

Validation additions: a `git-cache` upstream requires the `git` block (`storage_path`) and a
`resource = { kind = "git-repo" }`; an `api` upstream must not carry a `git` block. Storage is
unbounded for now (no eviction; a configured directory) — LRU/size-cap is a future addition.

## 4. Read flow (clone / fetch)

Handled inside the proxy for a `git-cache` upstream, after host-route → JWT verify →
repo-scoped authorize (via the `git-repo` extractor + `permits`) succeed:

1. `git::classify` → `Read`.
2. `MirrorStore.ensure(repo, origin, cred)` — first request clones `--mirror` from upstream
   using the injected git credential.
3. `SyncManager.sync(repo, origin, cred)` — single-flighted incremental `git fetch` (fresh
   refs, only new objects). The injected credential is used here, out-of-band from the client
   request (the client's JWT never reaches upstream).
4. `git::Backend` runs `git http-backend` against the mirror for this path + query; trust
   writes the CGI status/headers and **streams** the packfile body to the client.
   Short-circuit — the upstream is never proxied for reads.

Errors: unknown host → 404, missing/invalid JWT → 401, repo not in scope → 403, upstream
sync failure (unreachable / bad cred) → 502, git-backend failure → 500.

## 5. Push flow (receive-pack)

Pushes are not cacheable and are **proxied** to the real upstream via the existing Phase-1/2
path: `upstream_peer` → strip the client JWT → inject the git credential → forward. This
covers both `GET /info/refs?service=git-receive-pack` and `POST .../git-receive-pack`. Repo
scope authorization still applies. On a successful push response, trigger
`SyncManager.sync(repo, ...)` so the mirror reflects the new commits on the next read.

## 6. Streaming & concurrency

- **Streaming:** the git-backend response body (potentially large packfiles) is streamed from
  the subprocess stdout to the client rather than buffered. The request body (client
  negotiation for POST upload-pack) is streamed to the subprocess stdin. The exact Pingora
  mechanism for writing a response body from a filter is confirmed at planning time; the
  contract is: no full-body buffering of packfiles in memory.
- **Single-flight:** `SyncManager` dedupes concurrent syncs of the same repo (keyed by
  upstream+owner+repo) so a burst of clones triggers one upstream fetch, not N. Independent
  repos sync concurrently.
- **Mirror creation race:** `ensure` is idempotent and guarded so two first-time requests for
  the same repo don't clone twice.

## 7. Error handling & security

- The client JWT is verified and authorized before any mirror work; it is **never** forwarded
  upstream (reads don't proxy; pushes strip it and inject the real credential — Phase 1/2
  invariant preserved).
- The injected git credential is used only for upstream fetch/clone/push; it is never written
  to logs and never returned to the client.
- git subprocesses run with a fixed argument vector (no shell); repo owner/repo come from the
  parsed path and are used to build filesystem paths under `storage_path` — path components
  are validated (no `..`, no `/` within a component, no absolute paths) to prevent traversal
  outside the mirror root.
- Typed errors (`thiserror`) at each boundary; no panics in the request path.

## 8. Testing

- **Unit:** `git-repo` path extraction (info/refs, upload-pack, receive-pack, `.git` suffix,
  non-git paths → None); path-traversal rejection; `git::classify` (read vs push vs other);
  `MirrorStore.path_for`; `SyncManager` single-flight (concurrent `sync` of one repo against a
  local origin ⇒ a single fetch); `git::Backend` CGI env construction.
- **Integration:** create a **local bare repo as the upstream origin**, configure a git-cache
  upstream pointing at it, run the proxy, and drive the real `git` client through it with a
  valid scoped JWT:
  - `git clone` through the proxy succeeds and the working tree matches the origin.
  - Commit + push to the origin directly, then `git fetch` through the proxy sees the new
    commit (fresh refs, cached objects).
  - `git push` through the proxy reaches the origin (push passthrough) and the origin has the
    commit; the mirror is refreshed afterward.
  - Out-of-scope repo → 403; missing/invalid JWT → 401.

## 9. Scope

- **In scope:** the `git-cache` upstream kind — read (mirror serve) + push (passthrough),
  fresh-refs/cached-objects sync, single-flight, git-repo authz, config + validation.
- **Out of scope (future):** mirror eviction / size caps (unbounded for now); non-GitHub git
  host quirks beyond Basic-auth injection; protocol-v2-specific optimizations beyond what
  `git http-backend` provides.
