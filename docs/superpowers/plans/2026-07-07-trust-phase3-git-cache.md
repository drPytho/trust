# trust Phase 3 — git smart-HTTP cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a `git-cache` upstream kind that serves `git clone`/`fetch` from local bare mirrors (fresh refs, cached objects) and passes `git push` through to the real upstream, reusing the Phase 1/2 routing + JWT + scoped-authz + secret-injection core.

**Architecture:** In `ProxyService::request_filter`, after the existing host-route → JWT-verify → repo-scoped-authorize prelude, a `git-cache` upstream branches: reads short-circuit (ensure+sync bare mirror, run `git http-backend`, stream stdout to client); pushes fall through to the normal proxy path (JWT stripped, credential injected) with a post-push background sync. Serving/sync use the `git` binary.

**Tech Stack:** Rust 2024, Pingora 0.8 (streaming responses from a filter), `tokio::process`, the `git` binary (runtime dep), plus the existing Phase 1/2 stack.

**Design spec:** `docs/superpowers/specs/2026-07-07-trust-phase3-git-cache-design.md` (read for full narrative).

## Global Constraints

- Rust edition 2024. Branch `filip/git-cache` (based on `filip/egress-proxy` = Phase 1+2).
- The `git` binary is a runtime dependency (serve via `git http-backend`, sync via `git fetch`).
- **Fresh refs, cached objects:** incremental `git fetch` per read, single-flighted per repo, no TTL.
- Client JWT is verified+authorized, **never forwarded upstream**; the git credential is injected only on upstream fetch/clone/push and **never logged**.
- git subprocesses use a fixed argv (no shell); `owner`/`repo` path components are validated (reject `..`, empty, embedded `/`, absolute) before building filesystem paths under `storage_path`.
- Reuse, do not reinvent: `decision::authorize`/`scope::permits`/`resource::extract` (authz), `secrets::SecretProvider`/`Secret::expose` (credential), Phase-2 `jwt::Issuer`+`keystore::build_key_material` (test JWTs).
- Typed errors (`thiserror`); no panics in the request path.
- TDD: failing test → run (fail) → implement → run (pass) → commit. clippy `-D warnings` + fmt clean by the end.

### Confirmed Pingora 0.8 streaming API (serve path, Task 8)
```rust
let mut resp = pingora::http::ResponseHeader::build(status_u16, Some(4))?; // omit Content-Length
for (k, v) in cgi_headers { resp.insert_header(k, v)?; }
session.write_response_header(Box::new(resp), false).await?;
while let Some(chunk) = /* backend stdout */ { session.write_response_body(Some(chunk), false).await?; }
session.write_response_body(None, true).await?;
return Ok(true);
```
Request body (POST negotiation): `session.read_request_body().await? -> Option<Bytes>` → subprocess stdin.

---

### Task 1: Config — `git-cache` kind + git block

**Files:** Modify `src/config.rs`.

**Interfaces produced:** `UpstreamKind::GitCache` (serde `"git-cache"`); `pub struct GitConfig { pub storage_path: String }`; `Upstream.git: Option<GitConfig>` (+ `RawUpstream.git` with `#[serde(default)]`); `ConfigError::{MissingGitBlock, UnexpectedGitBlock, GitCacheNeedsGitRepoResource}` (names your choice; one variant each).

- [ ] Step 1 — failing tests: extend the config test module: (a) a `git-cache` upstream with `git = { storage_path = "/m" }` + `resource = { kind = "git-repo" }` parses, `kind`=GitCache, `git` Some; (b) `git-cache` without a `git` block → Err(MissingGitBlock); (c) `git-cache` without `resource` (or non-git-repo resource) → Err; (d) an `api` upstream WITH a `git` block → Err(UnexpectedGitBlock).
- [ ] Step 2 — `cargo test config::` fails.
- [ ] Step 3 — implement: add the enum variant, `GitConfig`, the fields, and validation in `from_str` (after the existing dup-name/host + origin checks). Note: Task 2 adds `ResourceKind::GitRepo`; this task may reference it — if Task 2 isn't merged yet, gate the resource-kind check so it compiles (or do Task 2 first). Keep `Config` `#[derive(Clone)]`.
- [ ] Step 4 — `cargo test config::` passes.
- [ ] Step 5 — commit `feat(config): git-cache upstream kind + git storage block`.

---

### Task 2: Resource extractor — `git-repo`

**Files:** Modify `src/resource.rs`.

**Interfaces produced:** `ResourceKind::GitRepo` (serde `"git-repo"`); `extract(GitRepo, path)` returns `Some(Resource{owner,repo})` for git smart-HTTP paths, else `None`.

**Behavior:** parse the FIRST two path segments as `owner`/`repo` when the path ends in a git smart-HTTP suffix (`/info/refs`, `/git-upload-pack`, `/git-receive-pack`), stripping a trailing `.git` from `repo`. **Reject** any segment that is empty, `.`, `..`, or contains no content → `None` (path-traversal safety). Non-git paths → `None`.

- [ ] Step 1 — failing tests: `/pitorg/pit-ts.git/info/refs` → owner=pitorg repo=pit-ts; `/pitorg/pit-ts/git-upload-pack` → same; `/o/r.git/git-receive-pack` → o/r; `/repos/x/y` (API-style, not git) → None; `/../etc/info/refs` → None; `/pitorg/info/refs` (missing repo) → None.
- [ ] Step 2 — `cargo test resource::` fails.
- [ ] Step 3 — implement the `GitRepo` arm + a shared component-safety check (reused by MirrorStore in Task 5 — consider a `pub(crate) fn safe_component(&str) -> bool`).
- [ ] Step 4 — `cargo test resource::` passes.
- [ ] Step 5 — commit `feat(resource): git-repo path extractor with traversal guard`.

---

### Task 3: Injection value helper

**Files:** Modify `src/inject.rs`.

**Interfaces produced:** `pub fn injection_value(injection: &Injection, secret: &str) -> Result<String, InjectError>` returning the header value (`Bearer <s>` / `Basic <b64(s)>` / raw `<s>`). `inject()` refactored to call it.

- [ ] Step 1 — failing test: `injection_value` for each scheme returns the expected string (`Basic dXNlcjpwYXNz` for `user:pass`, `Bearer x`, raw `x`); keep existing `inject` tests.
- [ ] Step 2 — `cargo test inject::` fails (new test).
- [ ] Step 3 — extract the value builder; `inject()` calls `injection_value` then `insert_header`.
- [ ] Step 4 — `cargo test inject::` passes (old + new).
- [ ] Step 5 — commit `refactor(inject): extract injection_value helper`.

---

### Task 4: `git::classify`

**Files:** Create `src/git/mod.rs` (`pub mod classify; pub mod mirror; pub mod sync; pub mod backend;` — add stubs as needed so it compiles), `src/git/classify.rs`; add `pub mod git;` to `src/lib.rs`.

**Interfaces produced:** `pub enum GitRequest { Read, Push, Other }`; `pub fn classify(method: &str, path: &str, query: &str) -> GitRequest`.
- Read: `GET /…/info/refs?service=git-upload-pack` OR `POST /…/git-upload-pack`.
- Push: `GET /…/info/refs?service=git-receive-pack` OR `POST /…/git-receive-pack`.
- else Other.

- [ ] Step 1 — failing tests for each of the 4 forms + an Other.
- [ ] Step 2 — `cargo test git::classify` fails.
- [ ] Step 3 — implement (parse `service` from query for info/refs; suffix-match for POST). Create the other `git/*.rs` as empty stubs (filled in Tasks 5–7) so the module tree compiles.
- [ ] Step 4 — passes.
- [ ] Step 5 — commit `feat(git): request classification (read/push)`.

---

### Task 5: `git::MirrorStore`

**Files:** `src/git/mirror.rs`.

**Interfaces produced:** `pub struct MirrorStore { root: PathBuf }` with `new(storage_path)`, `pub fn path_for(&self, upstream: &str, owner: &str, repo: &str) -> Option<PathBuf>` (None if any component unsafe — reuse Task 2's `safe_component`), and `pub async fn ensure(&self, path: &Path, clone_url: &str, auth_header: &str) -> Result<(), GitError>` = if `path` missing, run `git -c http.extraHeader=Authorization: <auth_header> clone --mirror <clone_url> <path>` (fixed argv, `tokio::process`), guarded so concurrent first-hits don't double-clone (per-path lock or atomic create). `pub enum GitError` (thiserror).

- [ ] Step 1 — failing unit tests: `path_for` builds `root/upstream/owner/repo.git`; `path_for` returns None for `..`/empty components.
- [ ] Step 2 — fails.
- [ ] Step 3 — implement `path_for` + `ensure` (ensure exercised in Task 10 integration; unit-cover paths + safety here). Never log `auth_header`.
- [ ] Step 4 — `cargo test git::mirror` passes.
- [ ] Step 5 — commit `feat(git): mirror store (paths + ensure clone --mirror)`.

---

### Task 6: `git::SyncManager` (single-flight)

**Files:** `src/git/sync.rs`. May add a dep (`async-singleflight`) or hand-roll — decide here.

**Interfaces produced:** `pub struct SyncManager { … }` with `new()` and `pub async fn sync(&self, key: &str, git_dir: &Path, auth_header: &str) -> Result<(), GitError>` = `git -c http.extraHeader=… --git-dir <git_dir> fetch --prune origin`, **single-flighted by `key`** (concurrent callers for the same key await one in-flight fetch; different keys run concurrently).

- [ ] Step 1 — failing test: spin N concurrent `sync` calls for one key against a **local bare origin** created in the test; assert the upstream is fetched exactly once (e.g. count via a post-receive/`GIT_TRACE`-free scheme: use a local origin and a shared `AtomicUsize` incremented by wrapping the fetch in an instrumented closure — or assert timing/one-invocation via a test seam that records fetch invocations). Also assert two different keys both run.
- [ ] Step 2 — fails.
- [ ] Step 3 — implement single-flight (`Mutex<HashMap<String, Weak<Shared<…>>>>` or `async-singleflight`). Never log `auth_header`.
- [ ] Step 4 — passes.
- [ ] Step 5 — commit `feat(git): single-flight sync manager`.

---

### Task 7: `git::Backend` (CGI env + response parsing)

**Files:** `src/git/backend.rs`.

**Interfaces produced:** pure `pub fn cgi_env(storage_path, owner, repo, tail, query, method, content_type: Option<&str>, git_protocol: Option<&str>, remote_user: Option<&str>) -> Vec<(String,String)>`; pure `pub fn parse_cgi_head(buf: &[u8]) -> Option<(u16, Vec<(String,String)>, usize)>` (status default 200 from `Status:`; headers until blank line; returns body offset); and `pub async fn spawn(git_dir_root, env, ...) -> Result<Child, GitError>` producing a `git http-backend` child with piped stdin/stdout (wiring exercised in Task 10).

- [ ] Step 1 — failing tests: `cgi_env` includes `GIT_PROJECT_ROOT`, `GIT_HTTP_EXPORT_ALL=1`, correct `PATH_INFO=/owner/repo.git/tail`, `QUERY_STRING`, `REQUEST_METHOD`, and `GIT_PROTOCOL` when provided; `parse_cgi_head` on `b"Status: 200 OK\r\nContent-Type: application/x-git-upload-pack-result\r\n\r\nBODY"` → (200, [content-type], offset at BODY); default 200 when no Status line.
- [ ] Step 2 — fails.
- [ ] Step 3 — implement the two pure fns + the spawn helper.
- [ ] Step 4 — `cargo test git::backend` passes.
- [ ] Step 5 — commit `feat(git): http-backend CGI env + response parsing`.

---

### Task 8: Proxy integration (read serve + push passthrough)

**Files:** Modify `src/proxy.rs`.

**Interfaces produced:** `ProxyService` gains `mirrors: Arc<git::mirror::MirrorStore>` + `sync: Arc<git::sync::SyncManager>`; `ProxyService::new(router, verifier, keystore, secrets, mirrors, sync)`. `RequestCtx` gains a `push_repo: Option<(String,String,String)>` (upstream,owner,repo) flag.

**Behavior:** after the existing authorize step in `request_filter`, if `upstream.kind == GitCache`:
- `classify` the request. **Read**: resolve secret (`self.secrets.get(&upstream.secret_ref)`), build `auth_header = injection_value(&upstream.injection, secret.expose())`, compute the git origin URL (`{origin}/{owner}/{repo}.git`) and mirror path (`mirrors.path_for(...)` → 404/500 if None), `mirrors.ensure(...)` (502 on fail), `sync.sync(...)` (502 on fail), spawn `git http-backend`, feed `session.read_request_body()` → stdin, `parse_cgi_head` from stdout, then **stream** per the Global-Constraints API → `Ok(true)`. **Push**: record `ctx.push_repo` and `Ok(false)` (normal proxy path injects). **Other**: 400 → `Ok(true)`.
- In `response_filter` (or `logging`): if `ctx.push_repo` is set and the response status is success, `tokio::spawn` a background `sync.sync(...)` (resolve secret again inside the task). Errors here only log.

Errors: sync/ensure fail → 502; backend spawn/stream fail → 500. (401/403/404 already handled by the prelude.)

- [ ] Step 1 — implement (no unit test — Session isn't constructible; covered by Task 10). Keep `api` upstream behavior byte-identical.
- [ ] Step 2 — `cargo build` clean. (`cargo build --tests` will break on the Phase-2 integration test constructor + main.rs until Tasks 9/10 — expected; verify with `cargo build`.)
- [ ] Step 3 — `cargo clippy` on the lib is clean.
- [ ] Step 4 — commit `feat(proxy): git-cache read serve + push passthrough`.

---

### Task 9: Binary wiring

**Files:** Modify `src/main.rs`; update the Phase-2 integration test constructor call.

**Behavior:** build `MirrorStore::new(storage_path)` + `SyncManager::new()` (storage_path from the first git-cache upstream's `git` block, or a top-level setting — keep consistent with the config from Task 1), wrap in `Arc`, pass into `ProxyService::new`. Update the existing `tests/jwt_egress.rs` `ProxyService::new(...)` call to the new signature.

- [ ] Step 1 — implement wiring; update the test constructor.
- [ ] Step 2 — `cargo build` clean (bin+lib).
- [ ] Step 3 — `cargo test` — existing 46 tests still pass (git integration added in Task 10).
- [ ] Step 4 — commit `feat(bin): wire git mirror store + sync manager`.

---

### Task 10: End-to-end integration test

**Files:** Create `tests/git_cache.rs`.

**Behavior:** `git init --bare` a local origin in a tempdir + seed a commit (drive the real `git` CLI). Build a shared `Keystore` (Phase-2 `build_key_material`) + mint a scoped JWT (`Issuer`) for `github:testorg/testrepo`. Configure a `git-cache` `ProxyService` (origin = `file://<local-origin>` or a local `git http-backend`; storage in a tempdir) and run it on a background thread (as in `tests/jwt_egress.rs`). Assert:
- `git -c http.extraHeader="Authorization: Bearer <jwt>" clone http://127.0.0.1:PORT/testorg/testrepo.git` succeeds; cloned tree matches origin.
- Add a commit to the origin, then `git fetch` through the proxy sees it (fresh refs).
- `git push` through the proxy lands on the origin.
- Out-of-scope repo (`testorg/other`) → clone fails with 403; no JWT → 401.
Use `GIT_TERMINAL_PROMPT=0`. This is the checkpoint — iterate on harness details (origin URL scheme that `git http-backend` accepts for the mirror; `file://` works for `clone --mirror`) until green, without weakening the security assertions.

- [ ] Step 1 — write the test.
- [ ] Step 2 — `cargo test --test git_cache -- --nocapture` iterate to green.
- [ ] Step 3 — full `cargo test` green.
- [ ] Step 4 — commit `test: end-to-end git-cache clone/fetch/push + authz`.

---

### Task 11: Verification + README

**Files:** `README.md`; verification only otherwise.

- [ ] Step 1 — `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` all clean; fix any warnings.
- [ ] Step 2 — README: add a git-cache section (config example, `git clone`/`push` with `http.extraHeader` JWT, fresh-refs/cached-objects note, `git` binary requirement); move git-cache out of the roadmap.
- [ ] Step 3 — commit `docs: README + cleanup for git-cache`.

---

## Self-Review

- Spec coverage: config (T1), git-repo authz (T2), credential value (T3), classify (T4), mirror (T5), single-flight sync (T6), backend (T7), read-serve+push (T8), wiring (T9), e2e (T10), verify/docs (T11). ✓
- Security: JWT never upstream (reads don't proxy; push strips+injects — reuses Phase 1/2), credential never logged (T5/T6/T8), path traversal rejected (T2/T5). ✓
- Type consistency: `Resource`/`ScopeSet::permits`/`authorize` reused unchanged; `GitConfig`/`UpstreamKind::GitCache` (T1) used in T8/T9; `injection_value` (T3) used in T8; `MirrorStore`/`SyncManager` (T5/T6) used in T8/T9; `classify`/`GitRequest` (T4) used in T8.
