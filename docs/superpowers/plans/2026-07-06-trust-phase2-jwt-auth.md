# trust Phase 2 — JWT auth, mTLS issuance, scoped authz Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Phase 1's static token map with self-issued asymmetric JWTs — an mTLS-gated OAuth2 `client_credentials` endpoint mints ~7-day scoped tokens (scopes capped by the caller's SPIFFE identity); the proxy verifies them with trust's own keys and authorizes each request by scope, including repo-level authz for GitHub.

**Architecture:** trust runs its Pingora proxy on the main thread and a separate **management** HTTP stack (axum + rustls mTLS) on a dedicated Tokio runtime thread. Both share a hot-swappable `Keystore` (signing key from GCP Secret Manager via `ArcSwap`, JWKS = current+previous public keys). Pure modules (`scope`, `resource`, `jwt`, `keystore` builders, `ClientPolicy`, SPIFFE extraction) are unit-tested; the mTLS token endpoint and full proxy wiring are covered by integration tests with `rcgen`-generated PKI.

**Tech Stack:** Rust (edition 2024), Pingora 0.8, `jsonwebtoken` 10.4 (ES256, `aws_lc_rs`), `p256`, `arc-swap`, `humantime`, `axum` 0.8 + `axum-server-mtls`, `rustls` 0.23, `x509-parser`, `rcgen` (dev), plus the Phase 1 `SecretProvider`/GCP stack.

## Global Constraints

- Rust edition **2024**; builds on the Phase 1 crate (`filip/egress-proxy` → this branch `filip/jwt-auth`).
- JWT algorithm **ES256**; issuer/audience from config; token TTL default **7 days**.
- Pin: `jsonwebtoken = { version = "10.4", features = ["aws_lc_rs", "use_pem"] }`, `p256 = { version = "0.13", features = ["pem", "pkcs8"] }`, `arc-swap = "1"`, `humantime = "2"`, `axum = "0.8"`, `axum-server = { version = "0.8", features = ["tls-rustls-no-provider"] }`, `axum-server-mtls = "0.1"`, `rustls = "0.23"`, `rustls-pemfile = "2"`, `x509-parser = "0.18"`, dev `rcgen = { version = "0.14", features = ["pem", "x509-parser"] }`.
- **A rustls crypto provider MUST be installed once at startup** (`rustls::crypto::aws_lc_rs::default_provider().install_default()`) before any rustls builder runs, because `axum-server`'s `tls-rustls-no-provider` feature ships none.
- **mTLS is mandatory** on the token endpoint: `WebPkiClientVerifier::builder(roots).build()` — never `.allow_unauthenticated()`.
- Private keys are PKCS8 PEM. Signing keys and upstream secrets are **never logged** (redacted `Debug`, no `Display`); no plaintext secrets in config.
- Scope wildcard is **one segment** (`owner/*`); no `**`.
- Static `[[tokens]]` auth is **removed** — JWT-only. The Phase 1 `TokenMap` and its tests are deleted/replaced.
- Typed errors (`thiserror`); no panics/unwrap in the request or issuance path.
- TDD: failing test → run (fail) → minimal impl → run (pass) → commit.

---

### Task 1: Phase 2 dependencies

**Files:**
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: all Phase 2 crates resolve and the existing crate still builds + tests green.

- [ ] **Step 1: Add dependencies**

Add to `[dependencies]` in `Cargo.toml`:
```toml
jsonwebtoken = { version = "10.4", features = ["aws_lc_rs", "use_pem"] }
p256 = { version = "0.13", features = ["pem", "pkcs8"] }
arc-swap = "1"
humantime = "2"
axum = "0.8"
axum-server = { version = "0.8", features = ["tls-rustls-no-provider"] }
axum-server-mtls = "0.1"
rustls = "0.23"
rustls-pemfile = "2"
x509-parser = "0.18"
```
Add a `[dev-dependencies]` section (or extend it):
```toml
[dev-dependencies]
rcgen = { version = "0.14", features = ["pem", "x509-parser"] }
```

- [ ] **Step 2: Verify build + existing tests**

Run: `cargo build && cargo test`
Expected: compiles; the Phase 1 suite (19 tests) still passes. If a pinned version fails to resolve, run `cargo add <crate> --features ...` and let cargo pick the compatible patch, then re-run. `aws-lc-rs` needs `cmake` + a C compiler (already provided via `mise.toml`).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add phase 2 deps (jwt, rustls mtls, p256)"
```

---

### Task 2: Scope model

**Files:**
- Create: `src/scope.rs`
- Modify: `src/lib.rs` (add `pub mod scope;`)

**Interfaces:**
- Produces:
  - `pub struct Resource { pub owner: String, pub repo: String }` — a concrete request target.
  - `pub enum RepoPat { Exact(String), Wildcard }`
  - `pub enum Scope { Upstream(String), Resource { upstream: String, owner: String, repo: RepoPat } }`
  - `pub struct ScopeSet(Vec<Scope>)` with `pub fn parse(s: &str) -> Result<ScopeSet, ScopeError>`, `pub fn to_scope_string(&self) -> String`, `pub fn permits(&self, upstream: &str, resource: Option<&Resource>) -> bool`, `pub fn iter(&self) -> impl Iterator<Item = &Scope>`.
  - `pub fn covers(allowed: &Scope, requested: &Scope) -> bool`
  - `pub fn grant(allowed: &ScopeSet, requested: &ScopeSet) -> Result<(), String>` (Err = first uncovered scope token).
  - `pub enum ScopeError { Empty, Malformed(String) }` (thiserror).
  - `impl Scope { pub fn parse(tok: &str) -> Result<Scope, ScopeError>; pub fn to_token(&self) -> String }`

- [ ] **Step 1: Write the failing test**

Add to `src/scope.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn res(owner: &str, repo: &str) -> Resource {
        Resource { owner: owner.into(), repo: repo.into() }
    }

    #[test]
    fn parses_tokens() {
        assert!(matches!(Scope::parse("anthropic").unwrap(), Scope::Upstream(u) if u == "anthropic"));
        match Scope::parse("github:example-org/example-repo").unwrap() {
            Scope::Resource { upstream, owner, repo } => {
                assert_eq!(upstream, "github");
                assert_eq!(owner, "example-org");
                assert!(matches!(repo, RepoPat::Exact(r) if r == "example-repo"));
            }
            _ => panic!("expected resource"),
        }
        assert!(matches!(
            Scope::parse("github:customer-org/*").unwrap(),
            Scope::Resource { repo: RepoPat::Wildcard, .. }
        ));
        assert!(Scope::parse("bad:too/many/parts").is_err());
        assert!(Scope::parse("").is_err());
    }

    #[test]
    fn scopeset_roundtrip() {
        let s = ScopeSet::parse("anthropic github:example-org/example-repo").unwrap();
        assert_eq!(s.to_scope_string(), "anthropic github:example-org/example-repo");
    }

    #[test]
    fn permits_unscoped() {
        let s = ScopeSet::parse("anthropic").unwrap();
        assert!(s.permits("anthropic", None));
        assert!(!s.permits("mistral", None));
    }

    #[test]
    fn permits_resource_scoped() {
        let s = ScopeSet::parse("github:example-org/example-repo github:customer-org/*").unwrap();
        assert!(s.permits("github", Some(&res("example-org", "example-repo"))));       // exact
        assert!(s.permits("github", Some(&res("customer-org", "acme"))));   // wildcard
        assert!(!s.permits("github", Some(&res("example-org", "other"))));       // not granted
        assert!(!s.permits("github", None));                               // no bare token
    }

    #[test]
    fn bare_token_covers_resources() {
        let s = ScopeSet::parse("github").unwrap();
        assert!(s.permits("github", Some(&res("anyone", "anything"))));
        assert!(s.permits("github", None));
    }

    #[test]
    fn covers_for_issuance() {
        let bare = Scope::parse("github").unwrap();
        let wild = Scope::parse("github:example-org/*").unwrap();
        let exact = Scope::parse("github:example-org/example-repo").unwrap();
        assert!(covers(&bare, &exact));            // bare grants any repo
        assert!(covers(&wild, &exact));            // wildcard grants a specific repo
        assert!(covers(&wild, &wild));
        assert!(!covers(&exact, &wild));           // exact does not grant wildcard
        assert!(!covers(&Scope::parse("github:other/*").unwrap(), &exact));
    }

    #[test]
    fn grant_reports_first_uncovered() {
        let allowed = ScopeSet::parse("anthropic github:example-org/*").unwrap();
        assert!(grant(&allowed, &ScopeSet::parse("github:example-org/example-repo").unwrap()).is_ok());
        assert_eq!(
            grant(&allowed, &ScopeSet::parse("mistral").unwrap()),
            Err("mistral".to_string())
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test scope::`
Expected: FAIL (undefined items).

- [ ] **Step 3: Write the implementation**

Prepend to `src/scope.rs`:
```rust
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("empty scope")]
    Empty,
    #[error("malformed scope token: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub owner: String,
    pub repo: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoPat {
    Exact(String),
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Upstream(String),
    Resource {
        upstream: String,
        owner: String,
        repo: RepoPat,
    },
}

impl Scope {
    pub fn parse(tok: &str) -> Result<Scope, ScopeError> {
        if tok.is_empty() {
            return Err(ScopeError::Empty);
        }
        match tok.split_once(':') {
            None => Ok(Scope::Upstream(tok.to_string())),
            Some((upstream, resource)) => {
                let (owner, repo) = resource
                    .split_once('/')
                    .ok_or_else(|| ScopeError::Malformed(tok.to_string()))?;
                if upstream.is_empty() || owner.is_empty() || repo.is_empty() || repo.contains('/') {
                    return Err(ScopeError::Malformed(tok.to_string()));
                }
                let repo = if repo == "*" {
                    RepoPat::Wildcard
                } else {
                    RepoPat::Exact(repo.to_string())
                };
                Ok(Scope::Resource {
                    upstream: upstream.to_string(),
                    owner: owner.to_string(),
                    repo,
                })
            }
        }
    }

    pub fn to_token(&self) -> String {
        match self {
            Scope::Upstream(u) => u.clone(),
            Scope::Resource { upstream, owner, repo } => {
                let r = match repo {
                    RepoPat::Exact(r) => r.as_str(),
                    RepoPat::Wildcard => "*",
                };
                format!("{upstream}:{owner}/{r}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    pub fn parse(s: &str) -> Result<ScopeSet, ScopeError> {
        let scopes = s
            .split_whitespace()
            .map(Scope::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if scopes.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(ScopeSet(scopes))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }

    pub fn to_scope_string(&self) -> String {
        self.0.iter().map(Scope::to_token).collect::<Vec<_>>().join(" ")
    }

    /// Authorization check for a proxied request.
    pub fn permits(&self, upstream: &str, resource: Option<&Resource>) -> bool {
        for scope in &self.0 {
            match scope {
                // Bare upstream grants everything under it.
                Scope::Upstream(u) if u == upstream => return true,
                Scope::Resource { upstream: u, owner, repo } if u == upstream => {
                    if let Some(res) = resource {
                        if *owner == res.owner
                            && match repo {
                                RepoPat::Wildcard => true,
                                RepoPat::Exact(r) => *r == res.repo,
                            }
                        {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }
}

/// Issuance check: can `allowed` grant `requested`?
pub fn covers(allowed: &Scope, requested: &Scope) -> bool {
    match (allowed, requested) {
        (Scope::Upstream(a), Scope::Upstream(r)) => a == r,
        // A bare upstream grant covers any resource under that upstream.
        (Scope::Upstream(a), Scope::Resource { upstream: r, .. }) => a == r,
        (
            Scope::Resource { upstream: au, owner: ao, repo: ar },
            Scope::Resource { upstream: ru, owner: ro, repo: rr },
        ) => {
            au == ru
                && ao == ro
                && match (ar, rr) {
                    (RepoPat::Wildcard, _) => true,
                    (RepoPat::Exact(a), RepoPat::Exact(r)) => a == r,
                    (RepoPat::Exact(_), RepoPat::Wildcard) => false,
                }
        }
        _ => false,
    }
}

/// Every requested scope must be covered by some allowed scope.
/// Returns the first uncovered scope token on failure.
pub fn grant(allowed: &ScopeSet, requested: &ScopeSet) -> Result<(), String> {
    for req in &requested.0 {
        if !allowed.0.iter().any(|a| covers(a, req)) {
            return Err(req.to_token());
        }
    }
    Ok(())
}
```

Add `pub mod scope;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test scope::`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/scope.rs src/lib.rs
git commit -m "feat(scope): scope model, covers (issuance) + permits (authz)"
```

---

### Task 3: Resource extraction

**Files:**
- Create: `src/resource.rs`
- Modify: `src/lib.rs` (add `pub mod resource;`)

**Interfaces:**
- Consumes: `crate::scope::Resource` (Task 2).
- Produces:
  - `pub enum ResourceKind { GithubRepo }` (serde `Deserialize`, `#[serde(rename_all = "kebab-case")]` → `"github-repo"`).
  - `pub fn extract(kind: ResourceKind, path: &str) -> Option<Resource>`

- [ ] **Step 1: Write the failing test**

Add to `src/resource.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_repo_from_repos_path() {
        let r = extract(ResourceKind::GithubRepo, "/repos/example-org/example-repo/issues").unwrap();
        assert_eq!(r.owner, "example-org");
        assert_eq!(r.repo, "example-repo");
    }

    #[test]
    fn github_repo_trims_dot_git() {
        let r = extract(ResourceKind::GithubRepo, "/repos/example-org/example-repo.git").unwrap();
        assert_eq!(r.repo, "example-repo");
    }

    #[test]
    fn non_repo_paths_are_none() {
        assert!(extract(ResourceKind::GithubRepo, "/user").is_none());
        assert!(extract(ResourceKind::GithubRepo, "/repos/example-org").is_none());
        assert!(extract(ResourceKind::GithubRepo, "/").is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test resource::`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Prepend to `src/resource.rs`:
```rust
use serde::Deserialize;

use crate::scope::Resource;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    GithubRepo,
}

pub fn extract(kind: ResourceKind, path: &str) -> Option<Resource> {
    match kind {
        ResourceKind::GithubRepo => {
            // .../repos/{owner}/{repo}/...
            let mut segs = path.split('/').filter(|s| !s.is_empty());
            loop {
                match segs.next() {
                    Some("repos") => break,
                    Some(_) => continue,
                    None => return None,
                }
            }
            let owner = segs.next()?;
            let repo = segs.next()?;
            let repo = repo.strip_suffix(".git").unwrap_or(repo);
            if owner.is_empty() || repo.is_empty() {
                return None;
            }
            Some(Resource { owner: owner.to_string(), repo: repo.to_string() })
        }
    }
}
```

Add `pub mod resource;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test resource::`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/resource.rs src/lib.rs
git commit -m "feat(resource): github-repo path extraction"
```

---

### Task 4: Config changes (JWT auth + issuance)

**Files:**
- Modify: `src/config.rs`

**Interfaces:**
- Consumes: `crate::resource::ResourceKind` (Task 3).
- Produces (new/changed):
  - Remove `TokenEntry` and `tokens` from `Config`.
  - `pub struct AuthConfig { pub issuer: String, pub audience: String, pub signing: SigningConfig }`
  - `pub struct SigningConfig { pub algorithm: String, pub token_ttl: std::time::Duration, pub key_secret_ref: String, pub previous_key_secret_ref: Option<String> }`
  - `pub struct IssuanceConfig { pub mtls_addr: String, pub client_ca_path: String, pub jwks_addr: String, pub clients: Vec<ClientEntry> }`
  - `pub struct ClientEntry { pub spiffe: String, pub allowed_scopes: Vec<String> }`
  - `Upstream` gains `pub resource: Option<ResourceKind>`.
  - `Config` gains `pub auth: AuthConfig`, `pub issuance: IssuanceConfig`.
  - New `ConfigError` variants: `BadDuration { value: String }`, `BadScope { scope: String }`.

- [ ] **Step 1: Write the failing test**

Replace the `tests` module in `src/config.rs` with (note the new TOML shape — no `[[tokens]]`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[listen]
tcp = "0.0.0.0:6191"

[auth]
issuer = "https://trust.example.internal/"
audience = "trust-proxy"

[auth.signing]
algorithm = "ES256"
token_ttl = "7d"
key_secret_ref = "projects/p/secrets/sign/versions/latest"

[issuance]
mtls_addr = "0.0.0.0:8443"
client_ca_path = "/etc/trust/client-ca.pem"
jwks_addr = "0.0.0.0:8080"

[[issuance.clients]]
spiffe = "spiffe://example/ci/example-repo"
allowed_scopes = ["github:example-org/example-repo"]

[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "anthropic.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/p/secrets/anthropic/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }

[[upstreams]]
name = "github"
kind = "api"
listen_host = "github-api.proxy.internal"
origin = "https://api.github.com"
secret_ref = "projects/p/secrets/gh/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-repo" }
"#;

    #[test]
    fn parses_auth_issuance_and_resource() {
        let cfg = Config::from_str(GOOD).unwrap();
        assert_eq!(cfg.auth.issuer, "https://trust.example.internal/");
        assert_eq!(cfg.auth.audience, "trust-proxy");
        assert_eq!(cfg.auth.signing.token_ttl, std::time::Duration::from_secs(7 * 24 * 3600));
        assert_eq!(cfg.issuance.clients.len(), 1);
        assert_eq!(cfg.issuance.clients[0].spiffe, "spiffe://example/ci/example-repo");
        assert!(cfg.upstreams[0].resource.is_none());
        assert!(matches!(
            cfg.upstreams[1].resource,
            Some(crate::resource::ResourceKind::GithubRepo)
        ));
    }

    #[test]
    fn rejects_bad_ttl() {
        let bad = GOOD.replace(r#"token_ttl = "7d""#, r#"token_ttl = "banana""#);
        assert!(matches!(Config::from_str(&bad), Err(ConfigError::BadDuration { .. })));
    }

    #[test]
    fn rejects_bad_allowed_scope() {
        let bad = GOOD.replace(r#"allowed_scopes = ["github:example-org/example-repo"]"#, r#"allowed_scopes = ["bad:too/many/parts"]"#);
        assert!(matches!(Config::from_str(&bad), Err(ConfigError::BadScope { .. })));
    }

    #[test]
    fn rejects_duplicate_upstream_name() {
        let dup = GOOD.to_string() + r#"
[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "dup.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/p/secrets/x/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }
"#;
        assert!(matches!(Config::from_str(&dup), Err(ConfigError::DuplicateUpstream(_))));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config::`
Expected: FAIL (compile errors — new types/fields absent).

- [ ] **Step 3: Write the implementation**

In `src/config.rs`: add `use crate::resource::ResourceKind;`, add the two new `ConfigError` variants, add the new structs, extend `Upstream`/`RawUpstream`/`RawConfig`/`Config`, remove `TokenEntry` + `tokens`, and parse/validate. Concretely:

Add to `ConfigError`:
```rust
    #[error("invalid duration {value}")]
    BadDuration { value: String },
    #[error("invalid scope in issuance policy: {scope}")]
    BadScope { scope: String },
```

Add structs:
```rust
#[derive(Debug, Clone, Deserialize)]
pub struct RawSigning {
    pub algorithm: String,
    pub token_ttl: String,
    pub key_secret_ref: String,
    #[serde(default)]
    pub previous_key_secret_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub algorithm: String,
    pub token_ttl: std::time::Duration,
    pub key_secret_ref: String,
    pub previous_key_secret_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawAuth {
    pub issuer: String,
    pub audience: String,
    pub signing: RawSigning,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub signing: SigningConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    pub spiffe: String,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuanceConfig {
    pub mtls_addr: String,
    pub client_ca_path: String,
    pub jwks_addr: String,
    #[serde(default)]
    pub clients: Vec<ClientEntry>,
}
```

Extend `Upstream` and `RawUpstream` with:
```rust
    #[serde(default)]
    pub resource: Option<ResourceKind>,   // RawUpstream (add `resource: Option<ResourceKind>` — with #[serde(default)])
```
(For the resolved `Upstream`, add `pub resource: Option<ResourceKind>` too, copied through.)

Replace `RawConfig` / `Config` token fields with auth + issuance:
```rust
#[derive(Deserialize)]
struct RawConfig {
    listen: ListenConfig,
    #[serde(default)]
    tls: Option<TlsConfig>,
    auth: RawAuth,
    issuance: IssuanceConfig,
    upstreams: Vec<RawUpstream>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub tls: Option<TlsConfig>,
    pub auth: AuthConfig,
    pub issuance: IssuanceConfig,
    pub upstreams: Vec<Arc<Upstream>>,
}
```

In `from_str`, after building upstreams (unchanged validation for dup name/host + origin), add:
```rust
        // Parse token TTL.
        let token_ttl = humantime::parse_duration(&raw.auth.signing.token_ttl)
            .map_err(|_| ConfigError::BadDuration { value: raw.auth.signing.token_ttl.clone() })?;

        // Validate issuance client scopes parse.
        for c in &raw.issuance.clients {
            for s in &c.allowed_scopes {
                crate::scope::Scope::parse(s)
                    .map_err(|_| ConfigError::BadScope { scope: s.clone() })?;
            }
        }

        let auth = AuthConfig {
            issuer: raw.auth.issuer,
            audience: raw.auth.audience,
            signing: SigningConfig {
                algorithm: raw.auth.signing.algorithm,
                token_ttl,
                key_secret_ref: raw.auth.signing.key_secret_ref,
                previous_key_secret_ref: raw.auth.signing.previous_key_secret_ref,
            },
        };
```
Carry `resource: ru.resource` when constructing each `Upstream`, and return `Config { listen, tls, auth, issuance: raw.issuance, upstreams }`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test config::`
Expected: PASS (4 tests). (The old token-map tests are gone — that's intended.)

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): jwt auth + issuance config, per-upstream resource; drop tokens"
```

---

### Task 5: Keystore (signing key load + JWKS + hot swap)

**Files:**
- Create: `src/keystore.rs`
- Modify: `src/lib.rs` (add `pub mod keystore;`)

**Interfaces:**
- Consumes: `crate::secrets::{SecretProvider, SecretError}` (Phase 1), `crate::config::SigningConfig` (Task 4).
- Produces:
  - `pub struct KeyMaterial { pub signing_kid: String, pub encoding: jsonwebtoken::EncodingKey, pub decoding: std::collections::HashMap<String, jsonwebtoken::DecodingKey>, pub jwks_json: String }`
  - `pub struct Keystore { current: arc_swap::ArcSwapOption<KeyMaterial> }` with `pub fn new() -> Keystore`, `pub fn load(&self) -> Option<std::sync::Arc<KeyMaterial>>`, `pub fn store(&self, km: KeyMaterial)`.
  - `pub async fn fetch(provider: &dyn SecretProvider, cfg: &SigningConfig) -> Result<KeyMaterial, KeystoreError>` — fetch current (+ optional previous) PKCS8 PEM and build `KeyMaterial`.
  - `pub fn build_key_material(current_pkcs8_pem: &str, previous_pkcs8_pem: Option<&str>) -> Result<KeyMaterial, KeystoreError>` (pure — the unit-tested core).
  - `pub enum KeystoreError` (thiserror).

**Note:** `build_key_material` is the pure, unit-tested core; `fetch` is thin glue over `SecretProvider` + `build_key_material` (covered by later integration). Tests generate an EC P-256 PKCS8 key with `rcgen`.

- [ ] **Step 1: Write the failing test**

Add to `src/keystore.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Generate an EC P-256 PKCS8 private key PEM for tests.
    fn gen_pkcs8_pem() -> String {
        let params = rcgen::CertificateParams::new(vec!["test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let _ = params; // params unused; we only need the keypair PEM
        key.serialize_pem()
    }

    #[test]
    fn builds_material_with_one_key() {
        let pem = gen_pkcs8_pem();
        let km = build_key_material(&pem, None).unwrap();
        assert!(!km.signing_kid.is_empty());
        assert!(km.decoding.contains_key(&km.signing_kid));
        assert!(km.jwks_json.contains("\"kty\":\"EC\""));
        assert!(km.jwks_json.contains("\"crv\":\"P-256\""));
        assert!(km.jwks_json.contains(&km.signing_kid));
    }

    #[test]
    fn previous_key_is_verify_only_and_in_jwks() {
        let cur = gen_pkcs8_pem();
        let prev = gen_pkcs8_pem();
        let km = build_key_material(&cur, Some(&prev)).unwrap();
        // Two distinct kids in the decoding map + JWKS; signing kid is the current one.
        assert_eq!(km.decoding.len(), 2);
        assert!(km.decoding.contains_key(&km.signing_kid));
        let key_count = km.jwks_json.matches("\"kid\"").count();
        assert_eq!(key_count, 2);
    }

    #[test]
    fn keystore_swaps() {
        let ks = Keystore::new();
        assert!(ks.load().is_none());
        ks.store(build_key_material(&gen_pkcs8_pem(), None).unwrap());
        assert!(ks.load().is_some());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test keystore::`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Prepend to `src/keystore.rs`:
```rust
use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, ThumbprintHash,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use p256::SecretKey;

use crate::config::SigningConfig;
use crate::secrets::SecretProvider;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("invalid signing key: {0}")]
    BadKey(String),
    #[error("secret backend error: {0}")]
    Secret(String),
}

pub struct KeyMaterial {
    pub signing_kid: String,
    pub encoding: EncodingKey,
    pub decoding: HashMap<String, DecodingKey>,
    pub jwks_json: String,
}

fn jwk_for(secret: &SecretKey) -> (String, Jwk, DecodingKey) {
    let public = secret.public_key();
    let point = public.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 has X"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 has Y"));

    let mut jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::ES256),
            key_id: None,
            ..Default::default()
        },
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x,
            y,
        }),
    };
    let kid = jwk.thumbprint(ThumbprintHash::SHA256);
    jwk.common.key_id = Some(kid.clone());

    let spki_pem = public
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .expect("public key to SPKI PEM");
    let decoding = DecodingKey::from_ec_pem(spki_pem.as_bytes()).expect("valid SPKI");
    (kid, jwk, decoding)
}

pub fn build_key_material(
    current_pkcs8_pem: &str,
    previous_pkcs8_pem: Option<&str>,
) -> Result<KeyMaterial, KeystoreError> {
    let current = SecretKey::from_pkcs8_pem(current_pkcs8_pem)
        .map_err(|e| KeystoreError::BadKey(e.to_string()))?;
    let encoding = EncodingKey::from_ec_pem(current_pkcs8_pem.as_bytes())
        .map_err(|e| KeystoreError::BadKey(e.to_string()))?;

    let (signing_kid, cur_jwk, cur_decoding) = jwk_for(&current);
    let mut decoding = HashMap::new();
    decoding.insert(signing_kid.clone(), cur_decoding);
    let mut jwks = vec![cur_jwk];

    if let Some(prev_pem) = previous_pkcs8_pem {
        let prev = SecretKey::from_pkcs8_pem(prev_pem)
            .map_err(|e| KeystoreError::BadKey(e.to_string()))?;
        let (prev_kid, prev_jwk, prev_decoding) = jwk_for(&prev);
        if prev_kid != signing_kid {
            decoding.insert(prev_kid, prev_decoding);
            jwks.push(prev_jwk);
        }
    }

    let jwks_json = serde_json::to_string(&JwkSet { keys: jwks })
        .map_err(|e| KeystoreError::BadKey(e.to_string()))?;

    Ok(KeyMaterial { signing_kid, encoding, decoding, jwks_json })
}

pub async fn fetch(
    provider: &dyn SecretProvider,
    cfg: &SigningConfig,
) -> Result<KeyMaterial, KeystoreError> {
    let current = provider
        .get(&cfg.key_secret_ref)
        .await
        .map_err(|e| KeystoreError::Secret(e.to_string()))?;
    let previous = match &cfg.previous_key_secret_ref {
        Some(r) => Some(
            provider
                .get(r)
                .await
                .map_err(|e| KeystoreError::Secret(e.to_string()))?,
        ),
        None => None,
    };
    build_key_material(current.expose(), previous.as_ref().map(|s| s.expose()))
}

pub struct Keystore {
    current: ArcSwapOption<KeyMaterial>,
}

impl Keystore {
    pub fn new() -> Keystore {
        Keystore { current: ArcSwapOption::empty() }
    }

    pub fn load(&self) -> Option<Arc<KeyMaterial>> {
        self.current.load_full()
    }

    pub fn store(&self, km: KeyMaterial) {
        self.current.store(Some(Arc::new(km)));
    }
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new()
    }
}
```

Add `pub mod keystore;` to `src/lib.rs`. If `serde_json` isn't already a dependency, add `serde_json = "1"` (jsonwebtoken pulls it, but declare it explicitly): `cargo add serde_json`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test keystore::`
Expected: PASS (3 tests). If `KeyPair::generate_for`/`PKCS_ECDSA_P256_SHA256` names differ in rcgen 0.14.8, run `cargo doc -p rcgen` and use the current constructor for a P-256 keypair PEM; if `to_encoded_point`/`x()`/`y()` differ, check `cargo doc -p p256`.

- [ ] **Step 5: Commit**

```bash
git add src/keystore.rs src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(keystore): ES256 key material, JWKS, hot-swap store"
```

---

### Task 6: JWT issuer + verifier

**Files:**
- Create: `src/jwt.rs`
- Modify: `src/lib.rs` (add `pub mod jwt;`)

**Interfaces:**
- Consumes: `crate::keystore::KeyMaterial` (Task 5), `crate::scope::ScopeSet` (Task 2).
- Produces:
  - `pub struct Claims { pub iss: String, pub aud: String, pub sub: String, pub iat: u64, pub exp: u64, pub scope: String }` (serde).
  - `pub struct Issuer { issuer: String, audience: String, ttl_secs: u64 }` with `pub fn new(issuer: String, audience: String, ttl: std::time::Duration) -> Issuer` and `pub fn mint(&self, km: &KeyMaterial, sub: &str, scopes: &ScopeSet, now: u64) -> Result<String, JwtError>`.
  - `pub struct Verifier { issuer: String, audience: String }` with `pub fn new(issuer: String, audience: String) -> Verifier` and `pub fn verify(&self, km: &KeyMaterial, token: &str) -> Result<ScopeSet, JwtError>`.
  - `pub enum JwtError { Sign(String), UnknownKid, Invalid(String), Expired, BadScope(String) }` (thiserror).

- [ ] **Step 1: Write the failing test**

Add to `src/jwt.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::build_key_material;
    use crate::scope::ScopeSet;

    fn km() -> crate::keystore::KeyMaterial {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        build_key_material(&key.serialize_pem(), None).unwrap()
    }

    fn now() -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let km = km();
        let issuer = Issuer::new("iss".into(), "aud".into(), std::time::Duration::from_secs(3600));
        let verifier = Verifier::new("iss".into(), "aud".into());
        let scopes = ScopeSet::parse("anthropic github:example-org/example-repo").unwrap();
        let token = issuer.mint(&km, "user:filip", &scopes, now()).unwrap();
        let got = verifier.verify(&km, &token).unwrap();
        assert_eq!(got.to_scope_string(), "anthropic github:example-org/example-repo");
    }

    #[test]
    fn rejects_expired() {
        let km = km();
        let issuer = Issuer::new("iss".into(), "aud".into(), std::time::Duration::from_secs(3600));
        let verifier = Verifier::new("iss".into(), "aud".into());
        let scopes = ScopeSet::parse("anthropic").unwrap();
        // iat far in the past → exp already elapsed.
        let token = issuer.mint(&km, "s", &scopes, now() - 100_000).unwrap();
        assert!(matches!(verifier.verify(&km, &token), Err(JwtError::Expired)));
    }

    #[test]
    fn rejects_wrong_audience() {
        let km = km();
        let issuer = Issuer::new("iss".into(), "other-aud".into(), std::time::Duration::from_secs(3600));
        let verifier = Verifier::new("iss".into(), "aud".into());
        let token = issuer.mint(&km, "s", &ScopeSet::parse("anthropic").unwrap(), now()).unwrap();
        assert!(matches!(verifier.verify(&km, &token), Err(JwtError::Invalid(_))));
    }

    #[test]
    fn rejects_unknown_kid() {
        // Token signed by a DIFFERENT key material → its kid isn't in `km`.
        let signer_km = km();
        let verifier_km = km();
        let issuer = Issuer::new("iss".into(), "aud".into(), std::time::Duration::from_secs(3600));
        let verifier = Verifier::new("iss".into(), "aud".into());
        let token = issuer.mint(&signer_km, "s", &ScopeSet::parse("anthropic").unwrap(), now()).unwrap();
        assert!(matches!(verifier.verify(&verifier_km, &token), Err(JwtError::UnknownKid)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test jwt::`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Prepend to `src/jwt.rs`:
```rust
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, decode_header, encode, Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::keystore::KeyMaterial;
use crate::scope::ScopeSet;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("failed to sign token: {0}")]
    Sign(String),
    #[error("unknown signing key id")]
    UnknownKid,
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("token expired")]
    Expired,
    #[error("invalid scope claim: {0}")]
    BadScope(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub scope: String,
}

pub struct Issuer {
    issuer: String,
    audience: String,
    ttl_secs: u64,
}

impl Issuer {
    pub fn new(issuer: String, audience: String, ttl: std::time::Duration) -> Issuer {
        Issuer { issuer, audience, ttl_secs: ttl.as_secs() }
    }

    pub fn mint(
        &self,
        km: &KeyMaterial,
        sub: &str,
        scopes: &ScopeSet,
        now: u64,
    ) -> Result<String, JwtError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(km.signing_kid.clone());
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: sub.to_string(),
            iat: now,
            exp: now + self.ttl_secs,
            scope: scopes.to_scope_string(),
        };
        encode(&header, &claims, &km.encoding).map_err(|e| JwtError::Sign(e.to_string()))
    }
}

pub struct Verifier {
    issuer: String,
    audience: String,
}

impl Verifier {
    pub fn new(issuer: String, audience: String) -> Verifier {
        Verifier { issuer, audience }
    }

    pub fn verify(&self, km: &KeyMaterial, token: &str) -> Result<ScopeSet, JwtError> {
        let header = decode_header(token).map_err(|e| JwtError::Invalid(e.to_string()))?;
        let kid = header.kid.ok_or(JwtError::UnknownKid)?;
        let key = km.decoding.get(&kid).ok_or(JwtError::UnknownKid)?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let data = decode::<Claims>(token, key, &validation).map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid(e.to_string()),
        })?;

        ScopeSet::parse(&data.claims.scope).map_err(|e| JwtError::BadScope(e.to_string()))
    }
}
```

Add `pub mod jwt;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test jwt::`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/jwt.rs src/lib.rs
git commit -m "feat(jwt): ES256 issuer + verifier (kid selection, iss/aud/exp)"
```

---

### Task 7: SPIFFE extraction + client policy

**Files:**
- Create: `src/issuance/mod.rs` (declares submodules), `src/issuance/mtls.rs`, `src/issuance/policy.rs`
- Modify: `src/lib.rs` (add `pub mod issuance;`)

**Interfaces:**
- Consumes: `crate::config::ClientEntry` (Task 4), `crate::scope::{ScopeSet, grant}` (Task 2).
- Produces:
  - `issuance::mtls::extract_spiffe(cert_der: &[u8]) -> Option<String>`
  - `issuance::policy::ClientPolicy` with `pub fn new(entries: &[ClientEntry]) -> Result<ClientPolicy, crate::scope::ScopeError>` and `pub fn allowed_scopes(&self, spiffe: &str) -> Option<&ScopeSet>` (exact match, then a single trailing-`*` prefix match).

- [ ] **Step 1: Write the failing tests**

`src/issuance/mod.rs`:
```rust
pub mod mtls;
pub mod policy;
```

`src/issuance/mtls.rs` tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn client_cert_der_with_uri(uri: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::URI(rcgen::string::Ia5String::try_from(uri).unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extracts_spiffe_uri() {
        let der = client_cert_der_with_uri("spiffe://example/ci/example-repo");
        assert_eq!(extract_spiffe(&der).as_deref(), Some("spiffe://example/ci/example-repo"));
    }

    #[test]
    fn none_when_no_spiffe_san() {
        let der = client_cert_der_with_uri("https://example.com/not-spiffe");
        assert_eq!(extract_spiffe(&der), None);
    }
}
```

`src/issuance/policy.rs` tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientEntry;

    fn entries() -> Vec<ClientEntry> {
        vec![
            ClientEntry {
                spiffe: "spiffe://example/ci/example-repo".into(),
                allowed_scopes: vec!["github:example-org/example-repo".into()],
            },
            ClientEntry {
                spiffe: "spiffe://example/team/platform/*".into(),
                allowed_scopes: vec!["anthropic".into(), "github:example-org/*".into()],
            },
        ]
    }

    #[test]
    fn exact_match() {
        let p = ClientPolicy::new(&entries()).unwrap();
        let s = p.allowed_scopes("spiffe://example/ci/example-repo").unwrap();
        assert_eq!(s.to_scope_string(), "github:example-org/example-repo");
    }

    #[test]
    fn prefix_match() {
        let p = ClientPolicy::new(&entries()).unwrap();
        let s = p.allowed_scopes("spiffe://example/team/platform/build-42").unwrap();
        assert_eq!(s.to_scope_string(), "anthropic github:example-org/*");
    }

    #[test]
    fn no_match_is_none() {
        let p = ClientPolicy::new(&entries()).unwrap();
        assert!(p.allowed_scopes("spiffe://example/other/x").is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test issuance::`
Expected: FAIL.

- [ ] **Step 3: Write the implementations**

`src/issuance/mtls.rs`:
```rust
use x509_parser::prelude::*;

/// Return the first `spiffe://` URI SAN in a client leaf certificate (DER).
pub fn extract_spiffe(cert_der: &[u8]) -> Option<String> {
    let (_rem, cert) = X509Certificate::from_der(cert_der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    for gn in &san.value.general_names {
        if let GeneralName::URI(uri) = gn {
            if uri.starts_with("spiffe://") {
                return Some((*uri).to_string());
            }
        }
    }
    None
}
```

`src/issuance/policy.rs`:
```rust
use crate::config::ClientEntry;
use crate::scope::{ScopeError, ScopeSet};

struct Entry {
    // Either an exact identity or a prefix (trailing `*` stripped).
    matcher: Matcher,
    scopes: ScopeSet,
}

enum Matcher {
    Exact(String),
    Prefix(String),
}

pub struct ClientPolicy {
    entries: Vec<Entry>,
}

impl ClientPolicy {
    pub fn new(entries: &[ClientEntry]) -> Result<ClientPolicy, ScopeError> {
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let scopes = ScopeSet::parse(&e.allowed_scopes.join(" "))?;
            let matcher = match e.spiffe.strip_suffix('*') {
                Some(prefix) => Matcher::Prefix(prefix.to_string()),
                None => Matcher::Exact(e.spiffe.clone()),
            };
            out.push(Entry { matcher, scopes });
        }
        Ok(ClientPolicy { entries: out })
    }

    pub fn allowed_scopes(&self, spiffe: &str) -> Option<&ScopeSet> {
        // Exact matches win over prefix matches.
        for e in &self.entries {
            if let Matcher::Exact(id) = &e.matcher {
                if id == spiffe {
                    return Some(&e.scopes);
                }
            }
        }
        for e in &self.entries {
            if let Matcher::Prefix(p) = &e.matcher {
                if spiffe.starts_with(p) {
                    return Some(&e.scopes);
                }
            }
        }
        None
    }
}
```

Add `pub mod issuance;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test issuance::`
Expected: PASS (5 tests). If `san.value.general_names` / `GeneralName::URI` differ in x509-parser 0.18.1, adjust per `cargo doc -p x509-parser` (the research confirmed `GeneralName::URI(&str)` and `.value.general_names`). If `params.self_signed`/`cert.der()` differ in rcgen 0.14.8, check `cargo doc -p rcgen`.

- [ ] **Step 5: Commit**

```bash
git add src/issuance/ src/lib.rs
git commit -m "feat(issuance): SPIFFE SAN extraction + client scope policy"
```

---

### Task 8: Issuance server (OAuth2 token endpoint over mTLS + JWKS)

**Files:**
- Create: `src/issuance/server.rs`
- Modify: `src/issuance/mod.rs` (add `pub mod server;`)

**Interfaces:**
- Consumes: `Keystore` (Task 5), `Issuer` (Task 6), `ClientPolicy` (Task 7), `extract_spiffe` (Task 7), `ScopeSet`/`grant` (Task 2), config addrs/paths (Task 4).
- Produces:
  - `pub struct IssuanceState { pub keystore: std::sync::Arc<crate::keystore::Keystore>, pub issuer: crate::jwt::Issuer, pub policy: crate::issuance::policy::ClientPolicy }`
  - `pub fn build_mtls_server_config(server_cert_pem: &str, server_key_pem: &str, client_ca_pem: &str) -> Result<std::sync::Arc<rustls::ServerConfig>, ServerError>`
  - `pub fn token_router(state: std::sync::Arc<IssuanceState>) -> axum::Router` and `pub fn jwks_router(keystore: std::sync::Arc<crate::keystore::Keystore>) -> axum::Router`
  - `pub async fn serve_token(addr: std::net::SocketAddr, tls: std::sync::Arc<rustls::ServerConfig>, state: std::sync::Arc<IssuanceState>) -> Result<(), ServerError>` and `pub async fn serve_jwks(addr: std::net::SocketAddr, keystore: std::sync::Arc<crate::keystore::Keystore>) -> Result<(), ServerError>`
  - `pub fn install_crypto_provider()` — installs the rustls aws-lc-rs default provider (idempotent).
  - `pub enum ServerError` (thiserror).

**Note:** This task is validated by `cargo build`/`clippy` plus a focused test of the token handler logic via `axum::Router` `oneshot` where feasible; full mTLS wire behavior is covered by the Task 11 integration test. Keep handler logic thin over the already-tested pure pieces.

- [ ] **Step 1: Write the implementation**

`src/issuance/server.rs`:
```rust
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_server_mtls::PeerCertificates;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;

use crate::issuance::mtls::extract_spiffe;
use crate::issuance::policy::ClientPolicy;
use crate::jwt::Issuer;
use crate::keystore::Keystore;
use crate::scope::{grant, ScopeSet};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("tls config error: {0}")]
    Tls(String),
    #[error("bind/serve error: {0}")]
    Serve(String),
}

pub struct IssuanceState {
    pub keystore: Arc<Keystore>,
    pub issuer: Issuer,
    pub policy: ClientPolicy,
}

pub fn install_crypto_provider() {
    // Idempotent: ignore error if a provider is already installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(e.to_string()))
}

pub fn build_mtls_server_config(
    server_cert_pem: &str,
    server_key_pem: &str,
    client_ca_pem: &str,
) -> Result<Arc<ServerConfig>, ServerError> {
    let mut roots = RootCertStore::empty();
    for ca in certs_from_pem(client_ca_pem)? {
        roots.add(ca).map_err(|e| ServerError::Tls(e.to_string()))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| ServerError::Tls(e.to_string()))?;

    let server_certs = certs_from_pem(server_cert_pem)?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut server_key_pem.as_bytes())
        .map_err(|e| ServerError::Tls(e.to_string()))?
        .ok_or_else(|| ServerError::Tls("no private key in server key PEM".into()))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(serde::Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

async fn token_handler(
    State(state): State<Arc<IssuanceState>>,
    Extension(certs): Extension<PeerCertificates>,
    Form(form): Form<TokenForm>,
) -> axum::response::Response {
    if form.grant_type != "client_credentials" {
        return (StatusCode::BAD_REQUEST, "unsupported_grant_type").into_response();
    }
    // mTLS guarantees a client cert; extract SPIFFE identity.
    let Some(leaf) = certs.leaf() else {
        return (StatusCode::UNAUTHORIZED, "no client certificate").into_response();
    };
    let Some(spiffe) = extract_spiffe(leaf.as_ref()) else {
        return (StatusCode::UNAUTHORIZED, "no spiffe identity").into_response();
    };
    let Some(allowed) = state.policy.allowed_scopes(&spiffe) else {
        return (StatusCode::FORBIDDEN, "identity not authorized").into_response();
    };

    // Requested scopes default to the full allowed set.
    let requested = match &form.scope {
        Some(s) => match ScopeSet::parse(s) {
            Ok(rs) => rs,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid_scope").into_response(),
        },
        None => allowed.clone(),
    };
    if let Err(bad) = grant(allowed, &requested) {
        return (StatusCode::BAD_REQUEST, format!("invalid_scope: {bad}")).into_response();
    }

    let Some(km) = state.keystore.load() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "signing key unavailable").into_response();
    };
    let now = jsonwebtoken::get_current_timestamp();
    match state.issuer.mint(&km, &spiffe, &requested, now) {
        Ok(token) => Json(TokenResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in: state.issuer.ttl_secs(),
            scope: requested.to_scope_string(),
        })
        .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "mint failed").into_response(),
    }
}

async fn jwks_handler(State(keystore): State<Arc<Keystore>>) -> axum::response::Response {
    match keystore.load() {
        Some(km) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            km.jwks_json.clone(),
        )
            .into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "no keys").into_response(),
    }
}

pub fn token_router(state: Arc<IssuanceState>) -> Router {
    Router::new().route("/token", post(token_handler)).with_state(state)
}

pub fn jwks_router(keystore: Arc<Keystore>) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks_handler))
        .with_state(keystore)
}

pub async fn serve_token(
    addr: std::net::SocketAddr,
    tls: Arc<ServerConfig>,
    state: Arc<IssuanceState>,
) -> Result<(), ServerError> {
    let acceptor = axum_server_mtls::MtlsAcceptor::new(
        axum_server::tls_rustls::RustlsAcceptor::new(
            axum_server::tls_rustls::RustlsConfig::from_config(tls),
        ),
    );
    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(token_router(state).into_make_service())
        .await
        .map_err(|e| ServerError::Serve(e.to_string()))
}

pub async fn serve_jwks(
    addr: std::net::SocketAddr,
    keystore: Arc<Keystore>,
) -> Result<(), ServerError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ServerError::Serve(e.to_string()))?;
    axum::serve(listener, jwks_router(keystore).into_make_service())
        .await
        .map_err(|e| ServerError::Serve(e.to_string()))
}
```

Add `ttl_secs()` accessor to `Issuer` in `src/jwt.rs`:
```rust
impl Issuer {
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }
}
```

Add `pub mod server;` to `src/issuance/mod.rs`.

- [ ] **Step 2: Verify it builds & lints**

Run: `cargo build && cargo clippy --all-targets`
Expected: compiles. If `axum_server_mtls::MtlsAcceptor`/`PeerCertificates` or the `RustlsAcceptor`/`RustlsConfig` paths differ in the resolved versions, check `cargo doc -p axum-server-mtls -p axum-server` and adjust; the behavior (require client cert, read `certs.leaf()`, serve `/token` + JWKS) must be preserved. Ensure `axum`'s `Form` extractor is available (it is in the default features).

- [ ] **Step 3: Commit**

```bash
git add src/issuance/server.rs src/issuance/mod.rs src/jwt.rs
git commit -m "feat(issuance): mTLS OAuth2 client_credentials token endpoint + JWKS"
```

---

### Task 9: Proxy authorization via JWT

**Files:**
- Modify: `src/decision.rs`, `src/proxy.rs`
- Delete: `src/auth.rs` (Phase 1 `TokenMap`) — and remove `pub mod auth;` from `src/lib.rs`. Keep Bearer extraction by moving `extract_bearer` into `decision.rs` (or inline in proxy).

**Interfaces:**
- Consumes: `Verifier` (Task 6), `Keystore` (Task 5), `ScopeSet`/`Resource`/`permits` (Task 2), `resource::extract`/`ResourceKind` (Task 3), `Upstream` (Task 4).
- Produces:
  - `decision`: `pub fn extract_bearer(header: Option<&[u8]>) -> Option<String>` (returns the raw token or None), and `pub fn authorize(scopes: &ScopeSet, upstream: &Upstream, path: &str) -> bool` (applies the upstream's `resource` extractor to `path`, then `scopes.permits(&upstream.name, resource.as_ref())`).
  - `proxy`: `ProxyService` gains `verifier: crate::jwt::Verifier` and `keystore: std::sync::Arc<crate::keystore::Keystore>`; `ProxyService::new(router, verifier, keystore, secrets)`. `RequestCtx` unchanged (`upstream`, `secret`).

**Note:** Verifying a JWT needs the keystore (not a pure fn), so JWT verify lives in `request_filter`; `authorize` stays pure and unit-tested. This replaces the Phase 1 `decide()`.

- [ ] **Step 1: Write the failing test (authorize)**

Replace the `tests` module in `src/decision.rs` with:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
    use crate::resource::ResourceKind;
    use crate::scope::ScopeSet;
    use std::sync::Arc;

    fn upstream(name: &str, resource: Option<ResourceKind>) -> Arc<Upstream> {
        Arc::new(Upstream {
            name: name.into(),
            kind: UpstreamKind::Api,
            listen_host: format!("{name}.proxy"),
            origin: Origin { host: "h".into(), port: 443, tls: true, sni: "h".into() },
            secret_ref: "ref".into(),
            injection: Injection { header: "authorization".into(), scheme: InjectionScheme::Bearer },
            resource,
        })
    }

    #[test]
    fn extract_bearer_parses() {
        assert_eq!(extract_bearer(Some(b"Bearer abc")).as_deref(), Some("abc"));
        assert!(extract_bearer(None).is_none());
        assert!(extract_bearer(Some(b"Basic abc")).is_none());
    }

    #[test]
    fn authorize_unscoped() {
        let up = upstream("anthropic", None);
        let s = ScopeSet::parse("anthropic").unwrap();
        assert!(authorize(&s, &up, "/v1/messages"));
        let s2 = ScopeSet::parse("mistral").unwrap();
        assert!(!authorize(&s2, &up, "/v1/messages"));
    }

    #[test]
    fn authorize_resource_scoped() {
        let up = upstream("github", Some(ResourceKind::GithubRepo));
        let s = ScopeSet::parse("github:example-org/example-repo").unwrap();
        assert!(authorize(&s, &up, "/repos/example-org/example-repo/issues"));
        assert!(!authorize(&s, &up, "/repos/example-org/other/issues"));
        // Non-repo path on a scoped upstream: only a bare token authorizes.
        assert!(!authorize(&s, &up, "/user"));
        assert!(authorize(&ScopeSet::parse("github").unwrap(), &up, "/user"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test decision::`
Expected: FAIL (compile errors — old `decide`/`TokenMap` gone).

- [ ] **Step 3: Write the implementation**

Replace the non-test contents of `src/decision.rs` with:
```rust
use crate::config::Upstream;
use crate::resource::extract;
use crate::scope::ScopeSet;

/// Extract the raw bearer token (a JWT here) from an Authorization header value.
pub fn extract_bearer(header: Option<&[u8]>) -> Option<String> {
    let raw = header?;
    let text = std::str::from_utf8(raw).ok()?;
    let token = text.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Authorize a verified token's scopes against an upstream + request path.
pub fn authorize(scopes: &ScopeSet, upstream: &Upstream, path: &str) -> bool {
    let resource = upstream.resource.and_then(|kind| extract(kind, path));
    scopes.permits(&upstream.name, resource.as_ref())
}
```

Rewrite `src/proxy.rs` `request_filter` and `ProxyService`:
```rust
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

use crate::config::Upstream;
use crate::decision::{authorize, extract_bearer};
use crate::inject::inject;
use crate::jwt::Verifier;
use crate::keystore::Keystore;
use crate::router::Router;
use crate::secrets::{Secret, SecretProvider};

#[derive(Default)]
pub struct RequestCtx {
    pub upstream: Option<Arc<Upstream>>,
    pub secret: Option<Secret>,
}

pub struct ProxyService {
    pub router: Router,
    pub verifier: Verifier,
    pub keystore: Arc<Keystore>,
    pub secrets: Arc<dyn SecretProvider>,
}

impl ProxyService {
    pub fn new(
        router: Router,
        verifier: Verifier,
        keystore: Arc<Keystore>,
        secrets: Arc<dyn SecretProvider>,
    ) -> ProxyService {
        ProxyService { router, verifier, keystore, secrets }
    }
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let Some(host) = host else {
            session.respond_error_with_body(404, Bytes::from_static(b"unknown host")).await?;
            return Ok(true);
        };
        let Some(upstream) = self.router.resolve(&host) else {
            session.respond_error_with_body(404, Bytes::from_static(b"unknown host")).await?;
            return Ok(true);
        };

        // Verify the JWT.
        let auth = session
            .req_header()
            .headers
            .get("authorization")
            .map(|v| v.as_bytes().to_vec());
        let Some(token) = extract_bearer(auth.as_deref()) else {
            session.respond_error_with_body(401, Bytes::from_static(b"missing token")).await?;
            return Ok(true);
        };
        let Some(km) = self.keystore.load() else {
            session.respond_error_with_body(503, Bytes::from_static(b"keys unavailable")).await?;
            return Ok(true);
        };
        let scopes = match self.verifier.verify(&km, &token) {
            Ok(s) => s,
            Err(_) => {
                session.respond_error_with_body(401, Bytes::from_static(b"invalid token")).await?;
                return Ok(true);
            }
        };

        // Authorize by scope (+ resource path).
        let path = session.req_header().uri.path().to_string();
        if !authorize(&scopes, &upstream, &path) {
            session.respond_error_with_body(403, Bytes::from_static(b"not allowed")).await?;
            return Ok(true);
        }

        match self.secrets.get(&upstream.secret_ref).await {
            Ok(secret) => {
                ctx.secret = Some(secret);
                ctx.upstream = Some(upstream);
                Ok(false)
            }
            Err(e) => {
                log::error!("secret fetch failed for {}: {e}", upstream.name);
                session
                    .respond_error_with_body(502, Bytes::from_static(b"upstream secret unavailable"))
                    .await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let o = &upstream.origin;
        Ok(Box::new(HttpPeer::new((o.host.as_str(), o.port), o.tls, o.sni.clone())))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("authorization");
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let secret = ctx
            .secret
            .as_ref()
            .ok_or_else(|| Error::new_str("secret missing in ctx"))?;
        inject(upstream_request, &upstream.injection, secret.expose())
            .map_err(|_| Error::new_str("secret injection failed"))?;
        upstream_request
            .insert_header("host", upstream.origin.host.as_str())
            .map_err(|_| Error::new_str("failed to set host header"))?;
        Ok(())
    }
}
```

Delete `src/auth.rs` and remove `pub mod auth;` from `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test decision:: && cargo build`
Expected: decision tests PASS (3); crate builds. The Phase 1 `tests/api_egress.rs` will not compile yet (it uses the old `ProxyService::new` + tokens) — Task 11 rewrites it. If it blocks `cargo build --tests`, that's expected; `cargo build` (lib+bin) must pass here.

- [ ] **Step 5: Commit**

```bash
git add src/decision.rs src/proxy.rs src/lib.rs
git rm src/auth.rs
git commit -m "feat(proxy): JWT verification + scoped authorization; drop token map"
```

---

### Task 10: Binary wiring (keystore load + management servers)

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `Config` (Task 4), `Keystore`/`fetch` (Task 5), `Issuer`/`Verifier` (Task 6), `ClientPolicy` (Task 7), issuance `server` (Task 8), `ProxyService` (Task 9), Phase 1 `Router`, `GcpSecretProvider`, `CachingSecretProvider`.
- Produces: a runnable binary that loads keys, serves the proxy (Pingora) + the mTLS token endpoint + JWKS.

**Note:** The management stack (axum mTLS + JWKS + key refresh) runs on a dedicated Tokio runtime in a spawned thread with its OWN `GcpSecretProvider` (so no GCP client is shared across runtimes). Main blocks until the first key load succeeds, then runs Pingora. Verified by `cargo build` + Task 11.

- [ ] **Step 1: Write the implementation**

`src/main.rs`:
```rust
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;

use trust::config::Config;
use trust::issuance::policy::ClientPolicy;
use trust::issuance::server::{
    build_mtls_server_config, install_crypto_provider, serve_jwks, serve_token, IssuanceState,
};
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{fetch, Keystore};
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::gcp::GcpSecretProvider;
use trust::secrets::{CachingSecretProvider, SecretProvider};

fn main() {
    env_logger::init();

    let config_path = std::env::var("TRUST_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path).expect("failed to load config");

    let keystore = Arc::new(Keystore::new());

    // Management stack on its own runtime/thread with its own secret provider.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    {
        let keystore = keystore.clone();
        let config = config.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("management runtime");
            rt.block_on(async move {
                install_crypto_provider();

                let key_provider: Arc<dyn SecretProvider> = Arc::new(GcpSecretProvider::new());
                let km = fetch(key_provider.as_ref(), &config.auth.signing)
                    .await
                    .expect("failed to load signing key");
                keystore.store(km);
                ready_tx.send(()).expect("signal ready");

                // Background key refresh (rotation) every 10 minutes.
                {
                    let keystore = keystore.clone();
                    let provider = key_provider.clone();
                    let signing = config.auth.signing.clone();
                    tokio::spawn(async move {
                        let mut tick = tokio::time::interval(Duration::from_secs(600));
                        loop {
                            tick.tick().await;
                            match fetch(provider.as_ref(), &signing).await {
                                Ok(km) => keystore.store(km),
                                Err(e) => log::error!("key refresh failed: {e}"),
                            }
                        }
                    });
                }

                let issuer = Issuer::new(
                    config.auth.issuer.clone(),
                    config.auth.audience.clone(),
                    config.auth.signing.token_ttl,
                );
                let policy = ClientPolicy::new(&config.issuance.clients)
                    .expect("invalid issuance client policy");
                let state = Arc::new(IssuanceState { keystore: keystore.clone(), issuer, policy });

                let server_cert = std::fs::read_to_string(
                    config.tls.as_ref().map(|t| t.cert_path.as_str()).unwrap_or(""),
                )
                .expect("issuance needs a server cert (reuse [tls] cert/key)");
                let server_key = std::fs::read_to_string(
                    config.tls.as_ref().map(|t| t.key_path.as_str()).unwrap_or(""),
                )
                .expect("issuance needs a server key");
                let client_ca = std::fs::read_to_string(&config.issuance.client_ca_path)
                    .expect("read client CA");
                let tls = build_mtls_server_config(&server_cert, &server_key, &client_ca)
                    .expect("mtls server config");

                let token_addr = config.issuance.mtls_addr.parse().expect("mtls_addr");
                let jwks_addr = config.issuance.jwks_addr.parse().expect("jwks_addr");
                let jwks_ks = keystore.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_jwks(jwks_addr, jwks_ks).await {
                        log::error!("jwks server exited: {e}");
                    }
                });
                if let Err(e) = serve_token(token_addr, tls, state).await {
                    log::error!("token server exited: {e}");
                }
            });
        });
    }

    // Wait for the first key load so the verifier has keys before serving.
    ready_rx.recv().expect("management stack failed to load keys");

    let router = Router::new(&config.upstreams);
    let verifier = Verifier::new(config.auth.issuer.clone(), config.auth.audience.clone());
    let proxy_secrets: Arc<dyn SecretProvider> = Arc::new(CachingSecretProvider::new(
        Arc::new(GcpSecretProvider::new()),
        Duration::from_secs(300),
    ));
    let service = ProxyService::new(router, verifier, keystore, proxy_secrets);

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();
    let mut proxy = http_proxy_service(&server.configuration, service);
    if let Some(tcp) = &config.listen.tcp {
        proxy.add_tcp(tcp);
    }
    if let Some(tls) = &config.tls {
        let settings = TlsSettings::intermediate(&tls.cert_path, &tls.key_path)
            .expect("failed to build TLS settings");
        proxy.add_tls_with_settings(&tls.addr, None, settings);
    }
    server.add_service(proxy);
    log::info!("trust starting (config: {config_path})");
    server.run_forever();
}
```

- [ ] **Step 2: Verify it builds**

Run: `cargo build`
Expected: compiles. (`Config` must derive `Clone` — it does from Phase 1. If `tokio::runtime::Builder` needs the `rt-multi-thread`/`time` features, they're in tokio `full`.)

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(bin): load signing keys, run proxy + mTLS issuance + JWKS"
```

---

### Task 11: End-to-end integration test (mTLS mint → proxy authz)

**Files:**
- Replace: `tests/api_egress.rs` → `tests/jwt_egress.rs` (delete the old file; the old static-token test is obsolete).

**Interfaces:**
- Consumes the public API: `keystore`, `jwt::Issuer`, `scope::ScopeSet`, `proxy::ProxyService`, `router::Router`, `secrets::fake::FakeSecretProvider`, `issuance::server` helpers, config types.

**Note:** This is the wiring checkpoint; expect to iterate on timing/paths. It proves the whole chain. To keep it deterministic and avoid a second GCP dependency, the test builds a `KeyMaterial` directly from an `rcgen` P-256 key and `keystore.store()`s it (rather than going through GCP `fetch`). It exercises: (a) minting a JWT via the pure `Issuer` with a scoped set, then (b) using it against a running Pingora proxy with a mock upstream. A focused sub-test drives the mTLS `/token` axum router in-process with a client cert to prove SPIFFE→policy→scope issuance.

- [ ] **Step 1: Write the test**

`tests/jwt_egress.rs`:
```rust
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::prelude::*;
use trust::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{build_key_material, Keystore};
use trust::proxy::ProxyService;
use trust::resource::ResourceKind;
use trust::router::Router;
use trust::scope::ScopeSet;
use trust::secrets::fake::FakeSecretProvider;
use trust::secrets::SecretProvider;

fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_pem()
}

fn start_mock_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = received.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            sink.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, received)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn raw_request(proxy_port: u16, host: &str, path: &str, bearer: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(b) = bearer {
        req.push_str(&format!("Authorization: Bearer {b}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp)
}

fn scoped_upstream() -> Arc<Upstream> {
    Arc::new(Upstream {
        name: "github".into(),
        kind: UpstreamKind::Api,
        listen_host: "gh.test".into(),
        origin: Origin { host: "127.0.0.1".into(), port: 0, tls: false, sni: String::new() },
        secret_ref: "ref/gh".into(),
        injection: Injection { header: "authorization".into(), scheme: InjectionScheme::Bearer },
        resource: Some(ResourceKind::GithubRepo),
    })
}

#[test]
fn jwt_scoped_egress_end_to_end() {
    let (mock_port, upstream_reqs) = start_mock_upstream();

    // Shared keystore with a freshly generated signing key.
    let keystore = Arc::new(Keystore::new());
    keystore.store(build_key_material(&signing_key_pem(), None).unwrap());
    let km = keystore.load().unwrap();

    // Mint a token scoped to github:example-org/example-repo.
    let issuer = Issuer::new("trust".into(), "trust-proxy".into(), Duration::from_secs(3600));
    let now = jsonwebtoken::get_current_timestamp();
    let scopes = ScopeSet::parse("github:example-org/example-repo").unwrap();
    let token = issuer.mint(&km, "spiffe://example/ci/example-repo", &scopes, now).unwrap();
    let expired = issuer.mint(&km, "s", &scopes, now - 100_000).unwrap();

    // Build the proxy with the same keystore + a github upstream pointing at the mock.
    let mut up = (*scoped_upstream()).clone();
    up.origin.port = mock_port;
    let router = Router::new(&[Arc::new(up)]);
    let verifier = Verifier::new("trust".into(), "trust-proxy".into());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(FakeSecretProvider::new(&[("ref/gh", "INJECTED-TOKEN")]));
    let service = ProxyService::new(router, verifier, keystore, secrets);

    let proxy_port = free_port();
    let addr = format!("127.0.0.1:{proxy_port}");
    std::thread::spawn(move || {
        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut proxy = http_proxy_service(&server.configuration, service);
        proxy.add_tcp(&addr);
        server.add_service(proxy);
        server.run_forever();
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Missing token → 401.
    assert_eq!(raw_request(proxy_port, "gh.test", "/repos/example-org/example-repo/x", None).0, 401);
    // Expired token → 401.
    assert_eq!(raw_request(proxy_port, "gh.test", "/repos/example-org/example-repo/x", Some(&expired)).0, 401);
    // Valid token, repo OUT of scope → 403.
    assert_eq!(raw_request(proxy_port, "gh.test", "/repos/example-org/other/x", Some(&token)).0, 403);
    // Valid token, repo IN scope → 200.
    let (status, _) = raw_request(proxy_port, "gh.test", "/repos/example-org/example-repo/x", Some(&token));
    assert_eq!(status, 200);

    std::thread::sleep(Duration::from_millis(100));
    let reqs = upstream_reqs.lock().unwrap();
    let last = reqs.last().expect("upstream got a request");
    let lower = last.to_lowercase();
    assert!(lower.contains("authorization: bearer injected-token"), "secret not injected: {last}");
    assert!(!lower.contains(&token.to_lowercase()), "client JWT leaked upstream: {last}");
    assert!(lower.contains("host: 127.0.0.1"), "host not rewritten: {last}");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test --test jwt_egress -- --nocapture`
Expected: PASS. Iterate on harness details (startup wait, header casing) if needed — do not weaken the security assertions (403 out-of-scope, 401 expired, secret injected, JWT stripped).

- [ ] **Step 3: Add the issuance (mTLS) sub-test**

Append a second `#[test]` to `tests/jwt_egress.rs` that generates a client CA + client cert with a SPIFFE URI SAN via `rcgen` (see the pattern in `src/issuance/mtls.rs` tests and the plan's research), builds `IssuanceState` (keystore + `Issuer` + `ClientPolicy` from a `ClientEntry` granting `github:example-org/*`), and drives `issuance::server::token_router` in-process using `axum`'s testing (`tower::ServiceExt::oneshot`) with the `PeerCertificates` extension injected manually from the generated client cert DER — asserting: a `client_credentials` request for `scope=github:example-org/example-repo` returns 200 with a JWT whose `verify` yields that scope, and a request for `scope=mistral` returns 400 `invalid_scope`. Add `tower = "0.5"` to `[dev-dependencies]` for `oneshot`.

Run: `cargo test --test jwt_egress -- --nocapture`
Expected: both tests PASS. If wiring `PeerCertificates` in a `oneshot` proves impractical (its constructor may be private), instead assert the issuance decision path directly by testing `ClientPolicy` + `grant` + `Issuer::mint` composed (the mTLS transport itself is exercised by the proxy path and the `extract_spiffe` unit test). Document whichever approach you took in the report.

- [ ] **Step 4: Commit**

```bash
git rm tests/api_egress.rs
git add tests/jwt_egress.rs Cargo.toml Cargo.lock
git commit -m "test: end-to-end jwt scoped egress + issuance"
```

---

### Task 12: Verification, docs, README

**Files:**
- Modify: `README.md`; verification only otherwise.

- [ ] **Step 1: Full suite + lints**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all tests pass; no warnings; formatting clean. Fix anything reported (e.g. `#[allow(clippy::should_implement_trait)]` on any `from_str`; collapse nested ifs) and re-run.

- [ ] **Step 2: Update README**

Update `README.md`: replace the static-token auth section with JWT auth — the mint endpoint (mTLS OAuth2 client_credentials), scope grammar (`anthropic`, `github:owner/repo`, `github:owner/*`), SPIFFE identity → allowed scopes, JWKS/rotation, and updated client examples (curl with `Authorization: Bearer <jwt>`, `git -c http.extraHeader=...`). Note the `[auth]`/`[issuance]` config and that `[[tokens]]` is gone. Move git-cache to the roadmap as Phase 3.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README for JWT auth + mTLS issuance"
```

---

## Self-Review

**Spec coverage** (against `2026-07-06-trust-phase2-jwt-auth-design.md`):
- Scope model (`covers`, `permits`, one-segment wildcard) → Task 2. ✓
- Resource extraction (`github-repo`) → Task 3. ✓
- Config: `[auth]`/`[auth.signing]`/`[issuance]`/`[[issuance.clients]]`, per-upstream `resource`, tokens removed, TTL + scope validation → Task 4. ✓
- Keystore: load signing key from GCP `SecretProvider`, JWKS current+previous, hot swap → Task 5 (+ refresh loop in Task 10). ✓
- `jwt::Issuer`/`Verifier` (ES256, kid selection, iss/aud/exp) → Task 6. ✓
- SPIFFE SAN extraction + `ClientPolicy` (exact/prefix) → Task 7. ✓
- mTLS OAuth2 `client_credentials` token endpoint + JWKS endpoint + crypto-provider install → Task 8. ✓
- Proxy verify + scoped authz; strip/inject/rewrite unchanged; token map removed → Task 9. ✓
- Binary: load keys, management runtime, proxy + issuance + JWKS, rotation refresh → Task 10. ✓
- Rotation (current+previous verify, sign with current) → Tasks 5, 6, 10. ✓
- Error handling (401/403/502 proxy; 400/401/403 issuance; no secret/key logging) → Tasks 8, 9. ✓
- Testing (unit per module + mTLS issuance + e2e proxy authz) → Tasks 2–11. ✓
- git-cache out of scope → not implemented (deferred to Phase 3). ✓

**Placeholder scan:** No TBD/TODO; every code step has full code; version-fallback notes point to concrete `cargo doc` checks, not vague instructions.

**Type consistency:** `KeyMaterial` fields (`signing_kid`, `encoding`, `decoding`, `jwks_json`) used identically in Tasks 5/6/8/10/11. `Issuer::new(issuer, audience, ttl)` + `mint(km, sub, scopes, now)` + `ttl_secs()` and `Verifier::new(issuer, audience)` + `verify(km, token)` consistent across 6/8/9/10/11. `ScopeSet::parse`/`permits`/`to_scope_string`, `Scope::parse`, `covers`, `grant` consistent across 2/6/7/8/9. `Upstream.resource: Option<ResourceKind>` from Task 4 used in 3/9/11. `ProxyService::new(router, verifier, keystore, secrets)` consistent in 9/10/11. `ClientPolicy::new`/`allowed_scopes` consistent in 7/8/10. `extract_spiffe` consistent in 7/8.
