# trust Phase 1 — API Egress Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared proxy core (config, client-token auth, routing, authz, GCP secret resolution, injection) plus the `api` handler on Pingora, so clients authenticate with a Bearer proxy-token and have the real per-upstream secret injected before the request is forwarded.

**Architecture:** A single Pingora `ProxyHttp` service. `request_filter` runs a pure `decide()` (route by `Host` → validate Bearer token → authorize), short-circuiting 401/403/404; on success it fetches the upstream secret (GCP, cached) and stashes it in the per-request ctx. `upstream_peer` returns the configured origin. `upstream_request_filter` strips the client's `Authorization` and injects the resolved secret. Decision, injection, config, and caching are pure/unit-tested modules; the wired service is covered by one end-to-end integration test against a raw-TCP mock upstream.

**Tech Stack:** Rust (edition 2024), Pingora 0.8 (`proxy` + `openssl` features), `google-cloud-secretmanager-v1` 1.10, `serde`/`toml`, `url`, `base64`, `thiserror`, `async-trait`, `tokio`.

## Global Constraints

- Rust edition **2024**; crate name **`trust`** (library `trust` + binary `trust`).
- Pin Pingora to **`0.8`** with features **`["proxy", "openssl"]`** (pre-1.0; minor versions break).
- GCP crate: **`google-cloud-secretmanager-v1 = "1.10"`**, **`google-cloud-gax = "0.24"`**.
- **Secrets are never logged** (redact `Secret` `Debug`) and **never stored in the TOML** — config holds only GCP `secret_ref`s and the client token map.
- The **client's `Authorization` header MUST be removed** before the request is forwarded upstream.
- Every fallible boundary returns a typed error (`thiserror`); no `unwrap()` in request-path code except where a value is structurally guaranteed (documented inline).
- TDD: failing test → run (fail) → minimal impl → run (pass) → commit. Small, frequent commits.

---

### Task 1: Project setup & module skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`, `src/main.rs`
- Create (empty stubs): `src/config.rs`, `src/auth.rs`, `src/router.rs`, `src/decision.rs`, `src/inject.rs`, `src/proxy.rs`, `src/secrets/mod.rs`, `src/secrets/gcp.rs`, `src/secrets/fake.rs`

**Interfaces:**
- Produces: the crate compiles as lib + bin with all module paths declared, so later tasks only fill bodies.

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[package]
name = "trust"
version = "0.1.0"
edition = "2024"

[lib]
name = "trust"
path = "src/lib.rs"

[[bin]]
name = "trust"
path = "src/main.rs"

[dependencies]
pingora = { version = "0.8", features = ["proxy", "openssl"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
bytes = "1"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
url = "2"
base64 = "0.22"
thiserror = "1"
log = "0.4"
env_logger = "0.11"
google-cloud-secretmanager-v1 = "1.10"
google-cloud-gax = "0.24"
```

- [ ] **Step 2: Write `src/lib.rs`**

```rust
pub mod auth;
pub mod config;
pub mod decision;
pub mod inject;
pub mod proxy;
pub mod router;
pub mod secrets;
```

- [ ] **Step 3: Create empty module stubs**

`src/secrets/mod.rs`:
```rust
pub mod fake;
pub mod gcp;
```
Create `src/config.rs`, `src/auth.rs`, `src/router.rs`, `src/decision.rs`, `src/inject.rs`, `src/proxy.rs`, `src/secrets/gcp.rs`, `src/secrets/fake.rs` as empty files.

`src/main.rs`:
```rust
fn main() {}
```

- [ ] **Step 4: Verify it builds**

Run: `cargo build`
Expected: compiles (downloads Pingora + GCP crates). If a pinned version fails to resolve, run `cargo add pingora --features proxy,openssl` / `cargo add google-cloud-secretmanager-v1 google-cloud-gax` and let cargo pick the compatible patch, then re-run. Warnings about empty modules are fine.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/
git commit -m "chore: scaffold trust crate + module skeleton"
```

---

### Task 2: Config types, TOML load & validation

**Files:**
- Modify: `src/config.rs`

**Interfaces:**
- Produces:
  - `pub struct Config { pub listen: ListenConfig, pub tls: Option<TlsConfig>, pub tokens: Vec<TokenEntry>, pub upstreams: Vec<std::sync::Arc<Upstream>> }`
  - `pub struct ListenConfig { pub tcp: Option<String> }`
  - `pub struct TlsConfig { pub addr: String, pub cert_path: String, pub key_path: String }`
  - `pub struct TokenEntry { pub token: String, pub principal: String, pub allowed_upstreams: Vec<String> }`
  - `pub struct Upstream { pub name: String, pub kind: UpstreamKind, pub listen_host: String, pub origin: Origin, pub secret_ref: String, pub injection: Injection }`
  - `pub enum UpstreamKind { Api }` (git-cache added in Phase 2)
  - `pub struct Origin { pub host: String, pub port: u16, pub tls: bool, pub sni: String }`
  - `pub struct Injection { pub header: String, pub scheme: InjectionScheme }`
  - `pub enum InjectionScheme { Bearer, Basic, Raw }`
  - `pub fn Config::load(path: &str) -> Result<Config, ConfigError>`
  - `pub fn Config::from_str(toml_text: &str) -> Result<Config, ConfigError>`
  - `pub enum ConfigError` (thiserror)

- [ ] **Step 1: Write the failing test**

Add to `src/config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[listen]
tcp = "0.0.0.0:6191"

[[tokens]]
token = "client-abc"
principal = "team-x"
allowed_upstreams = ["anthropic"]

[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "anthropic.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/p/secrets/anthropic-key/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }
"#;

    #[test]
    fn parses_and_resolves_origin() {
        let cfg = Config::from_str(GOOD).unwrap();
        assert_eq!(cfg.upstreams.len(), 1);
        let up = &cfg.upstreams[0];
        assert_eq!(up.name, "anthropic");
        assert!(matches!(up.kind, UpstreamKind::Api));
        assert_eq!(up.origin.host, "api.anthropic.com");
        assert_eq!(up.origin.port, 443);
        assert!(up.origin.tls);
        assert_eq!(up.origin.sni, "api.anthropic.com");
        assert_eq!(up.injection.header, "x-api-key");
        assert!(matches!(up.injection.scheme, InjectionScheme::Raw));
    }

    #[test]
    fn rejects_duplicate_upstream_name() {
        let dup = GOOD.to_string() + r#"
[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "other.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/p/secrets/x/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }
"#;
        assert!(matches!(Config::from_str(&dup), Err(ConfigError::DuplicateUpstream(_))));
    }

    #[test]
    fn rejects_token_referencing_unknown_upstream() {
        let bad = GOOD.replace(r#"allowed_upstreams = ["anthropic"]"#, r#"allowed_upstreams = ["ghost"]"#);
        assert!(matches!(Config::from_str(&bad), Err(ConfigError::UnknownUpstreamRef { .. })));
    }

    #[test]
    fn rejects_non_http_origin() {
        let bad = GOOD.replace("https://api.anthropic.com", "ftp://api.anthropic.com");
        assert!(matches!(Config::from_str(&bad), Err(ConfigError::BadOrigin { .. })));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config::`
Expected: FAIL (compile error — `Config` etc. not defined).

- [ ] **Step 3: Write the implementation**

Replace `src/config.rs` head (above the `tests` module) with:
```rust
use std::collections::HashSet;
use std::sync::Arc;

use serde::Deserialize;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("duplicate upstream name: {0}")]
    DuplicateUpstream(String),
    #[error("duplicate listen_host: {0}")]
    DuplicateListenHost(String),
    #[error("token for principal {principal} references unknown upstream {name}")]
    UnknownUpstreamRef { principal: String, name: String },
    #[error("bad origin URL {url}: {reason}")]
    BadOrigin { url: String, reason: String },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamKind {
    Api,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InjectionScheme {
    Bearer,
    Basic,
    Raw,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Injection {
    pub header: String,
    pub scheme: InjectionScheme,
}

#[derive(Debug, Clone)]
pub struct Origin {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub sni: String,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub kind: UpstreamKind,
    pub listen_host: String,
    pub origin: Origin,
    pub secret_ref: String,
    pub injection: Injection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    pub tcp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub addr: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenEntry {
    pub token: String,
    pub principal: String,
    pub allowed_upstreams: Vec<String>,
}

// Raw deserialization mirror (origin stays a String until validated).
#[derive(Deserialize)]
struct RawUpstream {
    name: String,
    kind: UpstreamKind,
    listen_host: String,
    origin: String,
    secret_ref: String,
    injection: Injection,
}

#[derive(Deserialize)]
struct RawConfig {
    listen: ListenConfig,
    #[serde(default)]
    tls: Option<TlsConfig>,
    tokens: Vec<TokenEntry>,
    upstreams: Vec<RawUpstream>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub tls: Option<TlsConfig>,
    pub tokens: Vec<TokenEntry>,
    pub upstreams: Vec<Arc<Upstream>>,
}

fn parse_origin(raw: &str) -> Result<Origin, ConfigError> {
    let url = Url::parse(raw).map_err(|e| ConfigError::BadOrigin {
        url: raw.to_string(),
        reason: e.to_string(),
    })?;
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        other => {
            return Err(ConfigError::BadOrigin {
                url: raw.to_string(),
                reason: format!("unsupported scheme {other}"),
            });
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::BadOrigin {
            url: raw.to_string(),
            reason: "missing host".to_string(),
        })?
        .to_string();
    let port = url.port().unwrap_or(if tls { 443 } else { 80 });
    let sni = host.clone();
    Ok(Origin { host, port, tls, sni })
}

impl Config {
    pub fn load(path: &str) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Config::from_str(&text)
    }

    pub fn from_str(toml_text: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(toml_text)?;

        let mut names = HashSet::new();
        let mut hosts = HashSet::new();
        let mut upstreams = Vec::with_capacity(raw.upstreams.len());
        for ru in raw.upstreams {
            if !names.insert(ru.name.clone()) {
                return Err(ConfigError::DuplicateUpstream(ru.name));
            }
            if !hosts.insert(ru.listen_host.clone()) {
                return Err(ConfigError::DuplicateListenHost(ru.listen_host));
            }
            let origin = parse_origin(&ru.origin)?;
            upstreams.push(Arc::new(Upstream {
                name: ru.name,
                kind: ru.kind,
                listen_host: ru.listen_host,
                origin,
                secret_ref: ru.secret_ref,
                injection: ru.injection,
            }));
        }

        for t in &raw.tokens {
            for r in &t.allowed_upstreams {
                if !names.contains(r) {
                    return Err(ConfigError::UnknownUpstreamRef {
                        principal: t.principal.clone(),
                        name: r.clone(),
                    });
                }
            }
        }

        Ok(Config {
            listen: raw.listen,
            tls: raw.tls,
            tokens: raw.tokens,
            upstreams,
        })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test config::`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): TOML load + validation + origin parsing"
```

---

### Task 3: Secret trait, Secret type, caching wrapper, fake provider

**Files:**
- Modify: `src/secrets/mod.rs`, `src/secrets/fake.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `#[async_trait] pub trait SecretProvider: Send + Sync { async fn get(&self, secret_ref: &str) -> Result<Secret, SecretError>; }`
  - `pub struct Secret` with `pub fn new(String) -> Secret`, `pub fn expose(&self) -> &str`, redacted `Debug`, `Clone`.
  - `pub enum SecretError { NotFound(String), Backend(String) }` (thiserror)
  - `pub struct CachingSecretProvider` with `pub fn new(inner: Arc<dyn SecretProvider>, ttl: std::time::Duration) -> Self`, implementing `SecretProvider`.
  - `pub struct fake::FakeSecretProvider` with `pub fn new(pairs: &[(&str, &str)]) -> Self`, `pub fn calls(&self) -> usize`, implementing `SecretProvider`.

- [ ] **Step 1: Write the failing test**

Append to `src/secrets/mod.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::fake::FakeSecretProvider;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn fake_returns_secret_and_counts() {
        let p = FakeSecretProvider::new(&[("ref/a", "hunter2")]);
        let s = p.get("ref/a").await.unwrap();
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(p.calls(), 1);
        assert!(matches!(p.get("missing").await, Err(SecretError::NotFound(_))));
    }

    #[tokio::test]
    async fn caching_hits_inner_once_within_ttl() {
        let inner = Arc::new(FakeSecretProvider::new(&[("ref/a", "v1")]));
        let cache = CachingSecretProvider::new(inner.clone(), Duration::from_secs(60));
        assert_eq!(cache.get("ref/a").await.unwrap().expose(), "v1");
        assert_eq!(cache.get("ref/a").await.unwrap().expose(), "v1");
        assert_eq!(inner.calls(), 1, "second get should be served from cache");
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("topsecret".to_string());
        assert!(!format!("{s:?}").contains("topsecret"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test secrets::`
Expected: FAIL (types not defined).

- [ ] **Step 3: Write the implementation**

Prepend to `src/secrets/mod.rs` (above the module declarations `pub mod fake; pub mod gcp;` — keep those):
```rust
pub mod fake;
pub mod gcp;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("secret backend error: {0}")]
    Backend(String),
}

#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get(&self, secret_ref: &str) -> Result<Secret, SecretError>;
}

pub struct CachingSecretProvider {
    inner: Arc<dyn SecretProvider>,
    ttl: Duration,
    cache: Mutex<HashMap<String, (Secret, Instant)>>,
}

impl CachingSecretProvider {
    pub fn new(inner: Arc<dyn SecretProvider>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SecretProvider for CachingSecretProvider {
    async fn get(&self, secret_ref: &str) -> Result<Secret, SecretError> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some((secret, at)) = cache.get(secret_ref) {
                if at.elapsed() < self.ttl {
                    return Ok(secret.clone());
                }
            }
        }
        let secret = self.inner.get(secret_ref).await?;
        self.cache
            .lock()
            .unwrap()
            .insert(secret_ref.to_string(), (secret.clone(), Instant::now()));
        Ok(secret)
    }
}
```

Write `src/secrets/fake.rs`:
```rust
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use super::{Secret, SecretError, SecretProvider};

pub struct FakeSecretProvider {
    map: HashMap<String, String>,
    calls: AtomicUsize,
}

impl FakeSecretProvider {
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        Self {
            map: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SecretProvider for FakeSecretProvider {
    async fn get(&self, secret_ref: &str) -> Result<Secret, SecretError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.map
            .get(secret_ref)
            .map(|v| Secret::new(v.clone()))
            .ok_or_else(|| SecretError::NotFound(secret_ref.to_string()))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test secrets::`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/secrets/mod.rs src/secrets/fake.rs
git commit -m "feat(secrets): SecretProvider trait, redacted Secret, caching, fake"
```

---

### Task 4: GCP Secret Manager provider

**Files:**
- Modify: `src/secrets/gcp.rs`

**Interfaces:**
- Consumes: `SecretProvider`, `Secret`, `SecretError` from Task 3.
- Produces: `pub struct GcpSecretProvider` with `pub fn new() -> Self` (lazy client), implementing `SecretProvider`.

**Note:** This provider requires live GCP credentials + network, so it is **not** unit-tested here (the fake covers the trait; the integration test in Task 11 uses the fake). The client is lazily initialized via `tokio::sync::OnceCell` so it is built inside Pingora's async runtime, not at construction time. Verification for this task is `cargo build` + `cargo clippy`.

- [ ] **Step 1: Write the implementation**

Write `src/secrets/gcp.rs`:
```rust
use async_trait::async_trait;
use google_cloud_gax::error::rpc::Code;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use tokio::sync::OnceCell;

use super::{Secret, SecretError, SecretProvider};

pub struct GcpSecretProvider {
    client: OnceCell<SecretManagerService>,
}

impl GcpSecretProvider {
    pub fn new() -> Self {
        Self {
            client: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<&SecretManagerService, SecretError> {
        self.client
            .get_or_try_init(|| async {
                SecretManagerService::builder()
                    .build()
                    .await
                    .map_err(|e| SecretError::Backend(format!("client init: {e}")))
            })
            .await
    }
}

impl Default for GcpSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretProvider for GcpSecretProvider {
    async fn get(&self, secret_ref: &str) -> Result<Secret, SecretError> {
        let client = self.client().await?;
        let resp = client
            .access_secret_version()
            .set_name(secret_ref.to_string())
            .send()
            .await
            .map_err(|e| {
                if e.status().map(|s| s.code) == Some(Code::NotFound) {
                    SecretError::NotFound(secret_ref.to_string())
                } else {
                    SecretError::Backend(e.to_string())
                }
            })?;

        let payload = resp
            .payload
            .ok_or_else(|| SecretError::Backend("secret version had no payload".to_string()))?;
        let value = String::from_utf8(payload.data.to_vec())
            .map_err(|_| SecretError::Backend("secret payload is not valid UTF-8".to_string()))?;
        Ok(Secret::new(value))
    }
}
```

- [ ] **Step 2: Verify it builds & lints**

Run: `cargo build && cargo clippy --all-targets`
Expected: compiles. If `access_secret_version`/`set_name`/`send`/`Code` paths differ in the resolved patch version, run `cargo doc --open -p google-cloud-secretmanager-v1` and adjust to the resolved API (the shape — request builder → `.set_name` → `.send().await`, `resp.payload: Option<SecretPayload>`, `payload.data: Bytes` — is stable in 1.x).

- [ ] **Step 3: Commit**

```bash
git add src/secrets/gcp.rs
git commit -m "feat(secrets): GCP Secret Manager provider (lazy client)"
```

---

### Task 5: Client auth (token map + Bearer extraction)

**Files:**
- Modify: `src/auth.rs`

**Interfaces:**
- Consumes: `TokenEntry` from Task 2.
- Produces:
  - `pub struct Principal { pub id: String, pub allowed: Vec<String> }`
  - `pub struct TokenMap` with `pub fn new(entries: &[TokenEntry]) -> TokenMap` and `pub fn lookup(&self, token: &str) -> Option<std::sync::Arc<Principal>>`
  - `pub enum AuthError { Missing, Malformed }`
  - `pub fn extract_bearer(header: Option<&[u8]>) -> Result<String, AuthError>`

- [ ] **Step 1: Write the failing test**

Append to `src/auth.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenEntry;

    fn entries() -> Vec<TokenEntry> {
        vec![TokenEntry {
            token: "client-abc".into(),
            principal: "team-x".into(),
            allowed_upstreams: vec!["anthropic".into()],
        }]
    }

    #[test]
    fn extracts_bearer() {
        assert_eq!(extract_bearer(Some(b"Bearer client-abc")).unwrap(), "client-abc");
    }

    #[test]
    fn rejects_missing_and_malformed() {
        assert!(matches!(extract_bearer(None), Err(AuthError::Missing)));
        assert!(matches!(extract_bearer(Some(b"Basic xxx")), Err(AuthError::Malformed)));
        assert!(matches!(extract_bearer(Some(b"Bearer ")), Err(AuthError::Malformed)));
    }

    #[test]
    fn token_map_lookup() {
        let m = TokenMap::new(&entries());
        let p = m.lookup("client-abc").unwrap();
        assert_eq!(p.id, "team-x");
        assert_eq!(p.allowed, vec!["anthropic".to_string()]);
        assert!(m.lookup("nope").is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test auth::`
Expected: FAIL (undefined items).

- [ ] **Step 3: Write the implementation**

Prepend to `src/auth.rs`:
```rust
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::TokenEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Malformed,
}

pub struct TokenMap {
    by_token: HashMap<String, Arc<Principal>>,
}

impl TokenMap {
    pub fn new(entries: &[TokenEntry]) -> TokenMap {
        let by_token = entries
            .iter()
            .map(|e| {
                (
                    e.token.clone(),
                    Arc::new(Principal {
                        id: e.principal.clone(),
                        allowed: e.allowed_upstreams.clone(),
                    }),
                )
            })
            .collect();
        TokenMap { by_token }
    }

    pub fn lookup(&self, token: &str) -> Option<Arc<Principal>> {
        self.by_token.get(token).cloned()
    }
}

pub fn extract_bearer(header: Option<&[u8]>) -> Result<String, AuthError> {
    let raw = header.ok_or(AuthError::Missing)?;
    let text = std::str::from_utf8(raw).map_err(|_| AuthError::Malformed)?;
    let token = text.strip_prefix("Bearer ").ok_or(AuthError::Malformed)?;
    if token.is_empty() {
        return Err(AuthError::Malformed);
    }
    Ok(token.to_string())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test auth::`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/auth.rs
git commit -m "feat(auth): token map + Bearer extraction"
```

---

### Task 6: Router (Host → Upstream)

**Files:**
- Modify: `src/router.rs`

**Interfaces:**
- Consumes: `Upstream` from Task 2.
- Produces: `pub struct Router` with `pub fn new(upstreams: &[std::sync::Arc<Upstream>]) -> Router` and `pub fn resolve(&self, host: &str) -> Option<std::sync::Arc<Upstream>>` (matches on host with any `:port` stripped).

- [ ] **Step 1: Write the failing test**

Append to `src/router.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
    use std::sync::Arc;

    fn up(name: &str, host: &str) -> Arc<Upstream> {
        Arc::new(Upstream {
            name: name.into(),
            kind: UpstreamKind::Api,
            listen_host: host.into(),
            origin: Origin { host: "example.com".into(), port: 443, tls: true, sni: "example.com".into() },
            secret_ref: "ref".into(),
            injection: Injection { header: "x-api-key".into(), scheme: InjectionScheme::Raw },
        })
    }

    #[test]
    fn resolves_by_host_ignoring_port() {
        let r = Router::new(&[up("anthropic", "anthropic.proxy.internal")]);
        assert_eq!(r.resolve("anthropic.proxy.internal").unwrap().name, "anthropic");
        assert_eq!(r.resolve("anthropic.proxy.internal:8443").unwrap().name, "anthropic");
        assert!(r.resolve("unknown.host").is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test router::`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Prepend to `src/router.rs`:
```rust
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Upstream;

pub struct Router {
    by_host: HashMap<String, Arc<Upstream>>,
}

impl Router {
    pub fn new(upstreams: &[Arc<Upstream>]) -> Router {
        let by_host = upstreams
            .iter()
            .map(|u| (u.listen_host.clone(), u.clone()))
            .collect();
        Router { by_host }
    }

    pub fn resolve(&self, host: &str) -> Option<Arc<Upstream>> {
        let bare = host.split(':').next().unwrap_or(host);
        self.by_host.get(bare).cloned()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test router::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/router.rs
git commit -m "feat(router): Host header -> upstream resolution"
```

---

### Task 7: Decision (routing + auth + authz combined)

**Files:**
- Modify: `src/decision.rs`

**Interfaces:**
- Consumes: `Router` (Task 6), `TokenMap`/`extract_bearer` (Task 5), `Upstream` (Task 2).
- Produces:
  - `pub enum Decision { Reject { status: u16, body: &'static str }, Forward(std::sync::Arc<Upstream>) }`
  - `pub fn authorize(principal: &Principal, upstream: &Upstream) -> bool`
  - `pub fn decide(host: Option<&str>, auth: Option<&[u8]>, router: &Router, tokens: &TokenMap) -> Decision`

- [ ] **Step 1: Write the failing test**

Append to `src/decision.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenMap;
    use crate::config::{Injection, InjectionScheme, Origin, TokenEntry, Upstream, UpstreamKind};
    use crate::router::Router;
    use std::sync::Arc;

    fn up(name: &str, host: &str) -> Arc<Upstream> {
        Arc::new(Upstream {
            name: name.into(),
            kind: UpstreamKind::Api,
            listen_host: host.into(),
            origin: Origin { host: "example.com".into(), port: 443, tls: true, sni: "example.com".into() },
            secret_ref: "ref".into(),
            injection: Injection { header: "x-api-key".into(), scheme: InjectionScheme::Raw },
        })
    }

    fn setup() -> (Router, TokenMap) {
        let ups = vec![up("anthropic", "anthropic.proxy.internal")];
        let tokens = TokenMap::new(&[TokenEntry {
            token: "good".into(),
            principal: "team-x".into(),
            allowed_upstreams: vec!["anthropic".into()],
        }]);
        (Router::new(&ups), tokens)
    }

    #[test]
    fn unknown_host_404() {
        let (r, t) = setup();
        assert!(matches!(decide(Some("nope"), Some(b"Bearer good"), &r, &t), Decision::Reject { status: 404, .. }));
        assert!(matches!(decide(None, Some(b"Bearer good"), &r, &t), Decision::Reject { status: 404, .. }));
    }

    #[test]
    fn bad_token_401() {
        let (r, t) = setup();
        assert!(matches!(decide(Some("anthropic.proxy.internal"), None, &r, &t), Decision::Reject { status: 401, .. }));
        assert!(matches!(decide(Some("anthropic.proxy.internal"), Some(b"Bearer wrong"), &r, &t), Decision::Reject { status: 401, .. }));
    }

    #[test]
    fn not_allowed_403() {
        let ups = vec![up("anthropic", "anthropic.proxy.internal")];
        let tokens = TokenMap::new(&[TokenEntry {
            token: "good".into(),
            principal: "team-x".into(),
            allowed_upstreams: vec![], // allowed to nothing
        }]);
        let r = Router::new(&ups);
        assert!(matches!(decide(Some("anthropic.proxy.internal"), Some(b"Bearer good"), &r, &tokens), Decision::Reject { status: 403, .. }));
    }

    #[test]
    fn happy_path_forwards() {
        let (r, t) = setup();
        match decide(Some("anthropic.proxy.internal"), Some(b"Bearer good"), &r, &t) {
            Decision::Forward(u) => assert_eq!(u.name, "anthropic"),
            other => panic!("expected forward, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test decision::`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Prepend to `src/decision.rs`:
```rust
use std::sync::Arc;

use crate::auth::{extract_bearer, Principal, TokenMap};
use crate::config::Upstream;
use crate::router::Router;

#[derive(Debug)]
pub enum Decision {
    Reject { status: u16, body: &'static str },
    Forward(Arc<Upstream>),
}

pub fn authorize(principal: &Principal, upstream: &Upstream) -> bool {
    principal.allowed.iter().any(|name| name == &upstream.name)
}

pub fn decide(
    host: Option<&str>,
    auth: Option<&[u8]>,
    router: &Router,
    tokens: &TokenMap,
) -> Decision {
    let Some(host) = host else {
        return Decision::Reject { status: 404, body: "unknown host" };
    };
    let Some(upstream) = router.resolve(host) else {
        return Decision::Reject { status: 404, body: "unknown host" };
    };
    let token = match extract_bearer(auth) {
        Ok(t) => t,
        Err(_) => return Decision::Reject { status: 401, body: "missing or invalid token" },
    };
    let Some(principal) = tokens.lookup(&token) else {
        return Decision::Reject { status: 401, body: "missing or invalid token" };
    };
    if !authorize(&principal, &upstream) {
        return Decision::Reject { status: 403, body: "not allowed for this upstream" };
    }
    Decision::Forward(upstream)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test decision::`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/decision.rs
git commit -m "feat(decision): route+auth+authz decision function"
```

---

### Task 8: Injector

**Files:**
- Modify: `src/inject.rs`

**Interfaces:**
- Consumes: `Injection`/`InjectionScheme` (Task 2), `pingora_http::RequestHeader`.
- Produces:
  - `pub enum InjectError { InvalidValue }` (thiserror)
  - `pub fn inject(req: &mut pingora::http::RequestHeader, injection: &Injection, secret: &str) -> Result<(), InjectError>`

**Note:** With the umbrella `pingora` crate, `RequestHeader` is re-exported at `pingora::http::RequestHeader` (and also `pingora::prelude::RequestHeader`). Use `RequestHeader::build("GET", b"/", None)` to construct one in tests.

- [ ] **Step 1: Write the failing test**

Append to `src/inject.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme};
    use pingora::http::RequestHeader;

    fn req() -> RequestHeader {
        RequestHeader::build("GET", b"/", None).unwrap()
    }

    #[test]
    fn raw_injects_verbatim() {
        let mut r = req();
        let inj = Injection { header: "x-api-key".into(), scheme: InjectionScheme::Raw };
        inject(&mut r, &inj, "sekret").unwrap();
        assert_eq!(r.headers.get("x-api-key").unwrap().as_bytes(), b"sekret");
    }

    #[test]
    fn bearer_prefixes() {
        let mut r = req();
        let inj = Injection { header: "authorization".into(), scheme: InjectionScheme::Bearer };
        inject(&mut r, &inj, "sekret").unwrap();
        assert_eq!(r.headers.get("authorization").unwrap().as_bytes(), b"Bearer sekret");
    }

    #[test]
    fn basic_base64_encodes() {
        let mut r = req();
        let inj = Injection { header: "authorization".into(), scheme: InjectionScheme::Basic };
        inject(&mut r, &inj, "user:pass").unwrap();
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert_eq!(r.headers.get("authorization").unwrap().as_bytes(), b"Basic dXNlcjpwYXNz");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test inject::`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Prepend to `src/inject.rs`:
```rust
use base64::Engine;
use pingora::http::RequestHeader;

use crate::config::{Injection, InjectionScheme};

#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("invalid header value for injection")]
    InvalidValue,
}

pub fn inject(
    req: &mut RequestHeader,
    injection: &Injection,
    secret: &str,
) -> Result<(), InjectError> {
    let value = match injection.scheme {
        InjectionScheme::Bearer => format!("Bearer {secret}"),
        InjectionScheme::Basic => {
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(secret.as_bytes()))
        }
        InjectionScheme::Raw => secret.to_string(),
    };
    req.insert_header(injection.header.clone(), value)
        .map_err(|_| InjectError::InvalidValue)?;
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test inject::`
Expected: PASS (3 tests). If `pingora::http::RequestHeader` path is wrong for the resolved version, use `pingora::prelude::RequestHeader` (both are re-exported).

- [ ] **Step 5: Commit**

```bash
git add src/inject.rs
git commit -m "feat(inject): per-scheme secret header injection"
```

---

### Task 9: Proxy service (`ProxyHttp` impl)

**Files:**
- Modify: `src/proxy.rs`

**Interfaces:**
- Consumes: `Router` (6), `TokenMap` (5), `decide`/`Decision` (7), `inject` (8), `SecretProvider`/`Secret` (3), `Upstream` (2).
- Produces:
  - `pub struct RequestCtx { pub upstream: Option<Arc<Upstream>>, pub secret: Option<Secret> }`
  - `pub struct ProxyService { pub router: Router, pub tokens: TokenMap, pub secrets: Arc<dyn SecretProvider> }` with `pub fn new(router: Router, tokens: TokenMap, secrets: Arc<dyn SecretProvider>) -> ProxyService`
  - `impl ProxyHttp for ProxyService` (CTX = RequestCtx)

**Note:** This task has no unit test (Pingora `Session` has no public test constructor). It is validated by `cargo build` here and by the end-to-end integration test in Task 11. The decision/injection logic it calls is already unit-tested.

- [ ] **Step 1: Write the implementation**

Write `src/proxy.rs`:
```rust
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

use crate::config::Upstream;
use crate::decision::{decide, Decision};
use crate::inject::inject;
use crate::router::Router;
use crate::auth::TokenMap;
use crate::secrets::{Secret, SecretProvider};

#[derive(Default)]
pub struct RequestCtx {
    pub upstream: Option<Arc<Upstream>>,
    pub secret: Option<Secret>,
}

pub struct ProxyService {
    pub router: Router,
    pub tokens: TokenMap,
    pub secrets: Arc<dyn SecretProvider>,
}

impl ProxyService {
    pub fn new(router: Router, tokens: TokenMap, secrets: Arc<dyn SecretProvider>) -> ProxyService {
        ProxyService { router, tokens, secrets }
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
        let auth = session
            .req_header()
            .headers
            .get("authorization")
            .map(|v| v.as_bytes().to_vec());

        match decide(host.as_deref(), auth.as_deref(), &self.router, &self.tokens) {
            Decision::Reject { status, body } => {
                session
                    .respond_error_with_body(status, Bytes::from_static(body.as_bytes()))
                    .await?;
                Ok(true)
            }
            Decision::Forward(upstream) => {
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
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Guaranteed Some: request_filter returns Ok(false) only after setting this.
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let o = &upstream.origin;
        let peer = HttpPeer::new((o.host.as_str(), o.port), o.tls, o.sni.clone());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Strip the client's proxy token so it never leaks upstream.
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

        // Send the real upstream host, not the proxy listen_host.
        upstream_request
            .insert_header("host", upstream.origin.host.as_str())
            .map_err(|_| Error::new_str("failed to set host header"))?;
        Ok(())
    }
}
```

- [ ] **Step 2: Verify it builds & lints**

Run: `cargo build && cargo clippy --all-targets`
Expected: compiles. If `Error::new_str` is not found in the resolved version, use `pingora::Error::because(pingora::ErrorType::InternalError, "...", ...)` or the `Error::explain` constructor shown in `cargo doc -p pingora`. If `HttpPeer` is not re-exported at `pingora::upstreams::peer`, it is available via `pingora::prelude::HttpPeer`.

- [ ] **Step 3: Commit**

```bash
git add src/proxy.rs
git commit -m "feat(proxy): ProxyHttp impl (auth/route/inject/strip)"
```

---

### Task 10: Binary bootstrap (`main.rs`)

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `Config` (2), `Router` (6), `TokenMap` (5), `GcpSecretProvider`+`CachingSecretProvider` (3/4), `ProxyService` (9).
- Produces: runnable `trust` binary reading a config path from `TRUST_CONFIG` env (default `config.toml`).

**Note:** Wiring only; verified by a manual smoke run + the Task 11 integration test. Keep `main` synchronous — Pingora owns the runtime; the GCP client is built lazily inside it.

- [ ] **Step 1: Write the implementation**

Write `src/main.rs`:
```rust
use std::sync::Arc;
use std::time::Duration;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;

use trust::auth::TokenMap;
use trust::config::Config;
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::gcp::GcpSecretProvider;
use trust::secrets::{CachingSecretProvider, SecretProvider};

fn main() {
    env_logger::init();

    let config_path = std::env::var("TRUST_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path).expect("failed to load config");

    let router = Router::new(&config.upstreams);
    let tokens = TokenMap::new(&config.tokens);

    let base: Arc<dyn SecretProvider> = Arc::new(GcpSecretProvider::new());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(CachingSecretProvider::new(base, Duration::from_secs(300)));

    let service = ProxyService::new(router, tokens, secrets);

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
Expected: compiles. If `TlsSettings` path differs, check `cargo doc -p pingora` — it is `pingora::listeners::tls::TlsSettings` in 0.8 with the `openssl` feature.

- [ ] **Step 3: Manual smoke test**

Create `config.toml`:
```toml
[listen]
tcp = "127.0.0.1:6191"

[[tokens]]
token = "dev-token"
principal = "dev"
allowed_upstreams = ["httpbin"]

[[upstreams]]
name = "httpbin"
kind = "api"
listen_host = "httpbin.local"
origin = "https://httpbin.org"
secret_ref = "projects/PROJECT/secrets/dummy/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }
```
Run: `TRUST_CONFIG=config.toml cargo run` then in another shell:
`curl -s -o /dev/null -w "%{http_code}\n" -H "Host: httpbin.local" http://127.0.0.1:6191/get`
Expected: `502` (routing+auth path reached but no token → actually 401; with `-H "Authorization: Bearer dev-token"` you get 502 because the dummy GCP secret can't be fetched without real creds). A 401 without the token and 502 with it both confirm the pipeline is wired. Stop with Ctrl-C. Do **not** commit `config.toml` (add to `.gitignore`).

- [ ] **Step 4: Commit**

```bash
echo "/config.toml" >> .gitignore
git add src/main.rs .gitignore
git commit -m "feat(bin): server bootstrap (tcp+tls listeners, cached GCP secrets)"
```

---

### Task 11: End-to-end integration test

**Files:**
- Create: `tests/api_egress.rs`

**Interfaces:**
- Consumes the public API: `ProxyService::new`, `Router::new`, `TokenMap::new`, `Config`, `FakeSecretProvider`.

**Note:** This is the wiring checkpoint. It starts ONE Pingora server (in a background thread) with a `FakeSecretProvider`, points its single upstream at a raw-TCP mock that records the request it receives, and drives it with raw-TCP client requests. All cases run against the one server. Expect to iterate once on details (thread startup timing, exact header casing Pingora emits). Raw TCP is used deliberately so the `Host` header and connection target are fully controlled with zero extra deps.

- [ ] **Step 1: Write the test**

Write `tests/api_egress.rs`:
```rust
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::prelude::*;
use trust::auth::TokenMap;
use trust::config::{Injection, InjectionScheme, Origin, TokenEntry, Upstream, UpstreamKind};
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::fake::FakeSecretProvider;
use trust::secrets::SecretProvider;

/// Mock upstream: records the first request it receives, replies 200.
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
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            sink.lock().unwrap().push(req);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            );
        }
    });
    (port, received)
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Send a raw HTTP/1.1 request to the proxy; return (status_code, full_response).
fn raw_request(proxy_port: u16, host: &str, auth: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let mut req = format!("GET /v1/thing HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
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

#[test]
fn api_egress_end_to_end() {
    let (mock_port, upstream_reqs) = start_mock_upstream();

    let upstream = Arc::new(Upstream {
        name: "api".into(),
        kind: UpstreamKind::Api,
        listen_host: "api.test".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: mock_port,
            tls: false,
            sni: String::new(),
        },
        secret_ref: "ref/api".into(),
        injection: Injection { header: "x-api-key".into(), scheme: InjectionScheme::Raw },
    });

    let router = Router::new(&[upstream]);
    let tokens = TokenMap::new(&[TokenEntry {
        token: "good".into(),
        principal: "team".into(),
        allowed_upstreams: vec!["api".into()],
    }]);
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(FakeSecretProvider::new(&[("ref/api", "INJECTED-SECRET")]));
    let service = ProxyService::new(router, tokens, secrets);

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

    // Wait until the proxy is accepting connections.
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 404 unknown host.
    assert_eq!(raw_request(proxy_port, "nope.test", Some("Bearer good")).0, 404);
    // 401 missing token.
    assert_eq!(raw_request(proxy_port, "api.test", None).0, 401);
    // 401 wrong token.
    assert_eq!(raw_request(proxy_port, "api.test", Some("Bearer wrong")).0, 401);

    // 200 happy path.
    let (status, _resp) = raw_request(proxy_port, "api.test", Some("Bearer good"));
    assert_eq!(status, 200);

    // Give the mock a moment to record.
    std::thread::sleep(Duration::from_millis(100));
    let reqs = upstream_reqs.lock().unwrap();
    let last = reqs.last().expect("upstream received a request");
    let lower = last.to_lowercase();
    // Secret injected...
    assert!(lower.contains("x-api-key: injected-secret"), "missing injected secret: {last}");
    // ...and the client's proxy token stripped.
    assert!(!lower.contains("bearer good"), "client token leaked upstream: {last}");
    // ...and Host rewritten to the real upstream.
    assert!(lower.contains("host: 127.0.0.1"), "host not rewritten: {last}");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test --test api_egress -- --nocapture`
Expected: PASS. Common iterations if it fails:
- Increase the startup wait loop if the first request races the listener.
- Pingora may lowercase/normalize headers — the assertions already `.to_lowercase()`.
- If `run_forever` interferes with the test process on some platforms, confirm it's on its own thread (it is here).

- [ ] **Step 3: Commit**

```bash
git add tests/api_egress.rs
git commit -m "test: end-to-end api egress (route/auth/inject/strip)"
```

---

### Task 12: Full verification pass

**Files:** none (verification only).

- [ ] **Step 1: Run the whole suite**

Run: `cargo test`
Expected: all unit tests + the integration test PASS.

- [ ] **Step 2: Lint & format**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: no warnings; formatting clean. Fix anything reported, then re-run.

- [ ] **Step 3: Commit any fixups**

```bash
git add -A
git commit -m "chore: clippy/fmt cleanup for phase 1"
```

---

## Self-Review

**Spec coverage** (against `2026-07-06-trust-egress-proxy-design.md`):
- Config/TOML, no secrets in TOML → Task 2. ✓
- TokenMap → Task 5. ✓
- ClientAuth (Bearer for api) → Tasks 5 & 7. ✓
- Router (Host → upstream) → Task 6. ✓
- Authz → Task 7. ✓
- SecretProvider trait + GCP impl + TTL cache + fake for tests → Tasks 3 & 4. ✓
- Injector (per-host header + scheme) → Task 8. ✓
- ProxyService lifecycle: request_filter (404/401/403, strip Authorization), upstream_peer (origin + TLS/SNI), upstream_request_filter (fetch+inject, set Host), no api caching → Task 9. ✓
- Security invariants (token validated then discarded, secret never logged/never in config) → Secret redaction (Task 3), header strip (Task 9), `.gitignore` config (Task 10). ✓
- Testing: unit per component + fake provider + integration against mock upstream asserting strip/inject/authz → Tasks 2–11. ✓
- TLS termination with configured cert/key → Task 10. ✓
- Phase 2 (git-cache) intentionally **out of scope** — `UpstreamKind` has only `Api`; git-cache variant added later.

**Placeholder scan:** No TBD/TODO; every code step contains full code; version-fallback notes reference concrete `cargo doc`/`cargo add` actions, not vague "handle errors."

**Type consistency:** `Upstream`/`Origin`/`Injection`/`InjectionScheme`/`UpstreamKind`/`TokenEntry` (Task 2) reused verbatim in 5–11. `TokenMap::new`/`lookup` (5) match usage in 7/9/11. `Router::new`/`resolve` (6) match 7/9. `decide`/`Decision` (7) match 9. `inject` signature (8) matches call in 9. `SecretProvider::get`/`Secret::expose`/`CachingSecretProvider::new`/`FakeSecretProvider::new`/`calls` (3) match 4/9/10/11. `ProxyService::new(router, tokens, secrets)` (9) matches 10/11.
