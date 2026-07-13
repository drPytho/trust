use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use serde::Deserialize;
use url::Url;

use crate::resource::ResourceKind;

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
    #[error("bad origin URL {url}: {reason}")]
    BadOrigin { url: String, reason: String },
    #[error("invalid duration {value}")]
    BadDuration { value: String },
    #[error("invalid scope in issuance policy: {scope}")]
    BadScope { scope: String },
    #[error("issuance requires a [tls] section (server cert/key)")]
    MissingTls,
    #[error("git-cache upstream '{0}' is missing a [git] block (storage_path required)")]
    MissingGitBlock(String),
    #[error("git-cache upstream '{0}' must have resource = {{ kind = \"git-repo\" }}")]
    GitCacheNeedsGitRepoResource(String),
    #[error("api upstream '{0}' must not have a [git] block")]
    UnexpectedGitBlock(String),
    #[error("upstream '{0}' must configure exactly one of secret_ref or credential")]
    BadCredentialConfig(String),
    #[error("upstream '{0}' uses github-app credentials but [github_app] is missing")]
    MissingGithubApp(String),
    #[error("duplicate GitHub App installation owner: {0}")]
    DuplicateGithubOwner(String),
    #[error("invalid allowed method '{method}' on upstream '{upstream}'")]
    BadAllowedMethod { upstream: String, method: String },
    #[error("invalid GitHub App configuration: {0}")]
    BadGithubApp(String),
    #[error("github-app upstream '{0}' requires a GitHub repository resource")]
    GithubAppNeedsResource(String),
    #[error("gcp-adc upstream '{0}' requires Authorization bearer injection")]
    GcpAdcNeedsBearer(String),
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamKind {
    Api,
    GitCache,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitConfig {
    pub storage_path: String,
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CredentialSource {
    StaticSecret {
        secret_ref: String,
    },
    GithubApp {
        #[serde(default)]
        permissions: BTreeMap<String, String>,
        /// For Git smart-HTTP, GitHub expects the installation token as the
        /// password in HTTP Basic authentication (normally user `x-access-token`).
        #[serde(default)]
        basic_username: Option<String>,
    },
    GcpAdc {
        /// When set, rewrite absolute Artifact Registry metadata/tarball URLs
        /// back to this externally reachable proxy base URL.
        #[serde(default)]
        rewrite_registry_to: Option<String>,
    },
}

impl CredentialSource {
    pub fn provider_name(&self) -> &'static str {
        match self {
            CredentialSource::StaticSecret { .. } => "static-secret",
            CredentialSource::GithubApp { .. } => "github-app",
            CredentialSource::GcpAdc { .. } => "gcp-adc",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubInstallation {
    pub owner: String,
    pub installation_id: u64,
}

fn default_github_api_base() -> String {
    "https://api.github.com".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubAppConfig {
    pub app_id: u64,
    pub private_key_secret_ref: String,
    #[serde(default = "default_github_api_base")]
    pub api_base: String,
    #[serde(default)]
    pub installations: Vec<GithubInstallation>,
}

impl GithubAppConfig {
    pub fn installation_for(&self, owner: &str) -> Option<&GithubInstallation> {
        self.installations
            .iter()
            .find(|installation| installation.owner.eq_ignore_ascii_case(owner))
    }
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
    pub credential: CredentialSource,
    pub injection: Injection,
    pub resource: Option<ResourceKind>,
    pub git: Option<GitConfig>,
    pub allowed_methods: Vec<String>,
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

/// TOML shape: `resource = { kind = "github-repo" }`.
#[derive(Deserialize)]
struct RawResource {
    kind: ResourceKind,
}

// Raw deserialization mirror (origin stays a String until validated).
#[derive(Deserialize)]
struct RawUpstream {
    name: String,
    kind: UpstreamKind,
    listen_host: String,
    origin: String,
    #[serde(default)]
    secret_ref: Option<String>,
    #[serde(default)]
    credential: Option<CredentialSource>,
    injection: Injection,
    #[serde(default)]
    resource: Option<RawResource>,
    #[serde(default)]
    git: Option<GitConfig>,
    #[serde(default)]
    allowed_methods: Vec<String>,
}

#[derive(Deserialize)]
struct RawConfig {
    listen: ListenConfig,
    #[serde(default)]
    tls: Option<TlsConfig>,
    auth: RawAuth,
    issuance: IssuanceConfig,
    #[serde(default)]
    github_app: Option<GithubAppConfig>,
    upstreams: Vec<RawUpstream>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub tls: Option<TlsConfig>,
    pub auth: AuthConfig,
    pub issuance: IssuanceConfig,
    pub github_app: Option<GithubAppConfig>,
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
    Ok(Origin {
        host,
        port,
        tls,
        sni,
    })
}

impl Config {
    pub fn load(path: &str) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Config::from_str(&text)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(toml_text: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(toml_text)?;

        let mut names = HashSet::new();
        let mut hosts = HashSet::new();
        let mut upstreams = Vec::with_capacity(raw.upstreams.len());
        if let Some(github_app) = &raw.github_app {
            if github_app.app_id == 0 || github_app.private_key_secret_ref.is_empty() {
                return Err(ConfigError::BadGithubApp(
                    "app_id and private_key_secret_ref are required".to_string(),
                ));
            }
            let api_base = Url::parse(&github_app.api_base)
                .map_err(|error| ConfigError::BadGithubApp(format!("invalid api_base: {error}")))?;
            if !matches!(api_base.scheme(), "http" | "https") || api_base.host_str().is_none() {
                return Err(ConfigError::BadGithubApp(
                    "api_base must be an HTTP(S) URL".to_string(),
                ));
            }
            let mut owners = HashSet::new();
            for installation in &github_app.installations {
                if installation.installation_id == 0
                    || !crate::resource::safe_component(&installation.owner)
                {
                    return Err(ConfigError::BadGithubApp(format!(
                        "invalid installation for owner '{}'",
                        installation.owner
                    )));
                }
                let owner = installation.owner.to_ascii_lowercase();
                if !owners.insert(owner) {
                    return Err(ConfigError::DuplicateGithubOwner(
                        installation.owner.clone(),
                    ));
                }
            }
        }
        for ru in raw.upstreams {
            if !names.insert(ru.name.clone()) {
                return Err(ConfigError::DuplicateUpstream(ru.name));
            }
            if !hosts.insert(ru.listen_host.clone()) {
                return Err(ConfigError::DuplicateListenHost(ru.listen_host));
            }
            let origin = parse_origin(&ru.origin)?;
            let credential = match (ru.secret_ref, ru.credential) {
                (Some(secret_ref), None) => CredentialSource::StaticSecret { secret_ref },
                (None, Some(credential)) => credential,
                _ => return Err(ConfigError::BadCredentialConfig(ru.name)),
            };
            if matches!(credential, CredentialSource::GithubApp { .. }) && raw.github_app.is_none()
            {
                return Err(ConfigError::MissingGithubApp(ru.name));
            }
            if let CredentialSource::GithubApp { basic_username, .. } = &credential {
                if !matches!(
                    ru.resource,
                    Some(RawResource {
                        kind: ResourceKind::GithubRepo | ResourceKind::GitRepo
                    })
                ) {
                    return Err(ConfigError::GithubAppNeedsResource(ru.name));
                }
                if basic_username.as_deref().is_some_and(|username| {
                    username.is_empty()
                        || username
                            .bytes()
                            .any(|byte| byte == b':' || byte.is_ascii_control())
                }) {
                    return Err(ConfigError::BadGithubApp(
                        "basic_username must be a non-empty HTTP Basic username".to_string(),
                    ));
                }
            }
            if matches!(credential, CredentialSource::GcpAdc { .. })
                && (!ru.injection.header.eq_ignore_ascii_case("authorization")
                    || ru.injection.scheme != InjectionScheme::Bearer)
            {
                return Err(ConfigError::GcpAdcNeedsBearer(ru.name));
            }
            if let CredentialSource::GcpAdc {
                rewrite_registry_to: Some(base),
            } = &credential
            {
                let url = Url::parse(base).map_err(|error| ConfigError::BadOrigin {
                    url: base.clone(),
                    reason: format!("invalid rewrite_registry_to: {error}"),
                })?;
                if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                    return Err(ConfigError::BadOrigin {
                        url: base.clone(),
                        reason: "rewrite_registry_to must be an HTTP(S) URL".to_string(),
                    });
                }
            }
            let allowed_methods = ru
                .allowed_methods
                .into_iter()
                .map(|method| {
                    if method.is_empty()
                        || !method
                            .bytes()
                            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
                    {
                        Err(ConfigError::BadAllowedMethod {
                            upstream: ru.name.clone(),
                            method,
                        })
                    } else {
                        Ok(method)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Validate git-cache-specific rules.
            match ru.kind {
                UpstreamKind::GitCache => {
                    if ru.git.is_none() {
                        return Err(ConfigError::MissingGitBlock(ru.name));
                    }
                    if !matches!(
                        ru.resource,
                        Some(RawResource {
                            kind: ResourceKind::GitRepo
                        })
                    ) {
                        return Err(ConfigError::GitCacheNeedsGitRepoResource(ru.name));
                    }
                }
                UpstreamKind::Api => {
                    if ru.git.is_some() {
                        return Err(ConfigError::UnexpectedGitBlock(ru.name));
                    }
                }
            }

            upstreams.push(Arc::new(Upstream {
                name: ru.name,
                kind: ru.kind,
                listen_host: ru.listen_host,
                origin,
                credential,
                injection: ru.injection,
                resource: ru.resource.map(|r| r.kind),
                git: ru.git,
                allowed_methods,
            }));
        }

        // Parse token TTL.
        let token_ttl = humantime::parse_duration(&raw.auth.signing.token_ttl).map_err(|_| {
            ConfigError::BadDuration {
                value: raw.auth.signing.token_ttl.clone(),
            }
        })?;

        // Validate issuance client scopes.
        for c in &raw.issuance.clients {
            for s in &c.allowed_scopes {
                crate::scope::Scope::parse(s)
                    .map_err(|_| ConfigError::BadScope { scope: s.clone() })?;
            }
        }

        // [tls] is required because issuance reuses it for the mTLS server cert/key.
        if raw.tls.is_none() {
            return Err(ConfigError::MissingTls);
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

        Ok(Config {
            listen: raw.listen,
            tls: raw.tls,
            auth,
            issuance: raw.issuance,
            github_app: raw.github_app,
            upstreams,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[listen]
tcp = "0.0.0.0:6191"

[tls]
addr = "0.0.0.0:6443"
cert_path = "/etc/trust/server.crt"
key_path = "/etc/trust/server.key"

[auth]
issuer = "https://trust.pit.internal/"
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
spiffe = "spiffe://pit/ci/pit-ts"
allowed_scopes = ["github:pitorg/pit-ts"]

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
        assert_eq!(cfg.auth.issuer, "https://trust.pit.internal/");
        assert_eq!(cfg.auth.audience, "trust-proxy");
        assert_eq!(
            cfg.auth.signing.token_ttl,
            std::time::Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(cfg.issuance.clients.len(), 1);
        assert_eq!(cfg.issuance.clients[0].spiffe, "spiffe://pit/ci/pit-ts");
        assert!(cfg.upstreams[0].resource.is_none());
        assert!(matches!(
            cfg.upstreams[1].resource,
            Some(crate::resource::ResourceKind::GithubRepo)
        ));
    }

    #[test]
    fn rejects_bad_ttl() {
        let bad = GOOD.replace(r#"token_ttl = "7d""#, r#"token_ttl = "banana""#);
        assert!(matches!(
            Config::from_str(&bad),
            Err(ConfigError::BadDuration { .. })
        ));
    }

    #[test]
    fn rejects_bad_allowed_scope() {
        let bad = GOOD.replace(
            r#"allowed_scopes = ["github:pitorg/pit-ts"]"#,
            r#"allowed_scopes = ["bad:too/many/parts"]"#,
        );
        assert!(matches!(
            Config::from_str(&bad),
            Err(ConfigError::BadScope { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_upstream_name() {
        let dup = GOOD.to_string()
            + r#"
[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "dup.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/p/secrets/x/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }
"#;
        assert!(matches!(
            Config::from_str(&dup),
            Err(ConfigError::DuplicateUpstream(_))
        ));
    }

    #[test]
    fn rejects_missing_tls() {
        let no_tls = GOOD
            .replace(
                "[tls]\naddr = \"0.0.0.0:6443\"\ncert_path = \"/etc/trust/server.crt\"\nkey_path = \"/etc/trust/server.key\"\n\n",
                "",
            );
        assert!(matches!(
            Config::from_str(&no_tls),
            Err(ConfigError::MissingTls)
        ));
    }

    // ── git-cache upstream tests ─────────────────────────────────────────────

    const GIT_CACHE_UPSTREAM: &str = r#"
[[upstreams]]
name = "git-mirror"
kind = "git-cache"
listen_host = "git.proxy.internal"
origin = "https://github.com"
secret_ref = "projects/p/secrets/git/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "git-repo" }
git = { storage_path = "/m" }
"#;

    #[test]
    fn git_cache_upstream_parses() {
        let toml = GOOD.to_string() + GIT_CACHE_UPSTREAM;
        let cfg = Config::from_str(&toml).unwrap();
        let up = cfg
            .upstreams
            .iter()
            .find(|u| u.name == "git-mirror")
            .unwrap();
        assert_eq!(up.kind, UpstreamKind::GitCache);
        let git = up.git.as_ref().expect("git block should be Some");
        assert_eq!(git.storage_path, "/m");
    }

    #[test]
    fn git_cache_without_git_block_errors() {
        let upstream_no_git = r#"
[[upstreams]]
name = "git-mirror"
kind = "git-cache"
listen_host = "git.proxy.internal"
origin = "https://github.com"
secret_ref = "projects/p/secrets/git/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "git-repo" }
"#;
        let toml = GOOD.to_string() + upstream_no_git;
        assert!(matches!(
            Config::from_str(&toml),
            Err(ConfigError::MissingGitBlock(_))
        ));
    }

    #[test]
    fn git_cache_without_git_repo_resource_errors() {
        let upstream_no_resource = r#"
[[upstreams]]
name = "git-mirror"
kind = "git-cache"
listen_host = "git.proxy.internal"
origin = "https://github.com"
secret_ref = "projects/p/secrets/git/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
git = { storage_path = "/m" }
"#;
        let toml = GOOD.to_string() + upstream_no_resource;
        assert!(matches!(
            Config::from_str(&toml),
            Err(ConfigError::GitCacheNeedsGitRepoResource(_))
        ));

        let upstream_wrong_resource = r#"
[[upstreams]]
name = "git-mirror"
kind = "git-cache"
listen_host = "git.proxy.internal"
origin = "https://github.com"
secret_ref = "projects/p/secrets/git/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-repo" }
git = { storage_path = "/m" }
"#;
        let toml2 = GOOD.to_string() + upstream_wrong_resource;
        assert!(matches!(
            Config::from_str(&toml2),
            Err(ConfigError::GitCacheNeedsGitRepoResource(_))
        ));
    }

    #[test]
    fn api_upstream_with_git_block_errors() {
        let upstream_api_git = r#"
[[upstreams]]
name = "extra-api"
kind = "api"
listen_host = "extra.proxy.internal"
origin = "https://api.example.com"
secret_ref = "projects/p/secrets/extra/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
git = { storage_path = "/m" }
"#;
        let toml = GOOD.to_string() + upstream_api_git;
        assert!(matches!(
            Config::from_str(&toml),
            Err(ConfigError::UnexpectedGitBlock(_))
        ));
    }

    #[test]
    fn parses_multi_installation_github_app_and_gcp_adc() {
        let dynamic = r#"
[github_app]
app_id = 123
private_key_secret_ref = "projects/p/secrets/github-app-key/versions/latest"

[[github_app.installations]]
owner = "org-one"
installation_id = 111

[[github_app.installations]]
owner = "org-two"
installation_id = 222

[[upstreams]]
name = "github-dynamic"
kind = "api"
listen_host = "github-dynamic.proxy.internal"
origin = "https://api.github.com"
credential = { kind = "github-app", permissions = { contents = "read" } }
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-repo" }

[[upstreams]]
name = "npm-artifacts"
kind = "api"
listen_host = "npm.proxy.internal"
origin = "https://europe-north1-npm.pkg.dev"
credential = { kind = "gcp-adc", rewrite_registry_to = "https://npm.proxy.internal" }
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "artifact-registry-repo" }
allowed_methods = ["GET", "HEAD"]
"#;
        let cfg = Config::from_str(&(GOOD.to_string() + dynamic)).unwrap();
        let app = cfg.github_app.unwrap();
        assert_eq!(
            app.installation_for("ORG-ONE").unwrap().installation_id,
            111
        );
        assert_eq!(
            app.installation_for("org-two").unwrap().installation_id,
            222
        );
        let npm = cfg
            .upstreams
            .iter()
            .find(|upstream| upstream.name == "npm-artifacts")
            .unwrap();
        assert_eq!(npm.allowed_methods, ["GET", "HEAD"]);
        assert!(matches!(npm.credential, CredentialSource::GcpAdc { .. }));
    }

    #[test]
    fn rejects_duplicate_github_owner_case_insensitively() {
        let duplicate = r#"
[github_app]
app_id = 123
private_key_secret_ref = "key"

[[github_app.installations]]
owner = "Org-One"
installation_id = 111

[[github_app.installations]]
owner = "org-one"
installation_id = 222
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + duplicate)),
            Err(ConfigError::DuplicateGithubOwner(_))
        ));
    }

    #[test]
    fn rejects_github_credentials_without_app_config() {
        let upstream = r#"
[[upstreams]]
name = "github-dynamic"
kind = "api"
listen_host = "github-dynamic.proxy.internal"
origin = "https://api.github.com"
credential = { kind = "github-app" }
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-repo" }
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + upstream)),
            Err(ConfigError::MissingGithubApp(_))
        ));
    }
}
