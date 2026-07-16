use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use serde::Deserialize;
use url::Url;

use crate::resource::ResourceKind;

pub const AUDIT_UNMATCHED_METRICS_NAME: &str = "audit-unmatched";

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
    #[error("inject upstream '{0}' is missing injection configuration")]
    MissingInjection(String),
    #[error("passthrough upstream '{0}' must not configure credentials or injection")]
    PassthroughConfig(String),
    #[error("git-cache upstream '{0}' cannot use passthrough mode")]
    PassthroughGitCache(String),
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
    #[error(
        "GitHub CLI upstream '{0}' must be an API inject upstream using GitHub App bearer credentials"
    )]
    BadGithubCliUpstream(String),
    #[error("gcp-adc upstream '{0}' requires Authorization bearer injection")]
    GcpAdcNeedsBearer(String),
    #[error("CONNECT upstream '{0}' must use api kind and passthrough mode")]
    ConnectRequiresPassthrough(String),
    #[error("CONNECT upstream '{0}' cannot configure resource or allowed_methods policies")]
    ConnectPolicyUnsupported(String),
    #[error("CONNECT upstream '{0}' requires a [forward_proxy] listener")]
    ConnectWithoutListener(String),
    #[error("duplicate CONNECT destination authority: {0}")]
    DuplicateConnectAuthority(String),
    #[error("invalid forward proxy configuration: {0}")]
    BadForwardProxy(String),
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamKind {
    Api,
    GitCache,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    #[default]
    Inject,
    Passthrough,
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
    pub mode: UpstreamMode,
    pub credential: Option<CredentialSource>,
    pub injection: Option<Injection>,
    pub resource: Option<ResourceKind>,
    pub git: Option<GitConfig>,
    pub allowed_methods: Vec<String>,
    pub allow_connect: bool,
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

#[derive(Debug, Clone)]
pub struct ForwardProxyConfig {
    pub addr: String,
    pub tls: bool,
    pub connect_timeout: std::time::Duration,
    pub idle_timeout: std::time::Duration,
    pub max_tunnel_duration: std::time::Duration,
    pub max_concurrent_tunnels: usize,
    pub allow_private_ips: bool,
    pub audit_unmatched: Option<AuditUnmatchedConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuditUnmatchedConfig {
    pub scope: String,
}

fn default_true() -> bool {
    true
}

fn default_connect_timeout() -> String {
    "10s".to_string()
}

fn default_idle_timeout() -> String {
    "5m".to_string()
}

fn default_max_tunnel_duration() -> String {
    "1h".to_string()
}

fn default_max_concurrent_tunnels() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize)]
struct RawForwardProxyConfig {
    addr: String,
    #[serde(default = "default_true")]
    tls: bool,
    #[serde(default = "default_connect_timeout")]
    connect_timeout: String,
    #[serde(default = "default_idle_timeout")]
    idle_timeout: String,
    #[serde(default = "default_max_tunnel_duration")]
    max_tunnel_duration: String,
    #[serde(default = "default_max_concurrent_tunnels")]
    max_concurrent_tunnels: usize,
    #[serde(default)]
    allow_private_ips: bool,
    #[serde(default)]
    audit_unmatched: Option<AuditUnmatchedConfig>,
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
    mode: UpstreamMode,
    #[serde(default)]
    secret_ref: Option<String>,
    #[serde(default)]
    credential: Option<CredentialSource>,
    #[serde(default)]
    injection: Option<Injection>,
    #[serde(default)]
    resource: Option<RawResource>,
    #[serde(default)]
    git: Option<GitConfig>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allow_connect: bool,
}

#[derive(Deserialize)]
struct RawConfig {
    listen: ListenConfig,
    #[serde(default)]
    tls: Option<TlsConfig>,
    auth: RawAuth,
    issuance: IssuanceConfig,
    #[serde(default)]
    forward_proxy: Option<RawForwardProxyConfig>,
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
    pub forward_proxy: Option<ForwardProxyConfig>,
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
        let mut connect_authorities = HashSet::new();
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
            let (credential, injection) = match ru.mode {
                UpstreamMode::Inject => {
                    let credential = match (ru.secret_ref, ru.credential) {
                        (Some(secret_ref), None) => CredentialSource::StaticSecret { secret_ref },
                        (None, Some(credential)) => credential,
                        _ => return Err(ConfigError::BadCredentialConfig(ru.name)),
                    };
                    let injection = ru
                        .injection
                        .ok_or_else(|| ConfigError::MissingInjection(ru.name.clone()))?;
                    (Some(credential), Some(injection))
                }
                UpstreamMode::Passthrough => {
                    if ru.secret_ref.is_some() || ru.credential.is_some() || ru.injection.is_some()
                    {
                        return Err(ConfigError::PassthroughConfig(ru.name));
                    }
                    (None, None)
                }
            };
            if matches!(credential, Some(CredentialSource::GithubApp { .. }))
                && raw.github_app.is_none()
            {
                return Err(ConfigError::MissingGithubApp(ru.name));
            }
            if let Some(CredentialSource::GithubApp { basic_username, .. }) = &credential {
                if !matches!(
                    ru.resource,
                    Some(RawResource {
                        kind: ResourceKind::GithubRepo
                            | ResourceKind::GithubCliRepo
                            | ResourceKind::GitRepo
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
            if matches!(
                ru.resource,
                Some(RawResource {
                    kind: ResourceKind::GithubCliRepo
                })
            ) && (ru.kind != UpstreamKind::Api
                || ru.mode != UpstreamMode::Inject
                || !matches!(
                    credential,
                    Some(CredentialSource::GithubApp {
                        basic_username: None,
                        ..
                    })
                )
                || !matches!(
                    injection,
                    Some(Injection {
                        ref header,
                        scheme: InjectionScheme::Bearer,
                    }) if header.eq_ignore_ascii_case("authorization")
                ))
            {
                return Err(ConfigError::BadGithubCliUpstream(ru.name));
            }
            if matches!(credential, Some(CredentialSource::GcpAdc { .. }))
                && !matches!(
                    injection,
                    Some(Injection {
                        ref header,
                        scheme: InjectionScheme::Bearer,
                    }) if header.eq_ignore_ascii_case("authorization")
                )
            {
                return Err(ConfigError::GcpAdcNeedsBearer(ru.name));
            }
            if let Some(CredentialSource::GcpAdc {
                rewrite_registry_to: Some(base),
            }) = &credential
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

            if ru.allow_connect {
                if ru.kind != UpstreamKind::Api || ru.mode != UpstreamMode::Passthrough {
                    return Err(ConfigError::ConnectRequiresPassthrough(ru.name));
                }
                if ru.resource.is_some() || !allowed_methods.is_empty() {
                    return Err(ConfigError::ConnectPolicyUnsupported(ru.name));
                }
                if raw.forward_proxy.is_none() {
                    return Err(ConfigError::ConnectWithoutListener(ru.name));
                }
                let authority = format!("{}:{}", origin.host.to_ascii_lowercase(), origin.port);
                if !connect_authorities.insert(authority.clone()) {
                    return Err(ConfigError::DuplicateConnectAuthority(authority));
                }
            }

            // Validate git-cache-specific rules.
            match ru.kind {
                UpstreamKind::GitCache => {
                    if ru.mode == UpstreamMode::Passthrough {
                        return Err(ConfigError::PassthroughGitCache(ru.name));
                    }
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
                mode: ru.mode,
                credential,
                injection,
                resource: ru.resource.map(|r| r.kind),
                git: ru.git,
                allowed_methods,
                allow_connect: ru.allow_connect,
            }));
        }

        let forward_proxy = raw
            .forward_proxy
            .map(|forward| {
                let parse_duration = |value: &str| {
                    humantime::parse_duration(value)
                        .ok()
                        .filter(|duration| !duration.is_zero())
                        .ok_or_else(|| ConfigError::BadDuration {
                            value: value.to_string(),
                        })
                };
                if let Some(audit) = &forward.audit_unmatched {
                    if audit.scope.is_empty()
                        || !audit.scope.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                    {
                        return Err(ConfigError::BadForwardProxy(
                            "audit_unmatched.scope must be a bare scope name containing only letters, numbers, '.', '-', or '_'"
                                .to_string(),
                        ));
                    }
                    if names.contains(&audit.scope) {
                        return Err(ConfigError::BadForwardProxy(format!(
                            "audit_unmatched.scope '{}' must not reuse a configured upstream name",
                            audit.scope
                        )));
                    }
                    if names.contains(AUDIT_UNMATCHED_METRICS_NAME) {
                        return Err(ConfigError::BadForwardProxy(
                            "upstream name 'audit-unmatched' is reserved while audit_unmatched is enabled"
                                .to_string(),
                        ));
                    }
                }
                Ok::<_, ConfigError>(ForwardProxyConfig {
                    addr: forward.addr,
                    tls: forward.tls,
                    connect_timeout: parse_duration(&forward.connect_timeout)?,
                    idle_timeout: parse_duration(&forward.idle_timeout)?,
                    max_tunnel_duration: parse_duration(&forward.max_tunnel_duration)?,
                    max_concurrent_tunnels: if forward.max_concurrent_tunnels == 0 {
                        return Err(ConfigError::BadForwardProxy(
                            "max_concurrent_tunnels must be greater than zero".to_string(),
                        ));
                    } else {
                        forward.max_concurrent_tunnels
                    },
                    allow_private_ips: forward.allow_private_ips,
                    audit_unmatched: forward.audit_unmatched,
                })
            })
            .transpose()?;

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
            forward_proxy,
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
        assert_eq!(
            cfg.auth.signing.token_ttl,
            std::time::Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(cfg.issuance.clients.len(), 1);
        assert_eq!(
            cfg.issuance.clients[0].spiffe,
            "spiffe://example/ci/example-repo"
        );
        assert!(cfg.upstreams[0].resource.is_none());
        assert_eq!(cfg.upstreams[0].mode, UpstreamMode::Inject);
        assert!(matches!(
            cfg.upstreams[1].resource,
            Some(crate::resource::ResourceKind::GithubRepo)
        ));
    }

    #[test]
    fn parses_linear_personal_api_key_upstream() {
        let cfg = Config::from_str(include_str!("../examples/linear-js/config.toml")).unwrap();
        let upstream = cfg
            .upstreams
            .iter()
            .find(|upstream| upstream.name == "linear")
            .expect("Linear upstream should be configured");

        assert_eq!(upstream.origin.host, "api.linear.app");
        assert_eq!(upstream.allowed_methods, ["POST"]);
        assert!(matches!(
            upstream.credential,
            Some(CredentialSource::StaticSecret { .. })
        ));
        assert!(matches!(
            upstream.injection,
            Some(Injection {
                ref header,
                scheme: InjectionScheme::Raw,
            }) if header.eq_ignore_ascii_case("authorization")
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
            r#"allowed_scopes = ["github:example-org/example-repo"]"#,
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
        assert!(matches!(
            npm.credential,
            Some(CredentialSource::GcpAdc { .. })
        ));
    }

    #[test]
    fn parses_explicit_github_cli_repo_upstream() {
        let github_cli = r#"
[github_app]
app_id = 123
private_key_secret_ref = "github-app-key"

[[github_app.installations]]
owner = "example-org"
installation_id = 111

[[upstreams]]
name = "github-cli"
kind = "api"
listen_host = "github-cli.proxy.internal"
origin = "https://api.github.com"
credential = { kind = "github-app", permissions = { contents = "read", pull_requests = "read", issues = "read" } }
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-cli-repo" }
"#;
        let cfg = Config::from_str(&(GOOD.to_string() + github_cli)).unwrap();
        let upstream = cfg
            .upstreams
            .iter()
            .find(|upstream| upstream.name == "github-cli")
            .unwrap();
        assert_eq!(upstream.resource, Some(ResourceKind::GithubCliRepo));
    }

    #[test]
    fn rejects_github_cli_resource_without_app_bearer_injection() {
        let bad = r#"
[[upstreams]]
name = "github-cli"
kind = "api"
listen_host = "github-cli.proxy.internal"
origin = "https://api.github.com"
secret_ref = "github-token"
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-cli-repo" }
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + bad)),
            Err(ConfigError::BadGithubCliUpstream(_))
        ));
    }

    #[test]
    fn parses_explicit_passthrough_without_credentials() {
        let passthrough = r#"
[[upstreams]]
name = "public-api"
kind = "api"
mode = "passthrough"
listen_host = "public.proxy.internal"
origin = "https://api.example.com"
allowed_methods = ["GET", "HEAD"]
"#;
        let cfg = Config::from_str(&(GOOD.to_string() + passthrough)).unwrap();
        let upstream = cfg
            .upstreams
            .iter()
            .find(|upstream| upstream.name == "public-api")
            .unwrap();
        assert_eq!(upstream.mode, UpstreamMode::Passthrough);
        assert!(upstream.credential.is_none());
        assert!(upstream.injection.is_none());
    }

    #[test]
    fn parses_connect_listener_and_explicit_destination() {
        let connect = r#"
[forward_proxy]
addr = "0.0.0.0:6180"
tls = false
connect_timeout = "3s"
idle_timeout = "2m"
max_tunnel_duration = "30m"
allow_private_ips = true
audit_unmatched = { scope = "outbound-audit" }

[[upstreams]]
name = "public-docs"
kind = "api"
mode = "passthrough"
listen_host = "docs.proxy.internal"
origin = "https://docs.example.com"
allow_connect = true
"#;
        let cfg = Config::from_str(&(GOOD.to_string() + connect)).unwrap();
        let forward = cfg.forward_proxy.unwrap();
        assert_eq!(forward.addr, "0.0.0.0:6180");
        assert!(!forward.tls);
        assert_eq!(forward.connect_timeout, std::time::Duration::from_secs(3));
        assert_eq!(forward.idle_timeout, std::time::Duration::from_secs(120));
        assert_eq!(
            forward.max_tunnel_duration,
            std::time::Duration::from_secs(1800)
        );
        assert_eq!(forward.max_concurrent_tunnels, 1024);
        assert!(forward.allow_private_ips);
        assert_eq!(
            forward.audit_unmatched,
            Some(AuditUnmatchedConfig {
                scope: "outbound-audit".into()
            })
        );
        assert!(
            cfg.upstreams
                .iter()
                .find(|upstream| upstream.name == "public-docs")
                .unwrap()
                .allow_connect
        );
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_connect_configuration() {
        let no_listener = r#"
[[upstreams]]
name = "docs-connect"
kind = "api"
mode = "passthrough"
listen_host = "docs-connect.proxy.internal"
origin = "https://docs.example.com"
allow_connect = true
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + no_listener)),
            Err(ConfigError::ConnectWithoutListener(_))
        ));

        let inject = r#"
[forward_proxy]
addr = "0.0.0.0:6180"

[[upstreams]]
name = "bad-connect"
kind = "api"
listen_host = "bad-connect.proxy.internal"
origin = "https://api.example.com"
secret_ref = "projects/p/secrets/bad/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
allow_connect = true
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + inject)),
            Err(ConfigError::ConnectRequiresPassthrough(_))
        ));

        let path_policy = r#"
[forward_proxy]
addr = "0.0.0.0:6180"

[[upstreams]]
name = "path-connect"
kind = "api"
mode = "passthrough"
listen_host = "path-connect.proxy.internal"
origin = "https://api.example.com"
resource = { kind = "github-repo" }
allow_connect = true
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + path_policy)),
            Err(ConfigError::ConnectPolicyUnsupported(_))
        ));

        let zero_capacity = r#"
[forward_proxy]
addr = "0.0.0.0:6180"
max_concurrent_tunnels = 0
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + zero_capacity)),
            Err(ConfigError::BadForwardProxy(_))
        ));

        let resource_scope = r#"
[forward_proxy]
addr = "0.0.0.0:6180"
audit_unmatched = { scope = "github:org/repo" }
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + resource_scope)),
            Err(ConfigError::BadForwardProxy(_))
        ));

        let reused_scope = r#"
[forward_proxy]
addr = "0.0.0.0:6180"
audit_unmatched = { scope = "github" }
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + reused_scope)),
            Err(ConfigError::BadForwardProxy(_))
        ));

        let reserved_metrics_name = r#"
[forward_proxy]
addr = "0.0.0.0:6180"
audit_unmatched = { scope = "outbound-audit" }

[[upstreams]]
name = "audit-unmatched"
kind = "api"
mode = "passthrough"
listen_host = "audit-unmatched.proxy.internal"
origin = "https://example.com"
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + reserved_metrics_name)),
            Err(ConfigError::BadForwardProxy(_))
        ));
    }

    #[test]
    fn rejects_passthrough_credentials_and_inject_without_injection() {
        let passthrough_with_secret = r#"
[[upstreams]]
name = "bad-passthrough"
kind = "api"
mode = "passthrough"
listen_host = "bad-passthrough.proxy.internal"
origin = "https://api.example.com"
secret_ref = "projects/p/secrets/bad/versions/latest"
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + passthrough_with_secret)),
            Err(ConfigError::PassthroughConfig(_))
        ));

        let inject_without_injection = r#"
[[upstreams]]
name = "bad-inject"
kind = "api"
listen_host = "bad-inject.proxy.internal"
origin = "https://api.example.com"
secret_ref = "projects/p/secrets/bad/versions/latest"
"#;
        assert!(matches!(
            Config::from_str(&(GOOD.to_string() + inject_without_injection)),
            Err(ConfigError::MissingInjection(_))
        ));
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
