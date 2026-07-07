use std::collections::HashSet;
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
    pub resource: Option<ResourceKind>,
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
    secret_ref: String,
    injection: Injection,
    #[serde(default)]
    resource: Option<RawResource>,
}

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
                resource: ru.resource.map(|r| r.kind),
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
}
