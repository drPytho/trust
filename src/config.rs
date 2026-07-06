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
