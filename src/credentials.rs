use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use google_cloud_auth::credentials::{AccessTokenCredentials, Builder as GoogleAuthBuilder};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex, OnceCell};

use crate::config::{CredentialSource, GithubAppConfig, Upstream};
use crate::resource::extract;
use crate::secrets::{Secret, SecretProvider};

const GITHUB_JWT_LIFETIME: u64 = 9 * 60;
const REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);
const GOOGLE_CLOUD_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("upstream does not have a credential provider")]
    MissingCredential,
    #[error("static secret unavailable: {0}")]
    StaticSecret(String),
    #[error("GitHub App configuration is missing")]
    MissingGithubApp,
    #[error("request does not identify a repository")]
    MissingRepository,
    #[error("no GitHub App installation configured for owner '{0}'")]
    UnknownGithubOwner(String),
    #[error("GitHub App private key is invalid")]
    InvalidGithubKey,
    #[error("failed to sign GitHub App JWT")]
    GithubJwt,
    #[error("GitHub token request failed: {0}")]
    GithubRequest(String),
    #[error("GitHub token response was invalid: {0}")]
    GithubResponse(String),
    #[error("Google application default credentials unavailable: {0}")]
    GoogleAuth(String),
}

#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub secret: Secret,
    /// Present for credentials that can be invalidated after an upstream 401.
    pub cache_key: Option<String>,
    pub result: &'static str,
}

#[async_trait]
pub trait CredentialProvider: Send + Sync {
    async fn resolve(
        &self,
        upstream: &Upstream,
        method: &str,
        path: &str,
    ) -> Result<ResolvedCredential, CredentialError>;

    async fn invalidate(&self, _cache_key: &str) {}
}

#[derive(Clone)]
struct CachedCredential {
    secret: Secret,
    refresh_at: Instant,
}

pub struct CredentialManager {
    secrets: Arc<dyn SecretProvider>,
    github_app: Option<GithubAppConfig>,
    github_client: reqwest::Client,
    github_cache: Mutex<HashMap<String, CachedCredential>>,
    google_credentials: OnceCell<AccessTokenCredentials>,
}

impl CredentialManager {
    pub fn new(
        secrets: Arc<dyn SecretProvider>,
        github_app: Option<GithubAppConfig>,
    ) -> CredentialManager {
        CredentialManager {
            secrets,
            github_app,
            github_client: reqwest::Client::new(),
            github_cache: Mutex::new(HashMap::new()),
            google_credentials: OnceCell::new(),
        }
    }

    async fn resolve_github(
        &self,
        upstream: &Upstream,
        permissions: &std::collections::BTreeMap<String, String>,
        basic_username: Option<&str>,
        path: &str,
    ) -> Result<ResolvedCredential, CredentialError> {
        let app = self
            .github_app
            .as_ref()
            .ok_or(CredentialError::MissingGithubApp)?;
        let resource = upstream
            .resource
            .and_then(|kind| extract(kind, path))
            .ok_or(CredentialError::MissingRepository)?;
        let installation = app
            .installation_for(&resource.owner)
            .ok_or_else(|| CredentialError::UnknownGithubOwner(resource.owner.clone()))?;
        let permission_key = serde_json::to_string(permissions)
            .map_err(|error| CredentialError::GithubResponse(error.to_string()))?;
        let cache_key = format!(
            "github:{}:{}:{}/{}:{}",
            app.app_id,
            installation.installation_id,
            resource.owner.to_ascii_lowercase(),
            resource.repo.to_ascii_lowercase(),
            permission_key
        );

        // The mutex intentionally covers the mint operation. Token generation is rare
        // and this gives all concurrent misses single-flight behaviour without ever
        // duplicating installation tokens.
        let mut cache = self.github_cache.lock().await;
        if let Some(cached) = cache.get(&cache_key)
            && Instant::now() < cached.refresh_at
        {
            let secret = match basic_username {
                Some(username) => Secret::new(format!("{username}:{}", cached.secret.expose())),
                None => cached.secret.clone(),
            };
            return Ok(ResolvedCredential {
                secret,
                cache_key: Some(cache_key),
                result: "cache-hit",
            });
        }

        let private_key = self
            .secrets
            .get(&app.private_key_secret_ref)
            .await
            .map_err(|error| CredentialError::StaticSecret(error.to_string()))?;
        let encoding_key = EncodingKey::from_rsa_pem(private_key.expose().as_bytes())
            .map_err(|_| CredentialError::InvalidGithubKey)?;
        let now = jsonwebtoken::get_current_timestamp();
        let claims = GithubAppClaims {
            iat: now.saturating_sub(60),
            exp: now + GITHUB_JWT_LIFETIME,
            iss: app.app_id.to_string(),
        };
        let app_jwt = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
            .map_err(|_| CredentialError::GithubJwt)?;
        let endpoint = format!(
            "{}/app/installations/{}/access_tokens",
            app.api_base.trim_end_matches('/'),
            installation.installation_id
        );
        let request = GithubTokenRequest {
            repositories: vec![resource.repo.clone()],
            permissions: permissions.clone(),
        };
        let response = self
            .github_client
            .post(endpoint)
            .bearer_auth(app_jwt)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("user-agent", "trust-credential-proxy")
            .json(&request)
            .send()
            .await
            .map_err(|error| CredentialError::GithubRequest(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CredentialError::GithubRequest(status.to_string()));
        }
        let response: GithubTokenResponse = response
            .json()
            .await
            .map_err(|error| CredentialError::GithubResponse(error.to_string()))?;
        let expires_at = OffsetDateTime::parse(&response.expires_at, &Rfc3339)
            .map_err(|error| CredentialError::GithubResponse(error.to_string()))?;
        let remaining = expires_at - OffsetDateTime::now_utc();
        let remaining = Duration::try_from(remaining)
            .map_err(|error| CredentialError::GithubResponse(error.to_string()))?;
        let refresh_in = remaining.saturating_sub(REFRESH_SKEW);
        if refresh_in.is_zero() {
            return Err(CredentialError::GithubResponse(
                "token expires too soon".to_string(),
            ));
        }
        let secret = Secret::new(response.token);
        cache.insert(
            cache_key.clone(),
            CachedCredential {
                secret: secret.clone(),
                refresh_at: Instant::now() + refresh_in,
            },
        );
        let resolved_secret = match basic_username {
            Some(username) => Secret::new(format!("{username}:{}", secret.expose())),
            None => secret,
        };
        Ok(ResolvedCredential {
            secret: resolved_secret,
            cache_key: Some(cache_key),
            result: "refreshed",
        })
    }

    async fn resolve_google(&self) -> Result<ResolvedCredential, CredentialError> {
        let credentials = self
            .google_credentials
            .get_or_try_init(|| async {
                GoogleAuthBuilder::default()
                    .with_scopes([GOOGLE_CLOUD_SCOPE])
                    .build_access_token_credentials()
                    .map_err(|error| CredentialError::GoogleAuth(error.to_string()))
            })
            .await?;
        // google-cloud-auth maintains its own expiry-aware access-token cache.
        let token = credentials
            .access_token()
            .await
            .map_err(|error| CredentialError::GoogleAuth(error.to_string()))?;
        Ok(ResolvedCredential {
            secret: Secret::new(token.token),
            cache_key: None,
            result: "managed-cache",
        })
    }
}

#[async_trait]
impl CredentialProvider for CredentialManager {
    async fn resolve(
        &self,
        upstream: &Upstream,
        _method: &str,
        path: &str,
    ) -> Result<ResolvedCredential, CredentialError> {
        let credential = upstream
            .credential
            .as_ref()
            .ok_or(CredentialError::MissingCredential)?;
        match credential {
            CredentialSource::StaticSecret { secret_ref } => {
                let secret = self
                    .secrets
                    .get(secret_ref)
                    .await
                    .map_err(|error| CredentialError::StaticSecret(error.to_string()))?;
                Ok(ResolvedCredential {
                    secret,
                    cache_key: None,
                    result: "static",
                })
            }
            CredentialSource::GithubApp {
                permissions,
                basic_username,
            } => {
                self.resolve_github(upstream, permissions, basic_username.as_deref(), path)
                    .await
            }
            CredentialSource::GcpAdc { .. } => self.resolve_google().await,
        }
    }

    async fn invalidate(&self, cache_key: &str) {
        self.github_cache.lock().await.remove(cache_key);
    }
}

#[derive(Serialize)]
struct GithubAppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Serialize)]
struct GithubTokenRequest {
    repositories: Vec<String>,
    permissions: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    token: String,
    expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CredentialSource, GithubInstallation, Injection, InjectionScheme, Origin, Upstream,
        UpstreamKind, UpstreamMode,
    };
    use crate::resource::ResourceKind;
    use crate::secrets::fake::FakeSecretProvider;
    use axum::extract::{Path, State};
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};
    use openssl::rsa::Rsa;
    use serde_json::{Value, json};

    #[test]
    fn installation_lookup_is_case_insensitive() {
        let app = GithubAppConfig {
            app_id: 1,
            private_key_secret_ref: "key".into(),
            api_base: "https://api.github.com".into(),
            installations: vec![
                GithubInstallation {
                    owner: "Org-One".into(),
                    installation_id: 11,
                },
                GithubInstallation {
                    owner: "org-two".into(),
                    installation_id: 22,
                },
            ],
        };
        assert_eq!(app.installation_for("ORG-ONE").unwrap().installation_id, 11);
        assert_eq!(app.installation_for("org-two").unwrap().installation_id, 22);
        assert!(app.installation_for("other").is_none());
    }

    #[tokio::test]
    async fn mints_and_caches_tokens_per_organization_installation() {
        type Requests = Arc<Mutex<Vec<(u64, Value)>>>;

        async fn mint(
            Path(installation_id): Path<u64>,
            State(requests): State<Requests>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            assert!(
                headers
                    .get("authorization")
                    .and_then(|header| header.to_str().ok())
                    .is_some_and(|header| header.starts_with("Bearer ey"))
            );
            requests.lock().await.push((installation_id, body));
            Json(json!({
                "token": format!("token-{installation_id}"),
                "expires_at": "2099-01-01T00:00:00Z"
            }))
        }

        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(
                "/app/installations/{installation_id}/access_tokens",
                post(mint),
            )
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let key = Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
        let key = String::from_utf8(key).unwrap();
        let secrets: Arc<dyn SecretProvider> =
            Arc::new(FakeSecretProvider::new(&[("github-key", key.as_str())]));
        let github_app = GithubAppConfig {
            app_id: 123,
            private_key_secret_ref: "github-key".into(),
            api_base: format!("http://{address}"),
            installations: vec![
                GithubInstallation {
                    owner: "org-one".into(),
                    installation_id: 111,
                },
                GithubInstallation {
                    owner: "org-two".into(),
                    installation_id: 222,
                },
            ],
        };
        let manager = CredentialManager::new(secrets, Some(github_app));
        let upstream = Upstream {
            name: "github".into(),
            kind: UpstreamKind::Api,
            listen_host: "github.proxy".into(),
            origin: Origin {
                host: "api.github.com".into(),
                port: 443,
                tls: true,
                sni: "api.github.com".into(),
            },
            mode: UpstreamMode::Inject,
            credential: Some(CredentialSource::GithubApp {
                permissions: [("contents".to_string(), "read".to_string())]
                    .into_iter()
                    .collect(),
                basic_username: None,
            }),
            injection: Some(Injection {
                header: "authorization".into(),
                scheme: InjectionScheme::Bearer,
            }),
            resource: Some(ResourceKind::GithubRepo),
            git: None,
            allowed_methods: vec!["GET".into()],
            allow_connect: false,
        };

        let one = manager
            .resolve(&upstream, "GET", "/repos/org-one/repo-a/contents")
            .await
            .unwrap();
        assert_eq!(one.secret.expose(), "token-111");
        let cached = manager
            .resolve(&upstream, "GET", "/repos/ORG-ONE/repo-a/contents")
            .await
            .unwrap();
        assert_eq!(cached.secret.expose(), "token-111");
        let mut git_upstream = upstream.clone();
        git_upstream.resource = Some(ResourceKind::GitRepo);
        git_upstream.injection.as_mut().unwrap().scheme = InjectionScheme::Basic;
        if let Some(CredentialSource::GithubApp { basic_username, .. }) =
            &mut git_upstream.credential
        {
            *basic_username = Some("x-access-token".into());
        }
        let git = manager
            .resolve(&git_upstream, "GET", "/org-one/repo-a.git/info/refs")
            .await
            .unwrap();
        assert_eq!(git.secret.expose(), "x-access-token:token-111");
        let two = manager
            .resolve(&upstream, "GET", "/repos/org-two/repo-a/contents")
            .await
            .unwrap();
        assert_eq!(two.secret.expose(), "token-222");

        let requests = requests.lock().await;
        assert_eq!(
            requests.len(),
            2,
            "org-one token should be served from cache"
        );
        assert_eq!(requests[0].0, 111);
        assert_eq!(requests[0].1["repositories"], json!(["repo-a"]));
        assert_eq!(requests[0].1["permissions"]["contents"], "read");
        assert_eq!(requests[1].0, 222);
        drop(requests);
        server.abort();
    }
}
