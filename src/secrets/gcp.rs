use async_trait::async_trait;
use google_cloud_auth::credentials::anonymous::Builder as AnonymousCredentials;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use tokio::sync::OnceCell;
use url::Url;

use super::{Secret, SecretError, SecretProvider};

const SECRET_MANAGER_EMULATOR_HOST: &str = "SECRET_MANAGER_EMULATOR_HOST";

pub struct GcpSecretProvider {
    client: OnceCell<SecretManagerService>,
    emulator_host: Option<String>,
}

impl GcpSecretProvider {
    pub fn new() -> Self {
        Self::with_emulator_host(std::env::var(SECRET_MANAGER_EMULATOR_HOST).ok())
    }

    fn with_emulator_host(emulator_host: Option<String>) -> Self {
        Self {
            client: OnceCell::new(),
            emulator_host,
        }
    }

    async fn client(&self) -> Result<&SecretManagerService, SecretError> {
        self.client
            .get_or_try_init(|| async {
                let mut builder = SecretManagerService::builder();
                if let Some(host) = &self.emulator_host {
                    builder = builder
                        .with_endpoint(emulator_endpoint(host)?)
                        .with_credentials(AnonymousCredentials::new().build());
                }
                builder
                    .build()
                    .await
                    .map_err(|e| SecretError::Backend(format!("client init: {e}")))
            })
            .await
    }
}

fn emulator_endpoint(host: &str) -> Result<String, SecretError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(SecretError::Backend(format!(
            "{SECRET_MANAGER_EMULATOR_HOST} must not be empty"
        )));
    }
    let candidate = if host.contains("://") {
        host.to_string()
    } else {
        format!("http://{host}")
    };
    let endpoint = Url::parse(&candidate).map_err(|error| {
        SecretError::Backend(format!("invalid {SECRET_MANAGER_EMULATOR_HOST}: {error}"))
    })?;
    if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host().is_none() {
        return Err(SecretError::Backend(format!(
            "{SECRET_MANAGER_EMULATOR_HOST} must use http or https"
        )));
    }
    if endpoint.path() != "/" || endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(SecretError::Backend(format!(
            "{SECRET_MANAGER_EMULATOR_HOST} must contain only a host and optional port"
        )));
    }
    Ok(endpoint.as_str().trim_end_matches('/').to_string())
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
                if e.http_status_code() == Some(404) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Uri};
    use axum::{Json, Router};
    use serde_json::{Value, json};

    #[test]
    fn normalizes_emulator_hosts_to_http_endpoints() {
        assert_eq!(
            emulator_endpoint("127.0.0.1:4588").unwrap(),
            "http://127.0.0.1:4588"
        );
        assert_eq!(
            emulator_endpoint(" https://secret-manager.local:4588/ ").unwrap(),
            "https://secret-manager.local:4588"
        );
    }

    #[test]
    fn rejects_ambiguous_emulator_endpoints() {
        for endpoint in ["", "ftp://localhost:4588", "http://localhost:4588/v1"] {
            assert!(emulator_endpoint(endpoint).is_err(), "accepted {endpoint}");
        }
    }

    #[tokio::test]
    async fn reads_from_the_emulator_without_google_credentials() {
        async fn access_secret(uri: Uri, headers: HeaderMap) -> Json<Value> {
            assert_eq!(
                uri.path(),
                "/v1/projects/local/secrets/anthropic/versions/latest:access"
            );
            assert!(!headers.contains_key("authorization"));
            Json(json!({
                "name": "projects/local/secrets/anthropic/versions/1",
                "payload": { "data": "c2VjcmV0LXZhbHVl" }
            }))
        }

        let app = Router::new().fallback(access_secret);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = GcpSecretProvider::with_emulator_host(Some(format!("http://{address}")));
        let secret = provider
            .get("projects/local/secrets/anthropic/versions/latest")
            .await
            .unwrap();
        assert_eq!(secret.expose(), "secret-value");
        server.abort();
    }
}
