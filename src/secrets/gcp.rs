use async_trait::async_trait;
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
