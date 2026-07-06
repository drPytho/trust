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

pub mod fake;
pub mod gcp;

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
