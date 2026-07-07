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
