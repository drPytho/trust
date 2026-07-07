use std::collections::HashMap;
use std::sync::Arc;

/// Legacy token-based auth entry — kept for backward compat until Phase-2 auth lands.
#[derive(Debug, Clone)]
pub struct TokenEntry {
    pub token: String,
    pub principal: String,
    pub allowed_upstreams: Vec<String>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<TokenEntry> {
        vec![TokenEntry {
            token: "client-abc".into(),
            principal: "team-x".into(),
            allowed_upstreams: vec!["anthropic".into()],
        }]
    }

    #[test]
    fn extracts_bearer() {
        assert_eq!(
            extract_bearer(Some(b"Bearer client-abc")).unwrap(),
            "client-abc"
        );
    }

    #[test]
    fn rejects_missing_and_malformed() {
        assert!(matches!(extract_bearer(None), Err(AuthError::Missing)));
        assert!(matches!(
            extract_bearer(Some(b"Basic xxx")),
            Err(AuthError::Malformed)
        ));
        assert!(matches!(
            extract_bearer(Some(b"Bearer ")),
            Err(AuthError::Malformed)
        ));
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
