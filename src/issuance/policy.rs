use crate::config::ClientEntry;
use crate::scope::{ScopeError, ScopeSet};

struct Entry {
    // Either an exact identity or a prefix (trailing `*` stripped).
    matcher: Matcher,
    scopes: ScopeSet,
}

enum Matcher {
    Exact(String),
    Prefix(String),
}

pub struct ClientPolicy {
    entries: Vec<Entry>,
}

impl ClientPolicy {
    pub fn new(entries: &[ClientEntry]) -> Result<ClientPolicy, ScopeError> {
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let scopes = ScopeSet::parse(&e.allowed_scopes.join(" "))?;
            let matcher = match e.spiffe.strip_suffix('*') {
                Some(prefix) => Matcher::Prefix(prefix.to_string()),
                None => Matcher::Exact(e.spiffe.clone()),
            };
            out.push(Entry { matcher, scopes });
        }
        Ok(ClientPolicy { entries: out })
    }

    pub fn allowed_scopes(&self, spiffe: &str) -> Option<&ScopeSet> {
        // Exact matches win over prefix matches.
        for e in &self.entries {
            if let Matcher::Exact(id) = &e.matcher
                && id == spiffe
            {
                return Some(&e.scopes);
            }
        }
        for e in &self.entries {
            if let Matcher::Prefix(p) = &e.matcher
                && spiffe.starts_with(p)
            {
                return Some(&e.scopes);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientEntry;

    fn entries() -> Vec<ClientEntry> {
        vec![
            ClientEntry {
                spiffe: "spiffe://example/ci/example-repo".into(),
                allowed_scopes: vec!["github:example-org/example-repo".into()],
            },
            ClientEntry {
                spiffe: "spiffe://example/team/platform/*".into(),
                allowed_scopes: vec!["anthropic".into(), "github:example-org/*".into()],
            },
        ]
    }

    #[test]
    fn exact_match() {
        let p = ClientPolicy::new(&entries()).unwrap();
        let s = p
            .allowed_scopes("spiffe://example/ci/example-repo")
            .unwrap();
        assert_eq!(s.to_scope_string(), "github:example-org/example-repo");
    }

    #[test]
    fn prefix_match() {
        let p = ClientPolicy::new(&entries()).unwrap();
        let s = p
            .allowed_scopes("spiffe://example/team/platform/build-42")
            .unwrap();
        assert_eq!(s.to_scope_string(), "anthropic github:example-org/*");
    }

    #[test]
    fn no_match_is_none() {
        let p = ClientPolicy::new(&entries()).unwrap();
        assert!(p.allowed_scopes("spiffe://example/other/x").is_none());
    }
}
