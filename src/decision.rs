use crate::config::Upstream;
use crate::resource::extract;
use crate::scope::ScopeSet;

/// Extract the raw bearer token (a JWT here) from an Authorization header value.
pub fn extract_bearer(header: Option<&[u8]>) -> Option<String> {
    let raw = header?;
    let text = std::str::from_utf8(raw).ok()?;
    let token = text.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Authorize a verified token's scopes against an upstream + request path.
pub fn authorize(scopes: &ScopeSet, upstream: &Upstream, path: &str) -> bool {
    let resource = upstream.resource.and_then(|kind| extract(kind, path));
    scopes.permits(&upstream.name, resource.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
    use crate::resource::ResourceKind;
    use crate::scope::ScopeSet;
    use std::sync::Arc;

    fn upstream(name: &str, resource: Option<ResourceKind>) -> Arc<Upstream> {
        Arc::new(Upstream {
            name: name.into(),
            kind: UpstreamKind::Api,
            listen_host: format!("{name}.proxy"),
            origin: Origin {
                host: "h".into(),
                port: 443,
                tls: true,
                sni: "h".into(),
            },
            secret_ref: "ref".into(),
            injection: Injection {
                header: "authorization".into(),
                scheme: InjectionScheme::Bearer,
            },
            resource,
        })
    }

    #[test]
    fn extract_bearer_parses() {
        assert_eq!(extract_bearer(Some(b"Bearer abc")).as_deref(), Some("abc"));
        assert!(extract_bearer(None).is_none());
        assert!(extract_bearer(Some(b"Basic abc")).is_none());
    }

    #[test]
    fn authorize_unscoped() {
        let up = upstream("anthropic", None);
        let s = ScopeSet::parse("anthropic").unwrap();
        assert!(authorize(&s, &up, "/v1/messages"));
        let s2 = ScopeSet::parse("mistral").unwrap();
        assert!(!authorize(&s2, &up, "/v1/messages"));
    }

    #[test]
    fn authorize_resource_scoped() {
        let up = upstream("github", Some(ResourceKind::GithubRepo));
        let s = ScopeSet::parse("github:pitorg/pit-ts").unwrap();
        assert!(authorize(&s, &up, "/repos/pitorg/pit-ts/issues"));
        assert!(!authorize(&s, &up, "/repos/pitorg/other/issues"));
        // Non-repo path on a scoped upstream: only a bare token authorizes.
        assert!(!authorize(&s, &up, "/user"));
        assert!(authorize(&ScopeSet::parse("github").unwrap(), &up, "/user"));
    }
}
