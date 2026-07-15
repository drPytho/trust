use crate::config::{CredentialSource, Upstream};
use crate::resource::extract;
use crate::scope::ScopeSet;

/// Extract the raw bearer token (a JWT here) from an Authorization header value.
pub fn extract_bearer(header: Option<&[u8]>) -> Option<String> {
    extract_client_token(header, false)
}

/// Extract the trust JWT from the client authentication header. GitHub CLI
/// sends `Authorization: token ...` to custom hosts; that alternate scheme is
/// accepted only by an explicitly configured GitHub CLI upstream.
pub fn extract_client_token(header: Option<&[u8]>, allow_github_token: bool) -> Option<String> {
    let raw = header?;
    let text = std::str::from_utf8(raw).ok()?;
    let (scheme, token) = text.split_once(' ')?;
    if !(scheme.eq_ignore_ascii_case("bearer")
        || allow_github_token && scheme.eq_ignore_ascii_case("token"))
    {
        return None;
    }
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Authorize a verified token's scopes against an upstream + request path.
pub fn authorize(scopes: &ScopeSet, upstream: &Upstream, method: &str, path: &str) -> bool {
    if !upstream.allowed_methods.is_empty()
        && !upstream
            .allowed_methods
            .iter()
            .any(|allowed| allowed == method)
    {
        return false;
    }
    let resource = upstream.resource.and_then(|kind| extract(kind, path));
    if resource.is_none()
        && upstream.resource.is_some()
        && matches!(
            upstream.credential,
            Some(CredentialSource::GithubApp { .. } | CredentialSource::GcpAdc { .. })
        )
    {
        return false;
    }
    scopes.permits(&upstream.name, resource.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind, UpstreamMode};
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
            mode: UpstreamMode::Inject,
            credential: Some(crate::config::CredentialSource::StaticSecret {
                secret_ref: "ref".into(),
            }),
            injection: Some(Injection {
                header: "authorization".into(),
                scheme: InjectionScheme::Bearer,
            }),
            resource,
            git: None,
            allowed_methods: Vec::new(),
            allow_connect: false,
        })
    }

    #[test]
    fn extract_bearer_parses() {
        assert_eq!(extract_bearer(Some(b"Bearer abc")).as_deref(), Some("abc"));
        assert_eq!(extract_bearer(Some(b"bearer abc")).as_deref(), Some("abc"));
        assert!(extract_bearer(None).is_none());
        assert!(extract_bearer(Some(b"Basic abc")).is_none());
        assert!(extract_bearer(Some(b"token abc")).is_none());
        assert_eq!(
            extract_client_token(Some(b"token abc"), true).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn authorize_unscoped() {
        let up = upstream("anthropic", None);
        let s = ScopeSet::parse("anthropic").unwrap();
        assert!(authorize(&s, &up, "POST", "/v1/messages"));
        let s2 = ScopeSet::parse("mistral").unwrap();
        assert!(!authorize(&s2, &up, "POST", "/v1/messages"));
    }

    #[test]
    fn authorize_resource_scoped() {
        let up = upstream("github", Some(ResourceKind::GithubRepo));
        let s = ScopeSet::parse("github:pitorg/pit-ts").unwrap();
        assert!(authorize(&s, &up, "GET", "/repos/pitorg/pit-ts/issues"));
        assert!(!authorize(&s, &up, "GET", "/repos/pitorg/other/issues"));
        // Non-repo path on a scoped upstream: only a bare token authorizes.
        assert!(!authorize(&s, &up, "GET", "/user"));
        assert!(authorize(
            &ScopeSet::parse("github").unwrap(),
            &up,
            "GET",
            "/user"
        ));
    }

    #[test]
    fn dynamic_credentials_fail_closed_without_resource_and_on_bad_method() {
        let mut github = (*upstream("github", Some(ResourceKind::GithubRepo))).clone();
        github.credential = Some(crate::config::CredentialSource::GithubApp {
            permissions: Default::default(),
            basic_username: None,
        });
        github.allowed_methods = vec!["GET".into()];
        let bare = ScopeSet::parse("github").unwrap();
        assert!(!authorize(&bare, &github, "GET", "/user"));
        assert!(!authorize(
            &bare,
            &github,
            "POST",
            "/repos/pitorg/pit-ts/issues"
        ));
        assert!(authorize(
            &bare,
            &github,
            "GET",
            "/repos/pitorg/pit-ts/issues"
        ));
    }
}
