#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("empty scope")]
    Empty,
    #[error("malformed scope token: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub owner: String,
    pub repo: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoPat {
    Exact(String),
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Upstream(String),
    Resource {
        upstream: String,
        owner: String,
        repo: RepoPat,
    },
}

impl Scope {
    pub fn parse(tok: &str) -> Result<Scope, ScopeError> {
        if tok.is_empty() {
            return Err(ScopeError::Empty);
        }
        match tok.split_once(':') {
            None => Ok(Scope::Upstream(tok.to_string())),
            Some((upstream, resource)) => {
                let (owner, repo) = resource
                    .split_once('/')
                    .ok_or_else(|| ScopeError::Malformed(tok.to_string()))?;
                // Reject `upstream:owner/repo/extra` — split_once('/') only splits on the first /,
                // so repo can still contain '/' even after split. This guard is load-bearing.
                if upstream.is_empty() || owner.is_empty() || repo.is_empty() || repo.contains('/')
                {
                    return Err(ScopeError::Malformed(tok.to_string()));
                }
                let repo = if repo == "*" {
                    RepoPat::Wildcard
                } else {
                    RepoPat::Exact(repo.to_string())
                };
                Ok(Scope::Resource {
                    upstream: upstream.to_string(),
                    owner: owner.to_string(),
                    repo,
                })
            }
        }
    }

    pub fn to_token(&self) -> String {
        match self {
            Scope::Upstream(u) => u.clone(),
            Scope::Resource {
                upstream,
                owner,
                repo,
            } => {
                let r = match repo {
                    RepoPat::Exact(r) => r.as_str(),
                    RepoPat::Wildcard => "*",
                };
                format!("{upstream}:{owner}/{r}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    pub fn parse(s: &str) -> Result<ScopeSet, ScopeError> {
        let scopes = s
            .split_whitespace()
            .map(Scope::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if scopes.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(ScopeSet(scopes))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }

    /// Return the exact repository grant for an upstream, when one is
    /// unambiguous. This lets credential injectors mint the repository token
    /// even for requests (for example GraphQL) whose URL has no repo path.
    pub fn exact_resource(&self, upstream: &str) -> Option<Resource> {
        let mut found = None;
        for scope in &self.0 {
            if let Scope::Resource {
                upstream: scoped_upstream,
                owner,
                repo: RepoPat::Exact(repo),
            } = scope
                && scoped_upstream == upstream
            {
                let resource = Resource {
                    owner: owner.clone(),
                    repo: repo.clone(),
                };
                if found.as_ref().is_some_and(|existing| existing != &resource) {
                    return None;
                }
                found = Some(resource);
            }
        }
        found
    }

    pub fn to_scope_string(&self) -> String {
        self.0
            .iter()
            .map(Scope::to_token)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Authorization check for a proxied request.
    pub fn permits(&self, upstream: &str, resource: Option<&Resource>) -> bool {
        for scope in &self.0 {
            match scope {
                // Bare upstream grants everything under it.
                Scope::Upstream(u) if u == upstream => return true,
                Scope::Resource {
                    upstream: u,
                    owner,
                    repo,
                } if u == upstream => {
                    if let Some(res) = resource
                        && *owner == res.owner
                        && match repo {
                            RepoPat::Wildcard => true,
                            RepoPat::Exact(r) => *r == res.repo,
                        }
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Returns the only exact repository scope granted for an upstream.
    ///
    /// GitHub's `createPullRequest` GraphQL mutation identifies its target by
    /// an opaque repository node ID rather than `owner/repo`. The caller must
    /// therefore carry exactly one explicit repository scope for the GitHub
    /// CLI upstream before Trust can safely select the repository-restricted
    /// installation token. Bare, wildcard, and conflicting resource grants
    /// are deliberately rejected.
    pub fn sole_exact_resource(&self, upstream: &str) -> Option<Resource> {
        let mut selected: Option<Resource> = None;

        for scope in &self.0 {
            match scope {
                Scope::Upstream(name) if name == upstream => return None,
                Scope::Resource {
                    upstream: name,
                    repo: RepoPat::Wildcard,
                    ..
                } if name == upstream => return None,
                Scope::Resource {
                    upstream: name,
                    owner,
                    repo: RepoPat::Exact(repo),
                } if name == upstream => {
                    let resource = Resource {
                        owner: owner.clone(),
                        repo: repo.clone(),
                    };
                    if selected
                        .as_ref()
                        .is_some_and(|current| current != &resource)
                    {
                        return None;
                    }
                    selected = Some(resource);
                }
                _ => {}
            }
        }

        selected
    }
}

/// Issuance check: can `allowed` grant `requested`?
pub fn covers(allowed: &Scope, requested: &Scope) -> bool {
    match (allowed, requested) {
        (Scope::Upstream(a), Scope::Upstream(r)) => a == r,
        // A bare upstream grant covers any resource under that upstream.
        (Scope::Upstream(a), Scope::Resource { upstream: r, .. }) => a == r,
        (
            Scope::Resource {
                upstream: au,
                owner: ao,
                repo: ar,
            },
            Scope::Resource {
                upstream: ru,
                owner: ro,
                repo: rr,
            },
        ) => {
            au == ru
                && ao == ro
                && match (ar, rr) {
                    (RepoPat::Wildcard, _) => true,
                    (RepoPat::Exact(a), RepoPat::Exact(r)) => a == r,
                    (RepoPat::Exact(_), RepoPat::Wildcard) => false,
                }
        }
        _ => false,
    }
}

/// Every requested scope must be covered by some allowed scope.
/// Returns the first uncovered scope token on failure.
pub fn grant(allowed: &ScopeSet, requested: &ScopeSet) -> Result<(), String> {
    for req in &requested.0 {
        if !allowed.0.iter().any(|a| covers(a, req)) {
            return Err(req.to_token());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(owner: &str, repo: &str) -> Resource {
        Resource {
            owner: owner.into(),
            repo: repo.into(),
        }
    }

    #[test]
    fn parses_tokens() {
        assert!(
            matches!(Scope::parse("anthropic").unwrap(), Scope::Upstream(u) if u == "anthropic")
        );
        match Scope::parse("github:example-org/example-repo").unwrap() {
            Scope::Resource {
                upstream,
                owner,
                repo,
            } => {
                assert_eq!(upstream, "github");
                assert_eq!(owner, "example-org");
                assert!(matches!(repo, RepoPat::Exact(r) if r == "example-repo"));
            }
            _ => panic!("expected resource"),
        }
        assert!(matches!(
            Scope::parse("github:customer-org/*").unwrap(),
            Scope::Resource {
                repo: RepoPat::Wildcard,
                ..
            }
        ));
        assert!(Scope::parse("bad:too/many/parts").is_err());
        assert!(Scope::parse("").is_err());
    }

    #[test]
    fn scopeset_roundtrip() {
        let s = ScopeSet::parse("anthropic github:example-org/example-repo").unwrap();
        assert_eq!(
            s.to_scope_string(),
            "anthropic github:example-org/example-repo"
        );
    }

    #[test]
    fn permits_unscoped() {
        let s = ScopeSet::parse("anthropic").unwrap();
        assert!(s.permits("anthropic", None));
        assert!(!s.permits("mistral", None));
    }

    #[test]
    fn permits_resource_scoped() {
        let s = ScopeSet::parse("github:example-org/example-repo github:customer-org/*").unwrap();
        assert!(s.permits("github", Some(&res("example-org", "example-repo")))); // exact
        assert!(s.permits("github", Some(&res("customer-org", "acme")))); // wildcard
        assert!(!s.permits("github", Some(&res("example-org", "other")))); // not granted
        assert!(!s.permits("github", None)); // no bare token
    }

    #[test]
    fn bare_token_covers_resources() {
        let s = ScopeSet::parse("github").unwrap();
        assert!(s.permits("github", Some(&res("anyone", "anything"))));
        assert!(s.permits("github", None));
    }

    #[test]
    fn covers_for_issuance() {
        let bare = Scope::parse("github").unwrap();
        let wild = Scope::parse("github:example-org/*").unwrap();
        let exact = Scope::parse("github:example-org/example-repo").unwrap();
        assert!(covers(&bare, &exact)); // bare grants any repo
        assert!(covers(&wild, &exact)); // wildcard grants a specific repo
        assert!(covers(&wild, &wild));
        assert!(!covers(&exact, &wild)); // exact does not grant wildcard
        assert!(!covers(&Scope::parse("github:other/*").unwrap(), &exact));
    }

    #[test]
    fn grant_reports_first_uncovered() {
        let allowed = ScopeSet::parse("anthropic github:example-org/*").unwrap();
        assert!(
            grant(
                &allowed,
                &ScopeSet::parse("github:example-org/example-repo").unwrap()
            )
            .is_ok()
        );
        assert_eq!(
            grant(&allowed, &ScopeSet::parse("mistral").unwrap()),
            Err("mistral".to_string())
        );
    }

    #[test]
    fn covers_different_upstream_false() {
        assert!(!covers(
            &Scope::parse("gitlab").unwrap(),
            &Scope::parse("github:example-org/example-repo").unwrap()
        ));
        assert!(!covers(
            &Scope::parse("github").unwrap(),
            &Scope::parse("gitlab").unwrap()
        ));
    }

    #[test]
    fn permits_wildcard_wrong_owner_denied() {
        let s = ScopeSet::parse("github:acme/*").unwrap();
        assert!(!s.permits("github", Some(&res("other", "repo"))));
    }

    #[test]
    fn scopeset_parse_empty() {
        assert!(matches!(ScopeSet::parse(""), Err(ScopeError::Empty)));
    }

    #[test]
    fn sole_exact_resource_requires_one_non_wildcard_scope() {
        assert_eq!(
            ScopeSet::parse("github-cli:example-org/example-repo")
                .unwrap()
                .sole_exact_resource("github-cli"),
            Some(res("example-org", "example-repo"))
        );
        assert_eq!(
            ScopeSet::parse(
                "github-cli:example-org/example-repo github-cli:example-org/example-repo",
            )
            .unwrap()
            .sole_exact_resource("github-cli"),
            Some(res("example-org", "example-repo"))
        );
        assert!(
            ScopeSet::parse("github-cli")
                .unwrap()
                .sole_exact_resource("github-cli")
                .is_none()
        );
        assert!(
            ScopeSet::parse("github-cli:example-org/*")
                .unwrap()
                .sole_exact_resource("github-cli")
                .is_none()
        );
        assert!(
            ScopeSet::parse(
                "github-cli:example-org/example-repo github-cli:example-org/other-repo",
            )
            .unwrap()
            .sole_exact_resource("github-cli")
            .is_none()
        );
    }
}
