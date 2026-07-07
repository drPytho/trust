use std::sync::Arc;

use crate::auth::{Principal, TokenMap, extract_bearer};
use crate::config::Upstream;
use crate::router::Router;

#[derive(Debug)]
pub enum Decision {
    Reject { status: u16, body: &'static str },
    Forward(Arc<Upstream>),
}

pub fn authorize(principal: &Principal, upstream: &Upstream) -> bool {
    principal.allowed.iter().any(|name| name == &upstream.name)
}

pub fn decide(
    host: Option<&str>,
    auth: Option<&[u8]>,
    router: &Router,
    tokens: &TokenMap,
) -> Decision {
    let Some(host) = host else {
        return Decision::Reject {
            status: 404,
            body: "unknown host",
        };
    };
    let Some(upstream) = router.resolve(host) else {
        return Decision::Reject {
            status: 404,
            body: "unknown host",
        };
    };
    let token = match extract_bearer(auth) {
        Ok(t) => t,
        Err(_) => {
            return Decision::Reject {
                status: 401,
                body: "missing or invalid token",
            };
        }
    };
    let Some(principal) = tokens.lookup(&token) else {
        return Decision::Reject {
            status: 401,
            body: "missing or invalid token",
        };
    };
    if !authorize(&principal, &upstream) {
        return Decision::Reject {
            status: 403,
            body: "not allowed for this upstream",
        };
    }
    Decision::Forward(upstream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenMap;
    use crate::auth::TokenEntry;
    use crate::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
    use crate::router::Router;
    use std::sync::Arc;

    fn up(name: &str, host: &str) -> Arc<Upstream> {
        Arc::new(Upstream {
            name: name.into(),
            kind: UpstreamKind::Api,
            listen_host: host.into(),
            origin: Origin {
                host: "example.com".into(),
                port: 443,
                tls: true,
                sni: "example.com".into(),
            },
            secret_ref: "ref".into(),
            injection: Injection {
                header: "x-api-key".into(),
                scheme: InjectionScheme::Raw,
            },
            resource: None,
        })
    }

    fn setup() -> (Router, TokenMap) {
        let ups = vec![up("anthropic", "anthropic.proxy.internal")];
        let tokens = TokenMap::new(&[TokenEntry {
            token: "good".into(),
            principal: "team-x".into(),
            allowed_upstreams: vec!["anthropic".into()],
        }]);
        (Router::new(&ups), tokens)
    }

    #[test]
    fn unknown_host_404() {
        let (r, t) = setup();
        assert!(matches!(
            decide(Some("nope"), Some(b"Bearer good"), &r, &t),
            Decision::Reject { status: 404, .. }
        ));
        assert!(matches!(
            decide(None, Some(b"Bearer good"), &r, &t),
            Decision::Reject { status: 404, .. }
        ));
    }

    #[test]
    fn bad_token_401() {
        let (r, t) = setup();
        assert!(matches!(
            decide(Some("anthropic.proxy.internal"), None, &r, &t),
            Decision::Reject { status: 401, .. }
        ));
        assert!(matches!(
            decide(
                Some("anthropic.proxy.internal"),
                Some(b"Bearer wrong"),
                &r,
                &t
            ),
            Decision::Reject { status: 401, .. }
        ));
    }

    #[test]
    fn not_allowed_403() {
        let ups = vec![up("anthropic", "anthropic.proxy.internal")];
        let tokens = TokenMap::new(&[TokenEntry {
            token: "good".into(),
            principal: "team-x".into(),
            allowed_upstreams: vec![], // allowed to nothing
        }]);

        let r = Router::new(&ups);
        assert!(matches!(
            decide(
                Some("anthropic.proxy.internal"),
                Some(b"Bearer good"),
                &r,
                &tokens
            ),
            Decision::Reject { status: 403, .. }
        ));
    }

    #[test]
    fn happy_path_forwards() {
        let (r, t) = setup();
        match decide(
            Some("anthropic.proxy.internal"),
            Some(b"Bearer good"),
            &r,
            &t,
        ) {
            Decision::Forward(u) => assert_eq!(u.name, "anthropic"),
            other => panic!("expected forward, got {other:?}"),
        }
    }
}
