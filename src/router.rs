use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Upstream;

#[derive(Clone, Debug)]
pub enum ConnectRoute {
    Opaque(Arc<Upstream>),
    Intercept(Arc<Upstream>),
}

impl ConnectRoute {
    pub fn upstream(&self) -> &Arc<Upstream> {
        match self {
            ConnectRoute::Opaque(upstream) | ConnectRoute::Intercept(upstream) => upstream,
        }
    }
}

pub struct Router {
    by_host: HashMap<String, Arc<Upstream>>,
    by_connect_authority: HashMap<(String, u16), ConnectRoute>,
}

impl Router {
    pub fn new(upstreams: &[Arc<Upstream>]) -> Router {
        let by_host = upstreams
            .iter()
            .map(|u| (u.listen_host.to_ascii_lowercase(), u.clone()))
            .collect();
        let by_connect_authority = upstreams
            .iter()
            .filter(|upstream| upstream.allow_connect || upstream.intercept_connect)
            .map(|upstream| {
                (
                    (
                        upstream
                            .origin
                            .host
                            .strip_suffix('.')
                            .unwrap_or(&upstream.origin.host)
                            .to_ascii_lowercase(),
                        upstream.origin.port,
                    ),
                    if upstream.intercept_connect {
                        ConnectRoute::Intercept(upstream.clone())
                    } else {
                        ConnectRoute::Opaque(upstream.clone())
                    },
                )
            })
            .collect();
        Router {
            by_host,
            by_connect_authority,
        }
    }

    pub fn resolve(&self, host: &str) -> Option<Arc<Upstream>> {
        let bare = host.split(':').next().unwrap_or(host);
        self.by_host.get(&bare.to_ascii_lowercase()).cloned()
    }

    pub fn resolve_connect(&self, host: &str, port: u16) -> Option<ConnectRoute> {
        self.by_connect_authority
            .get(&(
                host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase(),
                port,
            ))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CredentialSource, Injection, InjectionScheme, Origin, Upstream, UpstreamKind, UpstreamMode,
    };
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
            mode: UpstreamMode::Inject,
            credential: Some(CredentialSource::StaticSecret {
                secret_ref: "ref".into(),
            }),
            injection: Some(Injection {
                header: "x-api-key".into(),
                scheme: InjectionScheme::Raw,
            }),
            resource: None,
            git: None,
            allowed_methods: Vec::new(),
            allow_connect: false,
            intercept_connect: false,
        })
    }

    #[test]
    fn resolves_by_host_ignoring_port() {
        let r = Router::new(&[up("anthropic", "anthropic.proxy.internal")]);
        assert_eq!(
            r.resolve("anthropic.proxy.internal").unwrap().name,
            "anthropic"
        );
        assert_eq!(
            r.resolve("anthropic.proxy.internal:8443").unwrap().name,
            "anthropic"
        );
        assert!(r.resolve("unknown.host").is_none());
    }

    #[test]
    fn resolves_only_explicit_connect_destinations() {
        let mut connect = (*up("docs", "docs.proxy.internal")).clone();
        connect.origin.host = "docs.example.com".into();
        connect.mode = UpstreamMode::Passthrough;
        connect.credential = None;
        connect.injection = None;
        connect.allow_connect = true;
        let router = Router::new(&[Arc::new(connect), up("other", "other.proxy.internal")]);
        let route = router.resolve_connect("DOCS.EXAMPLE.COM", 443).unwrap();
        assert!(matches!(route, ConnectRoute::Opaque(_)));
        assert_eq!(route.upstream().name, "docs");
        assert!(router.resolve_connect("docs.example.com", 8443).is_none());
        assert!(router.resolve_connect("example.com", 443).is_none());
    }

    #[test]
    fn identifies_interception_routes() {
        let mut intercept = (*up("anthropic", "anthropic.proxy.internal")).clone();
        intercept.origin.host = "api.anthropic.com".into();
        intercept.intercept_connect = true;
        let router = Router::new(&[Arc::new(intercept)]);

        let route = router.resolve_connect("API.ANTHROPIC.COM.", 443).unwrap();
        assert!(matches!(route, ConnectRoute::Intercept(_)));
        assert_eq!(route.upstream().name, "anthropic");
    }
}
