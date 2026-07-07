use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Upstream;

pub struct Router {
    by_host: HashMap<String, Arc<Upstream>>,
}

impl Router {
    pub fn new(upstreams: &[Arc<Upstream>]) -> Router {
        let by_host = upstreams
            .iter()
            .map(|u| (u.listen_host.clone(), u.clone()))
            .collect();
        Router { by_host }
    }

    pub fn resolve(&self, host: &str) -> Option<Arc<Upstream>> {
        let bare = host.split(':').next().unwrap_or(host);
        self.by_host.get(bare).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
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
}
