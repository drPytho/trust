use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

use crate::auth::TokenMap;
use crate::config::Upstream;
use crate::decision::{Decision, decide};
use crate::inject::inject;
use crate::router::Router;
use crate::secrets::{Secret, SecretProvider};

#[derive(Default)]
pub struct RequestCtx {
    pub upstream: Option<Arc<Upstream>>,
    pub secret: Option<Secret>,
}

pub struct ProxyService {
    pub router: Router,
    pub tokens: TokenMap,
    pub secrets: Arc<dyn SecretProvider>,
}

impl ProxyService {
    pub fn new(router: Router, tokens: TokenMap, secrets: Arc<dyn SecretProvider>) -> ProxyService {
        ProxyService {
            router,
            tokens,
            secrets,
        }
    }
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let auth = session
            .req_header()
            .headers
            .get("authorization")
            .map(|v| v.as_bytes().to_vec());

        match decide(host.as_deref(), auth.as_deref(), &self.router, &self.tokens) {
            Decision::Reject { status, body } => {
                session
                    .respond_error_with_body(status, Bytes::from_static(body.as_bytes()))
                    .await?;
                Ok(true)
            }
            Decision::Forward(upstream) => match self.secrets.get(&upstream.secret_ref).await {
                Ok(secret) => {
                    ctx.secret = Some(secret);
                    ctx.upstream = Some(upstream);
                    Ok(false)
                }
                Err(e) => {
                    log::error!("secret fetch failed for {}: {e}", upstream.name);
                    session
                        .respond_error_with_body(
                            502,
                            Bytes::from_static(b"upstream secret unavailable"),
                        )
                        .await?;
                    Ok(true)
                }
            },
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Guaranteed Some: request_filter returns Ok(false) only after setting this.
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let o = &upstream.origin;
        let peer = HttpPeer::new((o.host.as_str(), o.port), o.tls, o.sni.clone());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Strip the client's proxy token so it never leaks upstream.
        upstream_request.remove_header("authorization");

        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let secret = ctx
            .secret
            .as_ref()
            .ok_or_else(|| Error::new_str("secret missing in ctx"))?;

        inject(upstream_request, &upstream.injection, secret.expose())
            .map_err(|_| Error::new_str("secret injection failed"))?;

        // Send the real upstream host, not the proxy listen_host.
        upstream_request
            .insert_header("host", upstream.origin.host.as_str())
            .map_err(|_| Error::new_str("failed to set host header"))?;
        Ok(())
    }
}
