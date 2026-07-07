use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

use crate::config::Upstream;
use crate::decision::{authorize, extract_bearer};
use crate::inject::inject;
use crate::jwt::Verifier;
use crate::keystore::Keystore;
use crate::router::Router;
use crate::secrets::{Secret, SecretProvider};

#[derive(Default)]
pub struct RequestCtx {
    pub upstream: Option<Arc<Upstream>>,
    pub secret: Option<Secret>,
}

pub struct ProxyService {
    pub router: Router,
    pub verifier: Verifier,
    pub keystore: Arc<Keystore>,
    pub secrets: Arc<dyn SecretProvider>,
}

impl ProxyService {
    pub fn new(
        router: Router,
        verifier: Verifier,
        keystore: Arc<Keystore>,
        secrets: Arc<dyn SecretProvider>,
    ) -> ProxyService {
        ProxyService { router, verifier, keystore, secrets }
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
        let Some(host) = host else {
            session.respond_error_with_body(404, Bytes::from_static(b"unknown host")).await?;
            return Ok(true);
        };
        let Some(upstream) = self.router.resolve(&host) else {
            session.respond_error_with_body(404, Bytes::from_static(b"unknown host")).await?;
            return Ok(true);
        };

        // Verify the JWT.
        let auth = session
            .req_header()
            .headers
            .get("authorization")
            .map(|v| v.as_bytes().to_vec());
        let Some(token) = extract_bearer(auth.as_deref()) else {
            session.respond_error_with_body(401, Bytes::from_static(b"missing token")).await?;
            return Ok(true);
        };
        let Some(km) = self.keystore.load() else {
            session.respond_error_with_body(503, Bytes::from_static(b"keys unavailable")).await?;
            return Ok(true);
        };
        let scopes = match self.verifier.verify(&km, &token) {
            Ok(s) => s,
            Err(_) => {
                session.respond_error_with_body(401, Bytes::from_static(b"invalid token")).await?;
                return Ok(true);
            }
        };

        // Authorize by scope (+ resource path).
        let path = session.req_header().uri.path().to_string();
        if !authorize(&scopes, &upstream, &path) {
            session.respond_error_with_body(403, Bytes::from_static(b"not allowed")).await?;
            return Ok(true);
        }

        match self.secrets.get(&upstream.secret_ref).await {
            Ok(secret) => {
                ctx.secret = Some(secret);
                ctx.upstream = Some(upstream);
                Ok(false)
            }
            Err(e) => {
                log::error!("secret fetch failed for {}: {e}", upstream.name);
                session
                    .respond_error_with_body(502, Bytes::from_static(b"upstream secret unavailable"))
                    .await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let o = &upstream.origin;
        Ok(Box::new(HttpPeer::new((o.host.as_str(), o.port), o.tls, o.sni.clone())))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
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
        upstream_request
            .insert_header("host", upstream.origin.host.as_str())
            .map_err(|_| Error::new_str("failed to set host header"))?;
        Ok(())
    }
}
