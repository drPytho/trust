use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;

use crate::config::{CredentialSource, Upstream, UpstreamKind, UpstreamMode};
use crate::credentials::CredentialProvider;
use crate::decision::authorize;
use crate::inject::inject;
use crate::metrics::ProxyMetrics;
use crate::mitm::MitmConnectionContext;
use crate::secrets::Secret;

pub struct MitmRequestCtx {
    upstream: Option<Arc<Upstream>>,
    upstream_address: Option<SocketAddr>,
    secret: Option<Secret>,
    credential_cache_key: Option<String>,
    started_at: Instant,
    metrics: Arc<ProxyMetrics>,
    metrics_finished: bool,
}

impl MitmRequestCtx {
    fn new(metrics: Arc<ProxyMetrics>) -> Self {
        metrics.request_started();
        MitmRequestCtx {
            upstream: None,
            upstream_address: None,
            secret: None,
            credential_cache_key: None,
            started_at: Instant::now(),
            metrics,
            metrics_finished: false,
        }
    }

    fn finish_metrics(&mut self, upstream: &str, status: u16) {
        if self.metrics_finished {
            return;
        }
        self.metrics
            .request_finished(upstream, status, self.started_at.elapsed().as_secs_f64());
        self.metrics_finished = true;
    }
}

impl Drop for MitmRequestCtx {
    fn drop(&mut self) {
        if !self.metrics_finished {
            self.metrics.request_abandoned();
        }
    }
}

/// The HTTP service used only after a successful, bound CONNECT + TLS
/// handshake. It intentionally has no Router or JWT verifier: its authority
/// comes exclusively from `MitmConnectionContext` attached to the TLS digest.
pub struct MitmProxyService {
    credentials: Arc<dyn CredentialProvider>,
    metrics: Arc<ProxyMetrics>,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl MitmProxyService {
    pub fn new(
        credentials: Arc<dyn CredentialProvider>,
        metrics: Arc<ProxyMetrics>,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        MitmProxyService {
            credentials,
            metrics,
            connect_timeout,
            idle_timeout,
        }
    }

    async fn reject(
        &self,
        session: &mut Session,
        ctx: &MitmRequestCtx,
        status: u16,
        reason: &'static str,
        body: &'static [u8],
    ) -> Result<bool> {
        let upstream = ctx
            .upstream
            .as_ref()
            .map(|upstream| upstream.name.as_str())
            .unwrap_or("unrouted");
        self.metrics.rejection(upstream, reason, status);
        log::warn!(
            "MITM request rejected status={status} reason={reason} upstream={upstream} \
             method={:?} path={:?}",
            session.req_header().method.as_str(),
            session.req_header().uri.path(),
        );
        session
            .respond_error_with_body(status, Bytes::from_static(body))
            .await?;
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for MitmProxyService {
    type CTX = MitmRequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        MitmRequestCtx::new(self.metrics.clone())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let Some(connection) = session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .and_then(|digest| digest.extension.get::<MitmConnectionContext>())
            .cloned()
        else {
            return self
                .reject(
                    session,
                    ctx,
                    403,
                    "missing_mitm_context",
                    b"intercept context missing",
                )
                .await;
        };
        let upstream = connection.upstream.clone();
        ctx.upstream = Some(upstream.clone());
        ctx.upstream_address = Some(connection.upstream_address);

        if !upstream.intercept_connect
            || upstream.kind != UpstreamKind::Api
            || upstream.mode != UpstreamMode::Inject
        {
            return self
                .reject(
                    session,
                    ctx,
                    403,
                    "invalid_mitm_route",
                    b"intercept route unavailable",
                )
                .await;
        }
        if jsonwebtoken::get_current_timestamp() >= connection.expires_at {
            return self
                .reject(session, ctx, 401, "expired_connect_token", b"token expired")
                .await;
        }
        if !request_authority_matches_context(session.req_header(), &connection) {
            return self
                .reject(
                    session,
                    ctx,
                    421,
                    "authority_mismatch",
                    b"CONNECT authority does not match request host",
                )
                .await;
        }

        let method = session.req_header().method.as_str().to_string();
        let path = session.req_header().uri.path().to_string();
        if !authorize(&connection.scopes, &upstream, &method, &path) {
            return self
                .reject(session, ctx, 403, "forbidden_scope", b"not allowed")
                .await;
        }

        let provider = upstream
            .credential
            .as_ref()
            .ok_or_else(|| Error::new_str("intercept route missing credential"))?
            .provider_name();
        let started = Instant::now();
        match self.credentials.resolve(&upstream, &method, &path).await {
            Ok(credential) => {
                self.metrics.credential_resolution(
                    &upstream.name,
                    provider,
                    credential.result,
                    started.elapsed().as_secs_f64(),
                );
                ctx.secret = Some(credential.secret);
                ctx.credential_cache_key = credential.cache_key;
                Ok(false)
            }
            Err(error) => {
                self.metrics.credential_resolution(
                    &upstream.name,
                    provider,
                    "error",
                    started.elapsed().as_secs_f64(),
                );
                log::error!(
                    "MITM credential resolution failed upstream={}: {error}",
                    upstream.name
                );
                session
                    .respond_error_with_body(
                        502,
                        Bytes::from_static(b"upstream secret unavailable"),
                    )
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
            .ok_or_else(|| Error::new_str("intercept upstream missing in context"))?;
        let address = ctx
            .upstream_address
            .ok_or_else(|| Error::new_str("intercept upstream address missing in context"))?;
        Ok(Box::new(configured_upstream_peer(
            upstream,
            address,
            self.connect_timeout,
            self.idle_timeout,
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // The outer CONNECT credential is hop-local. The decrypted client
        // Authorization header is never Trust authentication and is removed
        // before injecting the configured provider credential.
        upstream_request.remove_header("proxy-authorization");
        upstream_request.remove_header("authorization");
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("intercept upstream missing in context"))?;
        let injection = upstream
            .injection
            .as_ref()
            .ok_or_else(|| Error::new_str("intercept route missing injection"))?;
        let secret = ctx
            .secret
            .as_ref()
            .ok_or_else(|| Error::new_str("intercept credential missing"))?;
        inject(upstream_request, injection, secret.expose())
            .map_err(|_| Error::new_str("intercept secret injection failed"))?;
        if matches!(upstream.credential, Some(CredentialSource::GcpAdc { .. })) {
            upstream_request.remove_header("accept-encoding");
        }
        let origin_authority = origin_authority(upstream);
        upstream_request
            .insert_header("host", origin_authority.as_str())
            .map_err(|_| Error::new_str("failed to set intercept upstream host"))?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if upstream_response.status.as_u16() == 401
            && let Some(cache_key) = ctx.credential_cache_key.as_deref()
        {
            self.credentials.invalidate(cache_key).await;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        let status = session
            .response_written()
            .map(|response| response.status.as_u16())
            .unwrap_or(0);
        let upstream = ctx
            .upstream
            .as_ref()
            .map(|upstream| upstream.name.clone())
            .unwrap_or_else(|| "unrouted".to_string());
        ctx.finish_metrics(&upstream, status);
    }
}

fn origin_authority(upstream: &Upstream) -> String {
    let origin = &upstream.origin;
    if (origin.tls && origin.port == 443) || (!origin.tls && origin.port == 80) {
        origin.host.clone()
    } else {
        format!("{}:{}", origin.host, origin.port)
    }
}

fn configured_upstream_peer(
    upstream: &Upstream,
    address: SocketAddr,
    connect_timeout: Duration,
    idle_timeout: Duration,
) -> HttpPeer {
    let mut peer = HttpPeer::new(address, upstream.origin.tls, upstream.origin.sni.clone());
    // Preserve the forward proxy's egress timeouts. The address was resolved
    // and checked before CONNECT succeeded, so constructing the peer from it
    // also prevents DNS rebinding from bypassing that policy.
    peer.options.connection_timeout = Some(connect_timeout);
    peer.options.total_connection_timeout = Some(connect_timeout);
    peer.options.read_timeout = Some(idle_timeout);
    peer.options.write_timeout = Some(idle_timeout);
    peer.options.idle_timeout = Some(idle_timeout);
    peer
}

fn host_matches_context(value: Option<&str>, context: &MitmConnectionContext) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = value.strip_suffix('.').unwrap_or(value);
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse::<u16>() {
            Ok(port) => (host, port),
            Err(_) => return false,
        },
        _ => (value, 443),
    };
    host.strip_suffix('.')
        .unwrap_or(host)
        .eq_ignore_ascii_case(&context.authority_host)
        && port == context.authority_port
}

fn request_authority_matches_context(
    request: &RequestHeader,
    context: &MitmConnectionContext,
) -> bool {
    // HTTPS requests inside a CONNECT tunnel must use origin-form. Accepting
    // an absolute URI would introduce a second caller-controlled authority
    // alongside Host, even though the upstream connection itself is frozen.
    if request.uri.scheme().is_some() || request.uri.authority().is_some() {
        return false;
    }

    let mut hosts = request.headers.get_all("host").iter();
    let Some(host) = hosts.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    hosts.next().is_none() && host_matches_context(Some(host), context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialSource, Injection, InjectionScheme, Origin};
    use crate::scope::ScopeSet;

    fn context(host: &str, port: u16) -> MitmConnectionContext {
        MitmConnectionContext {
            upstream: Arc::new(Upstream {
                name: "provider".into(),
                kind: UpstreamKind::Api,
                listen_host: "provider.trust.internal".into(),
                origin: Origin {
                    host: host.into(),
                    port,
                    tls: true,
                    sni: host.into(),
                },
                mode: UpstreamMode::Inject,
                credential: Some(CredentialSource::StaticSecret {
                    secret_ref: "provider-key".into(),
                }),
                injection: Some(Injection {
                    header: "x-api-key".into(),
                    scheme: InjectionScheme::Raw,
                }),
                resource: None,
                git: None,
                allowed_methods: Vec::new(),
                allow_connect: false,
                intercept_connect: true,
            }),
            authority_host: host.into(),
            authority_port: port,
            upstream_address: "127.0.0.1:443".parse().unwrap(),
            subject: "sandbox".into(),
            scopes: ScopeSet::parse("provider").unwrap(),
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn host_must_match_the_bound_connect_authority() {
        let context = context("api.example.com", 443);
        assert!(host_matches_context(Some("API.EXAMPLE.COM"), &context));
        assert!(host_matches_context(Some("api.example.com:443"), &context));
        assert!(!host_matches_context(Some("other.example.com"), &context));
        assert!(!host_matches_context(
            Some("api.example.com:8443"),
            &context
        ));
        assert!(!host_matches_context(None, &context));
    }

    #[test]
    fn request_must_use_a_single_origin_form_host() {
        let context = context("api.example.com", 443);
        let mut request = RequestHeader::build("GET", b"/v1/messages", None).unwrap();
        request.insert_header("host", "api.example.com").unwrap();
        assert!(request_authority_matches_context(&request, &context));

        request.append_header("host", "api.example.com").unwrap();
        assert!(!request_authority_matches_context(&request, &context));
    }

    #[test]
    fn preserves_non_default_origin_port_in_upstream_host() {
        let non_default_context = context("api.example.com", 8443);
        assert_eq!(
            origin_authority(&non_default_context.upstream),
            "api.example.com:8443"
        );
        assert_eq!(
            origin_authority(&context("api.example.com", 443).upstream),
            "api.example.com"
        );
    }

    #[test]
    fn uses_the_policy_checked_address_and_forward_proxy_timeouts() {
        let context = context("api.example.com", 443);
        let peer = configured_upstream_peer(
            &context.upstream,
            "203.0.113.10:443".parse().unwrap(),
            Duration::from_secs(3),
            Duration::from_secs(7),
        );

        assert_eq!(peer.sni, "api.example.com");
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            peer.options.total_connection_timeout,
            Some(Duration::from_secs(3))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(7)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(7)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_secs(7)));
        assert!(peer.options.verify_cert);
        assert!(peer.options.verify_hostname);
    }
}
