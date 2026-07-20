use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::header::{
    CONNECTION, HOST, HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
    TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant as TokioInstant, sleep_until, timeout};
use tokio_rustls::TlsAcceptor;

use crate::config::{AUDIT_UNMATCHED_METRICS_NAME, ForwardProxyConfig};
use crate::jwt::{VerifiedToken, Verifier};
use crate::keystore::Keystore;
use crate::metrics::ProxyMetrics;
use crate::mitm::MitmConnectionContext;
use crate::mitm::runtime::MitmRuntime;
use crate::router::{ConnectRoute, Router};

type ResponseBody = BoxBody<Bytes, hyper::Error>;
type ProxyResponse = Response<ResponseBody>;
type ProxyResult<T> = Result<T, Box<ProxyResponse>>;

#[derive(Clone, Copy)]
enum ForwardOperation {
    Connect,
    Http,
}

impl ForwardOperation {
    fn label(self) -> &'static str {
        match self {
            ForwardOperation::Connect => "CONNECT",
            ForwardOperation::Http => "HTTP",
        }
    }
}

enum ConnectDestination {
    ConfiguredOpaque(Arc<crate::config::Upstream>),
    ConfiguredIntercept(Arc<crate::config::Upstream>),
    Audit {
        host: String,
        port: u16,
        scope: String,
    },
}

impl ConnectDestination {
    fn metrics_name(&self) -> &str {
        match self {
            ConnectDestination::ConfiguredOpaque(upstream)
            | ConnectDestination::ConfiguredIntercept(upstream) => &upstream.name,
            ConnectDestination::Audit { .. } => AUDIT_UNMATCHED_METRICS_NAME,
        }
    }

    fn required_scope(&self) -> &str {
        match self {
            ConnectDestination::ConfiguredOpaque(upstream)
            | ConnectDestination::ConfiguredIntercept(upstream) => &upstream.name,
            ConnectDestination::Audit { scope, .. } => scope,
        }
    }

    fn target(&self) -> (&str, u16) {
        match self {
            ConnectDestination::ConfiguredOpaque(upstream)
            | ConnectDestination::ConfiguredIntercept(upstream) => {
                (&upstream.origin.host, upstream.origin.port)
            }
            ConnectDestination::Audit { host, port, .. } => (host, *port),
        }
    }

    fn is_audit(&self) -> bool {
        matches!(self, ConnectDestination::Audit { .. })
    }

    fn permits_private_ips(&self, configured_allow_private_ips: bool) -> bool {
        // An audit scope intentionally permits only public generic egress.
        // The global switch exists solely for exact, operator-configured
        // internal routes, never for caller-selected fallback destinations.
        !self.is_audit() && configured_allow_private_ips
    }
}

pub struct ConnectProxy {
    router: Arc<Router>,
    verifier: Arc<Verifier>,
    keystore: Arc<Keystore>,
    metrics: Arc<ProxyMetrics>,
    config: ForwardProxyConfig,
    tunnel_slots: Arc<Semaphore>,
    mitm: Option<Arc<MitmRuntime>>,
}

impl ConnectProxy {
    pub fn new(
        router: Arc<Router>,
        verifier: Arc<Verifier>,
        keystore: Arc<Keystore>,
        metrics: Arc<ProxyMetrics>,
        config: ForwardProxyConfig,
    ) -> ConnectProxy {
        ConnectProxy::with_mitm(router, verifier, keystore, metrics, config, None)
    }

    pub fn with_mitm(
        router: Arc<Router>,
        verifier: Arc<Verifier>,
        keystore: Arc<Keystore>,
        metrics: Arc<ProxyMetrics>,
        config: ForwardProxyConfig,
        mitm: Option<Arc<MitmRuntime>>,
    ) -> ConnectProxy {
        let tunnel_slots = Arc::new(Semaphore::new(config.max_concurrent_tunnels));
        ConnectProxy {
            router,
            verifier,
            keystore,
            metrics,
            config,
            tunnel_slots,
            mitm,
        }
    }

    fn start_background_tasks(&self) {
        if let Some(mitm) = &self.mitm {
            mitm.start_background_refresh();
        }
    }

    fn record_attempt(&self, operation: ForwardOperation, upstream: &str, result: &str) {
        match operation {
            ForwardOperation::Connect => self.metrics.connect_attempt(upstream, result),
            ForwardOperation::Http => self.metrics.forward_proxy_request(upstream, result),
        }
    }

    fn resolve_destination(
        &self,
        host: &str,
        port: u16,
        operation: ForwardOperation,
    ) -> ProxyResult<ConnectDestination> {
        match self.router.resolve_connect(host, port) {
            Some(ConnectRoute::Opaque(upstream)) => {
                Ok(ConnectDestination::ConfiguredOpaque(upstream))
            }
            Some(ConnectRoute::Intercept(upstream)) => {
                if matches!(operation, ForwardOperation::Http) {
                    self.record_attempt(operation, &upstream.name, "intercept_requires_connect");
                    return Err(Box::new(response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "intercepted destinations require HTTPS CONNECT\n",
                    )));
                }
                Ok(ConnectDestination::ConfiguredIntercept(upstream))
            }
            None => match &self.config.audit_unmatched {
                Some(audit) => {
                    log::warn!(
                        "{} unmatched destination observed action=audit_allow_pending_auth \
                         destination_host={host:?} destination_port={port} required_scope={:?}",
                        operation.label(),
                        audit.scope
                    );
                    Ok(ConnectDestination::Audit {
                        host: host.to_string(),
                        port,
                        scope: audit.scope.clone(),
                    })
                }
                None => {
                    self.record_attempt(operation, "unrouted", "unknown_destination");
                    log::warn!(
                        "{} rejected reason=unknown_destination destination_host={host:?} \
                         destination_port={port}",
                        operation.label(),
                    );
                    Err(Box::new(response(
                        StatusCode::FORBIDDEN,
                        "destination not allowed\n",
                    )))
                }
            },
        }
    }

    fn authorize(
        &self,
        headers: &hyper::HeaderMap,
        destination: &ConnectDestination,
        host: &str,
        port: u16,
        operation: ForwardOperation,
    ) -> ProxyResult<VerifiedToken> {
        let metrics_name = destination.metrics_name();
        let token = match proxy_token(headers.get(PROXY_AUTHORIZATION)) {
            Ok(token) => token,
            Err(reason) => {
                self.record_attempt(operation, metrics_name, reason);
                log::warn!(
                    "{} rejected reason={reason} upstream={metrics_name} \
                     destination_host={host:?} destination_port={port}",
                    operation.label(),
                );
                return Err(Box::new(proxy_auth_required()));
            }
        };
        let Some(keys) = self.keystore.load() else {
            self.record_attempt(operation, metrics_name, "signing_keys_unavailable");
            return Err(Box::new(response(
                StatusCode::SERVICE_UNAVAILABLE,
                "signing keys unavailable\n",
            )));
        };
        let verified = match self.verifier.verify_token(&keys, &token) {
            Ok(verified) => verified,
            Err(_) => {
                self.record_attempt(operation, metrics_name, "invalid_token");
                return Err(Box::new(proxy_auth_required()));
            }
        };
        if !verified.scopes.permits(destination.required_scope(), None) {
            self.record_attempt(operation, metrics_name, "forbidden_scope");
            log::warn!(
                "{} rejected reason=forbidden_scope upstream={metrics_name} subject={:?} \
                 destination_host={host:?} destination_port={port}",
                operation.label(),
                verified.subject,
            );
            return Err(Box::new(response(StatusCode::FORBIDDEN, "not allowed\n")));
        }
        Ok(verified)
    }

    async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        if request.method() == Method::CONNECT {
            self.handle_connect(request).await
        } else {
            self.handle_http(request).await
        }
    }

    async fn handle_connect(
        self: Arc<Self>,
        mut request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        let Some(authority) = request.uri().authority() else {
            self.record_attempt(ForwardOperation::Connect, "unrouted", "invalid_authority");
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT authority\n",
            ));
        };
        let Some(port) = authority.port_u16() else {
            self.record_attempt(ForwardOperation::Connect, "unrouted", "invalid_authority");
            return Ok(response(StatusCode::BAD_REQUEST, "CONNECT port required\n"));
        };
        let host = authority.host().to_string();
        let destination = match self.resolve_destination(&host, port, ForwardOperation::Connect) {
            Ok(destination) => destination,
            Err(response) => return Ok(*response),
        };
        let metrics_name = destination.metrics_name();
        let verified = match self.authorize(
            request.headers(),
            &destination,
            &host,
            port,
            ForwardOperation::Connect,
        ) {
            Ok(verified) => verified,
            Err(response) => return Ok(*response),
        };

        let Some(max_duration) = tunnel_duration(&verified, self.config.max_tunnel_duration) else {
            self.record_attempt(ForwardOperation::Connect, metrics_name, "invalid_token");
            return Ok(proxy_auth_required());
        };
        let deadline = TokioInstant::now() + max_duration;
        let tunnel_slot = match self.tunnel_slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                self.record_attempt(ForwardOperation::Connect, metrics_name, "capacity_exceeded");
                log::warn!(
                    "CONNECT rejected reason=capacity_exceeded upstream={metrics_name} \
                     subject={:?} destination_host={host:?} destination_port={port}",
                    verified.subject,
                );
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "proxy tunnel capacity exceeded\n",
                ));
            }
        };

        if let ConnectDestination::ConfiguredIntercept(upstream) = &destination {
            let Some(mitm) = self.mitm.clone() else {
                self.record_attempt(ForwardOperation::Connect, metrics_name, "mitm_not_ready");
                log::error!(
                    "CONNECT interception rejected reason=mitm_not_ready upstream={metrics_name} \
                     subject={:?} destination_host={host:?} destination_port={port}",
                    verified.subject,
                );
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TLS interception is not initialized\n",
                ));
            };
            let Some(remaining) = deadline_remaining(deadline) else {
                self.record_attempt(ForwardOperation::Connect, metrics_name, "invalid_token");
                return Ok(proxy_auth_required());
            };
            let upstream_addresses = match resolve_targets(
                &upstream.origin.host,
                upstream.origin.port,
                destination.permits_private_ips(self.config.allow_private_ips),
                self.config.connect_timeout.min(remaining),
            )
            .await
            {
                Ok(address) => address,
                Err(error) => {
                    let reason = if error.kind() == io::ErrorKind::PermissionDenied {
                        "private_destination"
                    } else {
                        "connect_failed"
                    };
                    self.record_attempt(ForwardOperation::Connect, metrics_name, reason);
                    log::warn!(
                        "CONNECT interception target failed reason={reason} upstream={metrics_name} \
                         subject={:?} destination_host={host:?} destination_port={port}: {error}",
                        verified.subject,
                    );
                    return Ok(response(StatusCode::BAD_GATEWAY, "connection failed\n"));
                }
            };
            let connection = Arc::new(MitmConnectionContext {
                upstream: upstream.clone(),
                authority_host: upstream.origin.host.clone(),
                authority_port: upstream.origin.port,
                upstream_addresses,
                subject: verified.subject.clone(),
                scopes: verified.scopes.clone(),
                expires_at: verified.expires_at,
            });
            let upgrade = hyper::upgrade::on(&mut request);
            self.metrics.connect_started(metrics_name);
            let state = self.clone();
            let upstream_name = metrics_name.to_string();
            let subject = verified.subject;
            tokio::spawn(async move {
                let _tunnel_slot = tunnel_slot;
                let started = Instant::now();
                match upgrade.await {
                    Ok(upgraded) => {
                        if let Err(error) = mitm.intercept(upgraded, connection, deadline).await {
                            log::warn!(
                                "MITM CONNECT ended upstream={upstream_name} subject={subject:?}: {error}"
                            );
                        }
                    }
                    Err(error) => {
                        log::warn!(
                            "CONNECT upgrade failed upstream={upstream_name} subject={subject:?}: {error}"
                        );
                    }
                }
                state.metrics.connect_finished(
                    &upstream_name,
                    started.elapsed().as_secs_f64(),
                    0,
                    0,
                );
            });
            return Ok(response(StatusCode::OK, ""));
        }

        let Some(remaining) = deadline_remaining(deadline) else {
            self.record_attempt(ForwardOperation::Connect, metrics_name, "invalid_token");
            return Ok(proxy_auth_required());
        };
        let (target_host, target_port) = destination.target();
        let target = match connect_target(
            target_host,
            target_port,
            destination.permits_private_ips(self.config.allow_private_ips),
            self.config.connect_timeout.min(remaining),
        )
        .await
        {
            Ok(stream) => stream,
            Err(error) => {
                let reason = if error.kind() == io::ErrorKind::PermissionDenied {
                    "private_destination"
                } else {
                    "connect_failed"
                };
                self.record_attempt(ForwardOperation::Connect, metrics_name, reason);
                log::warn!(
                    "CONNECT target failed reason={reason} upstream={metrics_name} subject={:?} \
                     destination_host={host:?} destination_port={port}: {error}",
                    verified.subject,
                );
                return Ok(response(StatusCode::BAD_GATEWAY, "connection failed\n"));
            }
        };

        let upgrade = hyper::upgrade::on(&mut request);
        self.metrics.connect_started(metrics_name);
        if destination.is_audit() {
            log::warn!(
                "CONNECT unmatched destination allowed action=audit_allow result=established \
                 destination_host={host:?} destination_port={port} subject={:?}",
                verified.subject
            );
        }
        let state = self.clone();
        let upstream_name = metrics_name.to_string();
        let subject = verified.subject;
        tokio::spawn(async move {
            let _tunnel_slot = tunnel_slot;
            let started = Instant::now();
            let (to_upstream, to_client) = match upgrade.await {
                Ok(upgraded) => {
                    tunnel(
                        TokioIo::new(upgraded),
                        target,
                        state.config.idle_timeout,
                        deadline,
                    )
                    .await
                }
                Err(error) => {
                    log::warn!(
                        "CONNECT upgrade failed upstream={upstream_name} subject={subject:?}: {error}"
                    );
                    (0, 0)
                }
            };
            state.metrics.connect_finished(
                &upstream_name,
                started.elapsed().as_secs_f64(),
                to_upstream,
                to_client,
            );
        });

        Ok(response(StatusCode::OK, ""))
    }

    async fn handle_http(
        self: Arc<Self>,
        mut request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        if request.uri().scheme_str() != Some("http") {
            self.record_attempt(ForwardOperation::Http, "unrouted", "invalid_request_target");
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "absolute http URI required; use CONNECT for HTTPS\n",
            ));
        }
        let Some(host) = request.uri().host().map(ToOwned::to_owned) else {
            self.record_attempt(ForwardOperation::Http, "unrouted", "invalid_authority");
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "invalid proxy authority\n",
            ));
        };
        let port = request.uri().port_u16().unwrap_or(80);
        let authority = request
            .uri()
            .authority()
            .map(ToOwned::to_owned)
            .expect("absolute HTTP URI has an authority");
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let destination = match self.resolve_destination(&host, port, ForwardOperation::Http) {
            Ok(destination) => destination,
            Err(response) => return Ok(*response),
        };
        let metrics_name = destination.metrics_name();
        let verified = match self.authorize(
            request.headers(),
            &destination,
            &host,
            port,
            ForwardOperation::Http,
        ) {
            Ok(verified) => verified,
            Err(response) => return Ok(*response),
        };
        let method = request.method().clone();
        let Some(max_duration) = tunnel_duration(&verified, self.config.max_tunnel_duration) else {
            self.record_attempt(ForwardOperation::Http, metrics_name, "invalid_token");
            return Ok(proxy_auth_required());
        };
        let deadline = TokioInstant::now() + max_duration;
        let tunnel_slot = match self.tunnel_slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                self.record_attempt(ForwardOperation::Http, metrics_name, "capacity_exceeded");
                log::warn!(
                    "HTTP rejected reason=capacity_exceeded upstream={metrics_name} \
                     subject={:?} destination_host={host:?} destination_port={port}",
                    verified.subject,
                );
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "proxy tunnel capacity exceeded\n",
                ));
            }
        };
        let Some(remaining) = deadline_remaining(deadline) else {
            self.record_attempt(ForwardOperation::Http, metrics_name, "invalid_token");
            return Ok(proxy_auth_required());
        };

        let (target_host, target_port) = destination.target();
        let target = match connect_target(
            target_host,
            target_port,
            destination.permits_private_ips(self.config.allow_private_ips),
            self.config.connect_timeout.min(remaining),
        )
        .await
        {
            Ok(stream) => stream,
            Err(error) => {
                let reason = if error.kind() == io::ErrorKind::PermissionDenied {
                    "private_destination"
                } else {
                    "connect_failed"
                };
                self.record_attempt(ForwardOperation::Http, metrics_name, reason);
                log::warn!(
                    "HTTP target failed reason={reason} upstream={metrics_name} subject={:?} \
                     destination_host={host:?} destination_port={port}: {error}",
                    verified.subject,
                );
                return Ok(response(StatusCode::BAD_GATEWAY, "connection failed\n"));
            }
        };

        let origin_uri = match path_and_query.parse() {
            Ok(uri) => uri,
            Err(_) => {
                self.record_attempt(
                    ForwardOperation::Http,
                    metrics_name,
                    "invalid_request_target",
                );
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "invalid request target\n",
                ));
            }
        };
        let host_header = match HeaderValue::from_str(authority.as_str()) {
            Ok(value) => value,
            Err(_) => {
                self.record_attempt(ForwardOperation::Http, metrics_name, "invalid_authority");
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    "invalid proxy authority\n",
                ));
            }
        };
        *request.uri_mut() = origin_uri;
        strip_proxy_headers(request.headers_mut());
        request.headers_mut().insert(HOST, host_header);

        let (activity_tx, mut activity_rx) = mpsc::channel(1);
        let (mut sender, connection) =
            match client_http1::handshake(TokioIo::new(ActivityIo::new(target, activity_tx))).await
            {
                Ok(connection) => connection,
                Err(error) => {
                    self.record_attempt(ForwardOperation::Http, metrics_name, "connect_failed");
                    log::warn!(
                        "HTTP upstream handshake failed upstream={metrics_name} subject={:?} \
                     destination_host={host:?} destination_port={port}: {error}",
                        verified.subject,
                    );
                    return Ok(response(StatusCode::BAD_GATEWAY, "connection failed\n"));
                }
            };
        let upstream_name = metrics_name.to_string();
        let idle_timeout = self.config.idle_timeout;
        tokio::spawn(async move {
            let _tunnel_slot = tunnel_slot;
            let mut connection = Box::pin(connection);
            let idle = sleep_until(TokioInstant::now() + idle_timeout);
            let maximum = sleep_until(deadline);
            tokio::pin!(idle);
            tokio::pin!(maximum);
            let mut activity_open = true;
            loop {
                tokio::select! {
                    result = &mut connection => {
                        if let Err(error) = result {
                            log::debug!("HTTP upstream connection ended upstream={upstream_name}: {error}");
                        }
                        break;
                    }
                    activity = activity_rx.recv(), if activity_open => {
                        match activity {
                            Some(()) => idle.as_mut().reset(TokioInstant::now() + idle_timeout),
                            None => activity_open = false,
                        }
                    }
                    _ = &mut idle => {
                        log::debug!("HTTP forward-proxy connection reached idle timeout upstream={upstream_name}");
                        break;
                    }
                    _ = &mut maximum => {
                        log::debug!("HTTP forward-proxy connection reached maximum duration upstream={upstream_name}");
                        break;
                    }
                }
            }
        });
        let upstream_response = match sender.send_request(request).await {
            Ok(response) => response,
            Err(error) => {
                self.record_attempt(ForwardOperation::Http, metrics_name, "request_failed");
                log::warn!(
                    "HTTP upstream request failed upstream={metrics_name} subject={:?} \
                     destination_host={host:?} destination_port={port}: {error}",
                    verified.subject,
                );
                return Ok(response(
                    StatusCode::BAD_GATEWAY,
                    "upstream request failed\n",
                ));
            }
        };
        self.record_attempt(
            ForwardOperation::Http,
            metrics_name,
            upstream_response.status().as_str(),
        );
        if destination.is_audit() {
            log::warn!(
                "HTTP unmatched destination allowed action=audit_allow result=forwarded \
                 destination_host={host:?} destination_port={port} method={method:?} subject={:?}",
                verified.subject,
            );
        }
        Ok(upstream_response.map(|body| body.boxed()))
    }
}

fn response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(body.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static proxy response")
}

fn strip_proxy_headers(headers: &mut hyper::HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    headers.remove(CONNECTION);
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(PROXY_AUTHENTICATE);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove(HeaderName::from_static("proxy-connection"));
    for name in connection_headers {
        headers.remove(name);
    }
}

fn proxy_auth_required() -> Response<ResponseBody> {
    let mut response = response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required\n",
    );
    response.headers_mut().insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"trust\", Basic realm=\"trust\""),
    );
    response
}

fn proxy_token(value: Option<&HeaderValue>) -> Result<String, &'static str> {
    let Some(value) = value else {
        return Err("missing_token");
    };
    let value = value.to_str().map_err(|_| "invalid_token")?;
    let Some((scheme, credentials)) = value.split_once(' ') else {
        return Err("invalid_token");
    };
    if scheme.eq_ignore_ascii_case("bearer") && !credentials.is_empty() {
        return Ok(credentials.to_string());
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err("invalid_token");
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(credentials)
        .map_err(|_| "invalid_token")?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| "invalid_token")?;
    let Some((username, token)) = decoded.split_once(':') else {
        return Err("invalid_token");
    };
    if username != "jwt" || token.is_empty() {
        return Err("invalid_token");
    }
    Ok(token.to_string())
}

fn tunnel_duration(token: &VerifiedToken, configured_max: Duration) -> Option<Duration> {
    let now = jsonwebtoken::get_current_timestamp();
    let token_remaining = Duration::from_secs(token.expires_at.checked_sub(now)?);
    let duration = configured_max.min(token_remaining);
    (!duration.is_zero()).then_some(duration)
}

fn deadline_remaining(deadline: TokioInstant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(TokioInstant::now());
    (!remaining.is_zero()).then_some(remaining)
}

async fn resolved_target_addresses(
    host: &str,
    port: u16,
    allow_private_ips: bool,
) -> io::Result<Vec<SocketAddr>> {
    let addresses = tokio::net::lookup_host((host, port)).await?;
    let permitted = addresses
        .filter(|address| allow_private_ips || is_public_ip(address.ip()))
        .collect::<Vec<_>>();
    if permitted.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination resolved only to non-public addresses",
        ));
    }
    Ok(permitted)
}

async fn resolve_targets(
    host: &str,
    port: u16,
    allow_private_ips: bool,
    connect_timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    let addresses = timeout(
        connect_timeout,
        resolved_target_addresses(host, port, allow_private_ips),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "CONNECT target timed out"))??;
    Ok(addresses)
}

async fn connect_target(
    host: &str,
    port: u16,
    allow_private_ips: bool,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    timeout(connect_timeout, async {
        let addresses = resolved_target_addresses(host, port, allow_private_ips).await?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "destination did not resolve")
        }))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "CONNECT target timed out"))?
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(octets[0] == 0
                || ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                // IANA's benchmarking range 198.18.0.0/15.
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                // IETF protocol assignments at 192.0.0.0/24. The two
                // documented globally reachable anycast addresses are the
                // only exceptions.
                || (octets[0] == 192
                    && octets[1] == 0
                    && octets[2] == 0
                    && !matches!(octets[3], 9 | 10))
                // Multicast, reserved, and limited-broadcast ranges.
                || octets[0] >= 224)
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            // Permit only the currently assigned global-unicast range, then
            // exclude IANA special-purpose blocks inside it. This mirrors the
            // stable policy intent of the standard library's unstable
            // `Ipv6Addr::is_global` API without allowing future special-use
            // ranges by default.
            let global_unicast = (segments[0] & 0xe000) == 0x2000;
            let ietf_protocol_assignment = segments[0] == 0x2001 && segments[1] < 0x0200;
            let ietf_global_exception = matches!(
                segments,
                [0x2001, 0x0001, 0, 0, 0, 0, 0, 1]
                    | [0x2001, 0x0001, 0, 0, 0, 0, 0, 2]
                    | [0x2001, 0x0003, _, _, _, _, _, _]
                    | [0x2001, 0x0004, 0x0112, _, _, _, _, _]
                    | [0x2001, 0x0020..=0x003f, _, _, _, _, _, _]
            );
            global_unicast
                && !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || (ietf_protocol_assignment && !ietf_global_exception)
                    || segments[0] == 0x2002
                    || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                    || (segments[0] == 0x3fff && segments[1] <= 0x0fff))
        }
    }
}

/// A transparent IO adapter that reports completed byte transfers to the
/// request lifecycle watchdog. The watchdog owns the actual idle/deadline
/// timers so it can terminate a stalled HTTP request or response even when
/// Hyper is not currently polling this transport.
struct ActivityIo<T> {
    inner: T,
    activity: mpsc::Sender<()>,
}

impl<T> ActivityIo<T> {
    fn new(inner: T, activity: mpsc::Sender<()>) -> Self {
        ActivityIo { inner, activity }
    }

    fn record_activity(&self) {
        let _ = self.activity.try_send(());
    }
}

impl<T> AsyncRead for ActivityIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before {
                    self.record_activity();
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<T> AsyncWrite for ActivityIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.record_activity();
                }
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write_vectored(cx, buffers) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.record_activity();
                }
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    activity: mpsc::Sender<()>,
    bytes: Arc<AtomicU64>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        bytes.fetch_add(read as u64, Ordering::Relaxed);
        let _ = activity.try_send(());
    }
}

async fn tunnel<D>(
    downstream: D,
    upstream: TcpStream,
    idle_timeout: Duration,
    deadline: TokioInstant,
) -> (u64, u64)
where
    D: AsyncRead + AsyncWrite + Unpin,
{
    let (downstream_read, downstream_write) = tokio::io::split(downstream);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let to_upstream = Arc::new(AtomicU64::new(0));
    let to_client = Arc::new(AtomicU64::new(0));
    let mut upload = Box::pin(pump(
        downstream_read,
        upstream_write,
        activity_tx.clone(),
        to_upstream.clone(),
    ));
    let mut download = Box::pin(pump(
        upstream_read,
        downstream_write,
        activity_tx,
        to_client.clone(),
    ));
    let mut upload_done = false;
    let mut download_done = false;
    let idle = sleep_until(TokioInstant::now() + idle_timeout);
    let maximum = sleep_until(deadline);
    tokio::pin!(idle);
    tokio::pin!(maximum);

    while !upload_done || !download_done {
        tokio::select! {
            result = &mut upload, if !upload_done => {
                upload_done = true;
                if let Err(error) = result {
                    log::debug!("CONNECT upload ended with error: {error}");
                }
            }
            result = &mut download, if !download_done => {
                download_done = true;
                if let Err(error) = result {
                    log::debug!("CONNECT download ended with error: {error}");
                }
            }
            activity = activity_rx.recv() => {
                if activity.is_some() {
                    idle.as_mut().reset(TokioInstant::now() + idle_timeout);
                }
            }
            _ = &mut idle => {
                log::debug!("CONNECT tunnel reached idle timeout");
                break;
            }
            _ = &mut maximum => {
                log::debug!("CONNECT tunnel reached maximum duration");
                break;
            }
        }
    }

    (
        to_upstream.load(Ordering::Relaxed),
        to_client.load(Ordering::Relaxed),
    )
}

async fn serve_io<I>(io: I, state: Arc<ConnectProxy>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| state.clone().handle(request));
    if let Err(error) = http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await
    {
        log::debug!("forward-proxy client connection ended: {error}");
    }
}

pub async fn serve_connect(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    state: Arc<ConnectProxy>,
) -> io::Result<()> {
    let tls = tls.map(TlsAcceptor::from);
    state.start_background_tasks();
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(stream) => serve_io(stream, state).await,
                    Err(error) => log::warn!("CONNECT TLS handshake failed peer={peer}: {error}"),
                },
                None => serve_io(stream, state).await,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuditUnmatchedConfig, Origin, Upstream, UpstreamKind, UpstreamMode};
    use crate::jwt::Issuer;
    use crate::keystore::build_key_material;
    use crate::scope::ScopeSet;

    async fn read_response_head(stream: &mut TcpStream) -> String {
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
            assert!(response.len() < 16 * 1024, "oversized response header");
        }
        String::from_utf8(response).unwrap()
    }

    #[test]
    fn public_ip_filter_rejects_internal_ranges() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.1.2.3",
            "192.0.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "240.0.0.1",
            "255.255.255.254",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
        ] {
            assert!(!is_public_ip(value.parse().unwrap()), "accepted {value}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolved_intercept_targets_reject_private_addresses() {
        let error = resolve_targets("localhost", 443, false, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn bearer_proxy_auth_is_accepted() {
        let header = HeaderValue::from_static("Bearer abc.def");
        assert_eq!(proxy_token(Some(&header)).unwrap(), "abc.def");
        assert_eq!(proxy_token(None), Err("missing_token"));

        let basic = base64::engine::general_purpose::STANDARD.encode("jwt:abc.def");
        let header = HeaderValue::from_str(&format!("Basic {basic}")).unwrap();
        assert_eq!(proxy_token(Some(&header)).unwrap(), "abc.def");
    }

    #[test]
    fn tunnel_lifetime_is_capped_by_connect_token_expiry() {
        let now = jsonwebtoken::get_current_timestamp();
        let token = VerifiedToken {
            subject: "sandbox".to_string(),
            scopes: ScopeSet::parse("provider").unwrap(),
            expires_at: now + 60,
        };
        assert_eq!(
            tunnel_duration(&token, Duration::from_secs(5)),
            Some(Duration::from_secs(5))
        );

        let expired = VerifiedToken {
            expires_at: jsonwebtoken::get_current_timestamp(),
            ..token
        };
        assert!(tunnel_duration(&expired, Duration::from_secs(5)).is_none());
    }

    #[test]
    fn strips_hop_by_hop_proxy_headers_without_touching_origin_authorization() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("x-connection-header"));
        headers.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Bearer trust-jwt"),
        );
        headers.insert(TE, HeaderValue::from_static("trailers"));
        headers.insert(TRAILER, HeaderValue::from_static("x-trailer"));
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert(
            HeaderName::from_static("x-connection-header"),
            HeaderValue::from_static("remove-me"),
        );
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer origin-token"),
        );

        strip_proxy_headers(&mut headers);

        for name in [
            "connection",
            "keep-alive",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
            "x-connection-header",
        ] {
            assert!(headers.get(name).is_none(), "{name} was forwarded");
        }
        assert_eq!(
            headers.get("authorization"),
            Some(&HeaderValue::from_static("Bearer origin-token"))
        );
    }

    #[test]
    fn audit_scope_cannot_select_an_intercepted_provider() {
        let upstream = Arc::new(Upstream {
            name: "provider".into(),
            kind: UpstreamKind::Api,
            listen_host: "provider.proxy.internal".into(),
            origin: Origin {
                host: "api.example.com".into(),
                port: 443,
                tls: true,
                sni: "api.example.com".into(),
            },
            mode: UpstreamMode::Inject,
            credential: Some(crate::config::CredentialSource::StaticSecret {
                secret_ref: "provider-key".into(),
            }),
            injection: Some(crate::config::Injection {
                header: "x-api-key".into(),
                scheme: crate::config::InjectionScheme::Raw,
            }),
            resource: None,
            git: None,
            allowed_methods: Vec::new(),
            allow_connect: false,
            intercept_connect: true,
        });
        let keystore = Arc::new(Keystore::new());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        keystore.store(build_key_material(&key.serialize_pem(), None).unwrap());
        let keys = keystore.load().unwrap();
        let token = Issuer::new("trust".into(), "proxy".into(), Duration::from_secs(60))
            .mint(
                &keys,
                "sandbox-audit",
                &ScopeSet::parse("outbound-audit").unwrap(),
                jsonwebtoken::get_current_timestamp(),
            )
            .unwrap();
        let state = ConnectProxy::new(
            Arc::new(Router::new(std::slice::from_ref(&upstream))),
            Arc::new(Verifier::new("trust".into(), "proxy".into())),
            keystore,
            Arc::new(ProxyMetrics::new()),
            ForwardProxyConfig {
                addr: "127.0.0.1:6180".into(),
                tls: false,
                connect_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(5),
                max_tunnel_duration: Duration::from_secs(30),
                max_concurrent_tunnels: 10,
                allow_private_ips: false,
                audit_unmatched: Some(AuditUnmatchedConfig {
                    scope: "outbound-audit".into(),
                }),
                mitm: None,
            },
        );
        let destination = state
            .resolve_destination("API.EXAMPLE.COM.", 443, ForwardOperation::Connect)
            .unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        let result = state.authorize(
            &headers,
            &destination,
            "api.example.com",
            443,
            ForwardOperation::Connect,
        );
        let response = match result {
            Err(response) => response,
            Ok(_) => panic!("audit scope must not authorize a named provider"),
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response =
            match state.resolve_destination("api.example.com", 443, ForwardOperation::Http) {
                Err(response) => response,
                Ok(_) => panic!("intercept routes must require CONNECT"),
            };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn connect_is_authenticated_scoped_and_tunnels_bytes() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = target.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        if stream.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let upstream = Arc::new(Upstream {
            name: "docs".into(),
            kind: UpstreamKind::Api,
            listen_host: "docs.proxy.internal".into(),
            origin: Origin {
                host: "127.0.0.1".into(),
                port: target_port,
                tls: true,
                sni: "127.0.0.1".into(),
            },
            mode: UpstreamMode::Passthrough,
            credential: None,
            injection: None,
            resource: None,
            git: None,
            allowed_methods: Vec::new(),
            allow_connect: true,
            intercept_connect: false,
        });
        let router = Arc::new(Router::new(&[upstream]));
        let keystore = Arc::new(Keystore::new());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        keystore.store(build_key_material(&key.serialize_pem(), None).unwrap());
        let keys = keystore.load().unwrap();
        let issuer = Issuer::new("trust".into(), "proxy".into(), Duration::from_secs(60));
        let now = jsonwebtoken::get_current_timestamp();
        let allowed = issuer
            .mint(&keys, "sandbox-1", &ScopeSet::parse("docs").unwrap(), now)
            .unwrap();
        let forbidden = issuer
            .mint(&keys, "sandbox-1", &ScopeSet::parse("other").unwrap(), now)
            .unwrap();
        let metrics = Arc::new(ProxyMetrics::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let state = Arc::new(ConnectProxy::new(
            router,
            Arc::new(Verifier::new("trust".into(), "proxy".into())),
            keystore,
            metrics.clone(),
            ForwardProxyConfig {
                addr: proxy_addr.to_string(),
                tls: false,
                connect_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(5),
                max_tunnel_duration: Duration::from_secs(30),
                max_concurrent_tunnels: 10,
                allow_private_ips: true,
                audit_unmatched: None,
                mitm: None,
            },
        ));
        let server = tokio::spawn(serve_connect(listener, None, state));

        let authority = format!("127.0.0.1:{target_port}");
        let mut missing = TcpStream::connect(proxy_addr).await.unwrap();
        missing
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_response_head(&mut missing)
                .await
                .starts_with("HTTP/1.1 407")
        );

        let mut wrong_scope = TcpStream::connect(proxy_addr).await.unwrap();
        wrong_scope
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {forbidden}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_response_head(&mut wrong_scope)
                .await
                .starts_with("HTTP/1.1 403")
        );

        let mut tunnel = TcpStream::connect(proxy_addr).await.unwrap();
        tunnel
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {allowed}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response_head = read_response_head(&mut tunnel).await;
        assert!(response_head.starts_with("HTTP/1.1 200"));
        let response_head = response_head.to_ascii_lowercase();
        assert!(!response_head.contains("content-length:"));
        assert!(!response_head.contains("transfer-encoding:"));
        tunnel.write_all(b"hello through trust").await.unwrap();
        let mut echoed = [0_u8; 19];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello through trust");
        drop(tunnel);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let rendered = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(rendered.contains(
            "trust_connect_attempts_total{result=\"missing_token\",upstream=\"docs\"} 1"
        ));
        assert!(rendered.contains(
            "trust_connect_attempts_total{result=\"forbidden_scope\",upstream=\"docs\"} 1"
        ));
        assert!(
            rendered.contains(
                "trust_connect_attempts_total{result=\"established\",upstream=\"docs\"} 1"
            )
        );
        assert!(
            rendered.contains(
                "trust_connect_bytes_total{direction=\"to_upstream\",upstream=\"docs\"} 19"
            )
        );
        server.abort();
    }

    #[tokio::test]
    async fn audit_unmatched_rejects_private_destination_even_when_exact_routes_allow_them() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        drop(target);

        let keystore = Arc::new(Keystore::new());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        keystore.store(build_key_material(&key.serialize_pem(), None).unwrap());
        let keys = keystore.load().unwrap();
        let issuer = Issuer::new("trust".into(), "proxy".into(), Duration::from_secs(60));
        let now = jsonwebtoken::get_current_timestamp();
        let allowed = issuer
            .mint(
                &keys,
                "sandbox-audit",
                &ScopeSet::parse("outbound-audit").unwrap(),
                now,
            )
            .unwrap();
        let forbidden = issuer
            .mint(
                &keys,
                "sandbox-audit",
                &ScopeSet::parse("other").unwrap(),
                now,
            )
            .unwrap();

        let metrics = Arc::new(ProxyMetrics::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let state = Arc::new(ConnectProxy::new(
            Arc::new(Router::new(&[])),
            Arc::new(Verifier::new("trust".into(), "proxy".into())),
            keystore,
            metrics.clone(),
            ForwardProxyConfig {
                addr: proxy_addr.to_string(),
                tls: false,
                connect_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(5),
                max_tunnel_duration: Duration::from_secs(30),
                max_concurrent_tunnels: 10,
                allow_private_ips: true,
                audit_unmatched: Some(AuditUnmatchedConfig {
                    scope: "outbound-audit".into(),
                }),
                mitm: None,
            },
        ));
        let server = tokio::spawn(serve_connect(listener, None, state));
        let authority = format!("127.0.0.1:{target_port}");

        let mut denied = TcpStream::connect(proxy_addr).await.unwrap();
        denied
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {forbidden}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_response_head(&mut denied)
                .await
                .starts_with("HTTP/1.1 403")
        );

        let mut tunnel = TcpStream::connect(proxy_addr).await.unwrap();
        tunnel
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {allowed}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_response_head(&mut tunnel)
                .await
                .starts_with("HTTP/1.1 502")
        );

        let rendered = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(rendered.contains(
            "trust_connect_attempts_total{result=\"forbidden_scope\",upstream=\"audit-unmatched\"} 1"
        ));
        assert!(rendered.contains(
            "trust_connect_attempts_total{result=\"private_destination\",upstream=\"audit-unmatched\"} 1"
        ));
        server.abort();
    }

    #[tokio::test]
    async fn configured_http_forwards_without_forwarding_proxy_credentials() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let request = read_response_head(&mut stream).await;
            captured_tx.send(request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let keystore = Arc::new(Keystore::new());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        keystore.store(build_key_material(&key.serialize_pem(), None).unwrap());
        let keys = keystore.load().unwrap();
        let issuer = Issuer::new("trust".into(), "proxy".into(), Duration::from_secs(60));
        let token = issuer
            .mint(
                &keys,
                "sandbox-docs",
                &ScopeSet::parse("docs").unwrap(),
                jsonwebtoken::get_current_timestamp(),
            )
            .unwrap();

        let upstream = Arc::new(Upstream {
            name: "docs".into(),
            kind: UpstreamKind::Api,
            listen_host: "docs.proxy.internal".into(),
            origin: Origin {
                host: "127.0.0.1".into(),
                port: target_port,
                tls: false,
                sni: "".into(),
            },
            mode: UpstreamMode::Passthrough,
            credential: None,
            injection: None,
            resource: None,
            git: None,
            allowed_methods: Vec::new(),
            allow_connect: true,
            intercept_connect: false,
        });

        let metrics = Arc::new(ProxyMetrics::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let state = Arc::new(ConnectProxy::new(
            Arc::new(Router::new(std::slice::from_ref(&upstream))),
            Arc::new(Verifier::new("trust".into(), "proxy".into())),
            keystore,
            metrics.clone(),
            ForwardProxyConfig {
                addr: proxy_addr.to_string(),
                tls: false,
                connect_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(5),
                max_tunnel_duration: Duration::from_secs(30),
                max_concurrent_tunnels: 10,
                allow_private_ips: true,
                audit_unmatched: None,
                mitm: None,
            },
        ));
        let server = tokio::spawn(serve_connect(listener, None, state));
        let authority = format!("127.0.0.1:{target_port}");

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{authority}/resource?x=1 HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {token}\r\nProxy-Connection: keep-alive\r\nAuthorization: Bearer origin-token\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_response_head(&mut client)
                .await
                .starts_with("HTTP/1.1 200")
        );
        let mut body = [0_u8; 2];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");

        let captured = captured_rx.await.unwrap();
        assert!(captured.starts_with("GET /resource?x=1 HTTP/1.1\r\n"));
        let captured_lowercase = captured.to_ascii_lowercase();
        assert!(captured_lowercase.contains(&format!("host: {authority}\r\n")));
        assert!(captured_lowercase.contains("authorization: bearer origin-token\r\n"));
        assert!(!captured_lowercase.contains("proxy-authorization"));
        assert!(!captured_lowercase.contains("proxy-connection"));

        let rendered = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(
            rendered
                .contains("trust_forward_proxy_requests_total{result=\"200\",upstream=\"docs\"} 1")
        );
        server.abort();
    }
}
