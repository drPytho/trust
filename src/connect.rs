use std::convert::Infallible;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant as TokioInstant, sleep_until, timeout};
use tokio_rustls::TlsAcceptor;

use crate::config::{AUDIT_UNMATCHED_METRICS_NAME, ForwardProxyConfig};
use crate::jwt::{VerifiedToken, Verifier};
use crate::keystore::Keystore;
use crate::metrics::ProxyMetrics;
use crate::router::Router;

type ResponseBody = Full<Bytes>;

enum ConnectDestination {
    Configured(Arc<crate::config::Upstream>),
    Audit {
        host: String,
        port: u16,
        scope: String,
    },
}

impl ConnectDestination {
    fn metrics_name(&self) -> &str {
        match self {
            ConnectDestination::Configured(upstream) => &upstream.name,
            ConnectDestination::Audit { .. } => AUDIT_UNMATCHED_METRICS_NAME,
        }
    }

    fn required_scope(&self) -> &str {
        match self {
            ConnectDestination::Configured(upstream) => &upstream.name,
            ConnectDestination::Audit { scope, .. } => scope,
        }
    }

    fn target(&self) -> (&str, u16) {
        match self {
            ConnectDestination::Configured(upstream) => {
                (&upstream.origin.host, upstream.origin.port)
            }
            ConnectDestination::Audit { host, port, .. } => (host, *port),
        }
    }

    fn is_audit(&self) -> bool {
        matches!(self, ConnectDestination::Audit { .. })
    }
}

pub struct ConnectProxy {
    router: Arc<Router>,
    verifier: Arc<Verifier>,
    keystore: Arc<Keystore>,
    metrics: Arc<ProxyMetrics>,
    config: ForwardProxyConfig,
    tunnel_slots: Arc<Semaphore>,
}

impl ConnectProxy {
    pub fn new(
        router: Arc<Router>,
        verifier: Arc<Verifier>,
        keystore: Arc<Keystore>,
        metrics: Arc<ProxyMetrics>,
        config: ForwardProxyConfig,
    ) -> ConnectProxy {
        let tunnel_slots = Arc::new(Semaphore::new(config.max_concurrent_tunnels));
        ConnectProxy {
            router,
            verifier,
            keystore,
            metrics,
            config,
            tunnel_slots,
        }
    }

    async fn handle(
        self: Arc<Self>,
        mut request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, Infallible> {
        if request.method() != Method::CONNECT {
            self.metrics
                .connect_attempt("unrouted", "method_not_allowed");
            return Ok(response(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT required\n",
            ));
        }

        let Some(authority) = request.uri().authority() else {
            self.metrics
                .connect_attempt("unrouted", "invalid_authority");
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT authority\n",
            ));
        };
        let Some(port) = authority.port_u16() else {
            self.metrics
                .connect_attempt("unrouted", "invalid_authority");
            return Ok(response(StatusCode::BAD_REQUEST, "CONNECT port required\n"));
        };
        let host = authority.host().to_string();
        let destination = match self.router.resolve_connect(&host, port) {
            Some(upstream) => ConnectDestination::Configured(upstream),
            None => match &self.config.audit_unmatched {
                Some(audit) => {
                    log::warn!(
                        "CONNECT unmatched destination observed action=audit_allow_pending_auth \
                         destination_host={host:?} destination_port={port} required_scope={:?}",
                        audit.scope
                    );
                    ConnectDestination::Audit {
                        host: host.clone(),
                        port,
                        scope: audit.scope.clone(),
                    }
                }
                None => {
                    self.metrics
                        .connect_attempt("unrouted", "unknown_destination");
                    log::warn!(
                        "CONNECT rejected reason=unknown_destination destination_host={host:?} \
                         destination_port={port}"
                    );
                    return Ok(response(StatusCode::FORBIDDEN, "destination not allowed\n"));
                }
            },
        };
        let metrics_name = destination.metrics_name();

        let token = match proxy_token(request.headers().get(PROXY_AUTHORIZATION)) {
            Ok(token) => token,
            Err(reason) => {
                self.metrics.connect_attempt(metrics_name, reason);
                log::warn!(
                    "CONNECT rejected reason={reason} upstream={metrics_name} \
                     destination_host={host:?} destination_port={port}"
                );
                return Ok(proxy_auth_required());
            }
        };
        let Some(keys) = self.keystore.load() else {
            self.metrics
                .connect_attempt(metrics_name, "signing_keys_unavailable");
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                "signing keys unavailable\n",
            ));
        };
        let verified = match self.verifier.verify_token(&keys, &token) {
            Ok(verified) => verified,
            Err(_) => {
                self.metrics.connect_attempt(metrics_name, "invalid_token");
                return Ok(proxy_auth_required());
            }
        };
        if !verified.scopes.permits(destination.required_scope(), None) {
            self.metrics
                .connect_attempt(metrics_name, "forbidden_scope");
            log::warn!(
                "CONNECT rejected reason=forbidden_scope upstream={metrics_name} subject={:?} \
                 destination_host={host:?} destination_port={port}",
                verified.subject,
            );
            return Ok(response(StatusCode::FORBIDDEN, "not allowed\n"));
        }

        let Some(max_duration) = tunnel_duration(&verified, self.config.max_tunnel_duration) else {
            self.metrics.connect_attempt(metrics_name, "invalid_token");
            return Ok(proxy_auth_required());
        };
        let tunnel_slot = match self.tunnel_slots.clone().try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                self.metrics
                    .connect_attempt(metrics_name, "capacity_exceeded");
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

        let (target_host, target_port) = destination.target();
        let target = match connect_target(
            target_host,
            target_port,
            self.config.allow_private_ips,
            self.config.connect_timeout,
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
                self.metrics.connect_attempt(metrics_name, reason);
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
                        max_duration,
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
}

fn response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static CONNECT response")
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

async fn connect_target(
    host: &str,
    port: u16,
    allow_private_ips: bool,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    timeout(connect_timeout, async {
        let addresses = tokio::net::lookup_host((host, port)).await?;
        let mut last_error = None;
        let mut permitted = false;
        for address in addresses {
            if !allow_private_ips && !is_public_ip(address.ip()) {
                continue;
            }
            permitted = true;
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        if !permitted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination resolved only to non-public addresses",
            ));
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
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1])))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
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
    max_duration: Duration,
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
    let maximum = sleep_until(TokioInstant::now() + max_duration);
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
        log::debug!("CONNECT client connection ended: {error}");
    }
}

pub async fn serve_connect(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    state: Arc<ConnectProxy>,
) -> io::Result<()> {
    let tls = tls.map(TlsAcceptor::from);
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
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(value.parse().unwrap()), "accepted {value}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
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
    async fn audit_unmatched_allows_scoped_destination_and_records_metrics() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let read = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..read]).await.unwrap();
        });

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
                .starts_with("HTTP/1.1 200")
        );
        tunnel.write_all(b"audit me").await.unwrap();
        let mut echoed = [0_u8; 8];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"audit me");
        drop(tunnel);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let rendered = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(rendered.contains(
            "trust_connect_attempts_total{result=\"forbidden_scope\",upstream=\"audit-unmatched\"} 1"
        ));
        assert!(rendered.contains(
            "trust_connect_attempts_total{result=\"established\",upstream=\"audit-unmatched\"} 1"
        ));
        assert!(rendered.contains(
            "trust_connect_bytes_total{direction=\"to_upstream\",upstream=\"audit-unmatched\"} 8"
        ));
        server.abort();
    }
}
