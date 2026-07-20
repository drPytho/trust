use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hyper::upgrade::Upgraded;
use pingora::apps::HttpServerApp;
use pingora::listeners::TlsAccept;
use pingora::protocols::http::ServerSession;
use pingora::protocols::tls::TlsRef;
use pingora::protocols::tls::server::handshake_with_callback;
use pingora::proxy::{HttpProxy, http_proxy};
use pingora::server::{ShutdownWatch, configuration::ServerConf};
use pingora::tls::ext;
use pingora::tls::ssl::{AlpnError, NameType, SslAcceptor, SslMethod};
use tokio::sync::watch;
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};

use crate::config::{ForwardProxyConfig, Upstream, canonical_intercept_dns_host};
use crate::credentials::CredentialProvider;
use crate::metrics::ProxyMetrics;
use crate::mitm::MitmConnectionContext;
use crate::mitm::ca::{EgressSigner, LeafCertificateCache, MitmCaError};
use crate::mitm::io::MitmIo;
use crate::mitm::proxy::MitmProxyService;

#[derive(Debug, thiserror::Error)]
pub enum MitmRuntimeError {
    #[error("MITM is not configured for the forward proxy")]
    MissingConfig,
    #[error("failed to build MITM TLS acceptor: {0}")]
    Tls(String),
    #[error(transparent)]
    Ca(#[from] MitmCaError),
    #[error("MITM TLS handshake timed out")]
    HandshakeTimeout,
    #[error("MITM TLS handshake failed: {0}")]
    Handshake(String),
    #[error("MITM TLS handshake rejected: {0}")]
    HandshakeRejected(&'static str),
}

/// Shared runtime for post-CONNECT TLS interception. It owns only the online
/// intermediate signer/cache; the root key is never loaded by this process.
pub struct MitmRuntime {
    acceptor: Arc<SslAcceptor>,
    cache: Arc<LeafCertificateCache>,
    proxy: Arc<HttpProxy<MitmProxyService>>,
    shutdown: ShutdownWatch,
    _shutdown_tx: watch::Sender<bool>,
    handshake_timeout: Duration,
    idle_timeout: Duration,
    refresh_interval: Duration,
    metrics: Arc<ProxyMetrics>,
    refresher_started: AtomicBool,
}

impl MitmRuntime {
    pub fn new(
        server_conf: &Arc<ServerConf>,
        forward: &ForwardProxyConfig,
        upstreams: &[Arc<Upstream>],
        credentials: Arc<dyn CredentialProvider>,
        metrics: Arc<ProxyMetrics>,
    ) -> Result<Arc<Self>, MitmRuntimeError> {
        let config = forward
            .mitm
            .as_ref()
            .ok_or(MitmRuntimeError::MissingConfig)?;
        let signer = Arc::new(EgressSigner::load(config)?);
        let hosts = upstreams
            .iter()
            .filter(|upstream| upstream.intercept_connect)
            .map(|upstream| upstream.origin.host.clone());
        let cache = Arc::new(LeafCertificateCache::new(
            signer,
            hosts,
            config.refresh_before,
            config.leaf_cache_capacity,
        )?);
        for _ in 0..cache.len() {
            metrics.mitm_certificate_cache("prewarmed");
        }
        log::info!(
            "TLS interception initialized configured_hosts={} leaf_cache_capacity={}",
            cache.len(),
            config.leaf_cache_capacity,
        );

        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|error| MitmRuntimeError::Tls(error.to_string()))?;
        builder.set_alpn_select_callback(|_, offered| select_http1(offered));
        let acceptor = Arc::new(builder.build());
        let proxy = Arc::new(http_proxy(
            server_conf,
            MitmProxyService::new(
                credentials,
                metrics.clone(),
                forward.connect_timeout,
                forward.idle_timeout,
            ),
        ));
        let (shutdown_tx, shutdown) = watch::channel(false);

        Ok(Arc::new(MitmRuntime {
            acceptor,
            cache,
            proxy,
            shutdown,
            _shutdown_tx: shutdown_tx,
            handshake_timeout: config.handshake_timeout,
            idle_timeout: forward.idle_timeout,
            refresh_interval: config
                .refresh_before
                .div_f64(2.0)
                .max(Duration::from_secs(1)),
            metrics,
            refresher_started: AtomicBool::new(false),
        }))
    }

    /// Must run from the forward-proxy Tokio runtime, after startup prewarming
    /// has completed. A handshake never waits for this task.
    pub fn start_background_refresh(self: &Arc<Self>) {
        if !self.refresher_started.swap(true, Ordering::AcqRel) {
            let cache = self.cache.clone();
            let metrics = self.metrics.clone();
            let refresh_interval = self.refresh_interval;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(refresh_interval).await;
                    match cache.refresh_due() {
                        Ok(refreshed) => {
                            for _ in 0..refreshed {
                                metrics.mitm_certificate_cache("refresh");
                            }
                        }
                        Err(error) => {
                            metrics.mitm_certificate_cache("issuance_error");
                            log::error!("egress MITM leaf certificate refresh failed: {error}");
                        }
                    }
                }
            });
        }
    }

    pub async fn intercept(
        &self,
        upgraded: Upgraded,
        context: Arc<MitmConnectionContext>,
        deadline: TokioInstant,
    ) -> Result<(), MitmRuntimeError> {
        let started = Instant::now();
        let upstream_name = context.upstream.name.clone();
        let handshake_state = Arc::new(AtomicU8::new(HandshakeState::Pending as u8));
        let callbacks = MitmTlsCallbacks {
            expected_host: context.authority_host.clone(),
            cache: self.cache.clone(),
            context,
            metrics: self.metrics.clone(),
            upstream_name: upstream_name.clone(),
            handshake_state: handshake_state.clone(),
        };
        let callbacks: pingora::listeners::TlsAcceptCallbacks = Box::new(callbacks);
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        let tls = match timeout(
            self.handshake_timeout.min(remaining),
            handshake_with_callback(&self.acceptor, MitmIo::new(upgraded), &callbacks),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                if handshake_rejection_reason(handshake_state.load(Ordering::Acquire)).is_none() {
                    self.metrics.mitm_handshake(&upstream_name, "failed");
                }
                return Err(MitmRuntimeError::Handshake(error.to_string()));
            }
            Err(_) => {
                self.metrics.mitm_handshake(&upstream_name, "timeout");
                return Err(MitmRuntimeError::HandshakeTimeout);
            }
        };
        let handshake_state = handshake_state.load(Ordering::Acquire);
        if handshake_state != HandshakeState::Accepted as u8 {
            let reason = handshake_rejection_reason(handshake_state).unwrap_or("failed");
            if reason == "failed" {
                self.metrics.mitm_handshake(&upstream_name, reason);
            }
            return Err(MitmRuntimeError::HandshakeRejected(reason));
        }
        self.metrics.mitm_handshake(&upstream_name, "established");
        if deadline
            .saturating_duration_since(TokioInstant::now())
            .is_zero()
        {
            log::warn!(
                "MITM connection reached CONNECT lifetime during TLS handshake upstream={upstream_name}"
            );
            return Ok(());
        }
        self.metrics.mitm_connection_started(&upstream_name);

        let proxy = self.proxy.clone();
        let shutdown = self.shutdown.clone();
        let idle_timeout = self.idle_timeout;
        let result = timeout_at(deadline, async move {
            let mut next = Some(Box::new(tls) as pingora::protocols::Stream);
            while let Some(stream) = next.take() {
                let mut session = ServerSession::new_http1(stream);
                session.set_keepalive(Some(idle_timeout.as_secs()));
                session.set_read_timeout(Some(idle_timeout));
                session.set_write_timeout(Some(idle_timeout));
                next = proxy
                    .process_new_http(session, &shutdown)
                    .await
                    .map(|reused| reused.consume().0);
            }
        })
        .await;
        self.metrics
            .mitm_connection_finished(&upstream_name, started.elapsed().as_secs_f64());
        if result.is_err() {
            log::warn!(
                "MITM connection reached CONNECT lifetime upstream={upstream_name} duration_seconds={}",
                started.elapsed().as_secs_f64(),
            );
        }
        Ok(())
    }
}

struct MitmTlsCallbacks {
    expected_host: String,
    cache: Arc<LeafCertificateCache>,
    context: Arc<MitmConnectionContext>,
    metrics: Arc<ProxyMetrics>,
    upstream_name: String,
    handshake_state: Arc<AtomicU8>,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum HandshakeState {
    Pending,
    CertificateInstalled,
    Accepted,
    SniMismatch,
    CertificateUnavailable,
    CertificateError,
    AlpnMismatch,
}

fn handshake_rejection_reason(state: u8) -> Option<&'static str> {
    match state {
        value if value == HandshakeState::SniMismatch as u8 => Some("sni_mismatch"),
        value if value == HandshakeState::CertificateUnavailable as u8 => {
            Some("certificate_unavailable")
        }
        value if value == HandshakeState::CertificateError as u8 => Some("certificate_error"),
        value if value == HandshakeState::AlpnMismatch as u8 => Some("alpn_mismatch"),
        _ => None,
    }
}

#[async_trait]
impl TlsAccept for MitmTlsCallbacks {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .and_then(canonical_intercept_dns_host);
        if sni.as_deref() != Some(self.expected_host.as_str()) {
            self.handshake_state
                .store(HandshakeState::SniMismatch as u8, Ordering::Release);
            self.metrics
                .mitm_handshake(&self.upstream_name, "sni_mismatch");
            log::warn!(
                "MITM TLS rejected reason=sni_mismatch upstream={} expected_sni={:?} received_sni={sni:?}",
                self.upstream_name,
                self.expected_host,
            );
            return;
        }
        let Some(leaf) = self.cache.get(&self.expected_host) else {
            self.handshake_state.store(
                HandshakeState::CertificateUnavailable as u8,
                Ordering::Release,
            );
            self.metrics.mitm_certificate_cache("miss");
            self.metrics
                .mitm_handshake(&self.upstream_name, "certificate_unavailable");
            log::error!(
                "MITM TLS rejected reason=certificate_unavailable upstream={} host={}",
                self.upstream_name,
                self.expected_host,
            );
            return;
        };
        self.metrics.mitm_certificate_cache("hit");
        if let Err(error) = ext::ssl_use_certificate(ssl, &leaf.certificate)
            .and_then(|_| ext::ssl_use_private_key(ssl, &leaf.private_key))
        {
            self.handshake_state
                .store(HandshakeState::CertificateError as u8, Ordering::Release);
            self.metrics
                .mitm_handshake(&self.upstream_name, "certificate_error");
            log::error!(
                "MITM TLS rejected reason=certificate_error upstream={}: {error}",
                self.upstream_name,
            );
            return;
        }
        for intermediate in &leaf.intermediates {
            if let Err(error) = ext::ssl_add_chain_cert(ssl, intermediate) {
                self.handshake_state
                    .store(HandshakeState::CertificateError as u8, Ordering::Release);
                self.metrics
                    .mitm_handshake(&self.upstream_name, "certificate_error");
                log::error!(
                    "MITM TLS rejected reason=chain_error upstream={}: {error}",
                    self.upstream_name,
                );
                return;
            }
        }
        self.handshake_state.store(
            HandshakeState::CertificateInstalled as u8,
            Ordering::Release,
        );
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        if self.handshake_state.load(Ordering::Acquire)
            != HandshakeState::CertificateInstalled as u8
        {
            return None;
        }
        if let Some(protocol) = ssl.selected_alpn_protocol()
            && protocol != b"http/1.1"
        {
            self.handshake_state
                .store(HandshakeState::AlpnMismatch as u8, Ordering::Release);
            self.metrics
                .mitm_handshake(&self.upstream_name, "alpn_mismatch");
            log::warn!(
                "MITM TLS rejected reason=alpn_mismatch upstream={} protocol={protocol:?}",
                self.upstream_name,
            );
            return None;
        }
        self.handshake_state
            .store(HandshakeState::Accepted as u8, Ordering::Release);
        Some(self.context.clone())
    }
}

fn select_http1(offered: &[u8]) -> Result<&[u8], AlpnError> {
    let mut offset = 0;
    while offset < offered.len() {
        let length = usize::from(offered[offset]);
        offset += 1;
        let Some(end) = offset.checked_add(length) else {
            return Err(AlpnError::NOACK);
        };
        let Some(protocol) = offered.get(offset..end) else {
            return Err(AlpnError::NOACK);
        };
        if protocol == b"http/1.1" {
            return Ok(protocol);
        }
        offset = end;
    }
    Err(AlpnError::NOACK)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use pingora::protocols::tls::SslStream;
    use pingora::tls::ssl::{Ssl, SslContext, SslVerifyMode};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tempfile::TempDir;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;
    use crate::config::{
        CredentialSource, ForwardProxyMitmConfig, Injection, InjectionScheme, Origin, UpstreamKind,
        UpstreamMode,
    };
    use crate::connect::{ConnectProxy, serve_connect};
    use crate::credentials::{CredentialError, ResolvedCredential};
    use crate::jwt::{Issuer as JwtIssuer, Verifier};
    use crate::keystore::{Keystore, build_key_material};
    use crate::router::Router;
    use crate::scope::ScopeSet;
    use crate::secrets::Secret;

    struct StaticCredentials;

    #[async_trait]
    impl CredentialProvider for StaticCredentials {
        async fn resolve(
            &self,
            _upstream: &Upstream,
            _method: &str,
            _path: &str,
        ) -> Result<ResolvedCredential, CredentialError> {
            Ok(ResolvedCredential {
                secret: Secret::new("trust-injected-key".to_string()),
                cache_key: None,
                result: "test",
            })
        }
    }

    async fn read_headers<S>(stream: &mut S) -> String
    where
        S: AsyncRead + Unpin,
    {
        let mut bytes = Vec::new();
        let mut byte = [0_u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 32 * 1024, "oversized HTTP headers");
        }
        String::from_utf8(bytes).unwrap()
    }

    fn root_issuer(name: &str) -> (rcgen::Certificate, Issuer<'static, KeyPair>) {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate, Issuer::new(params, key))
    }

    fn signed_intermediate(issuer: &Issuer<'_, KeyPair>) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Trust test egress intermediate");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, issuer).unwrap();
        (certificate, key)
    }

    fn tls_server_config(certificate: &rcgen::Certificate, key: &KeyPair) -> Arc<ServerConfig> {
        crate::issuance::server::install_crypto_provider();
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certificate.der().as_ref().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap(),
        )
    }

    fn tls_client_config(root: &rcgen::Certificate) -> Arc<ClientConfig> {
        crate::issuance::server::install_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root.der().as_ref().to_vec()))
            .unwrap();
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn intercepted_upstream(host: &str) -> Arc<Upstream> {
        Arc::new(Upstream {
            name: "provider".to_string(),
            kind: UpstreamKind::Api,
            listen_host: "provider.trust.internal".to_string(),
            origin: Origin {
                host: host.to_string(),
                port: 443,
                tls: true,
                sni: host.to_string(),
            },
            mode: UpstreamMode::Inject,
            credential: Some(CredentialSource::StaticSecret {
                secret_ref: "provider-key".to_string(),
            }),
            injection: Some(Injection {
                header: "x-api-key".to_string(),
                scheme: InjectionScheme::Raw,
            }),
            resource: None,
            git: None,
            allowed_methods: Vec::new(),
            allow_connect: false,
            intercept_connect: true,
        })
    }

    #[tokio::test]
    async fn tls_rejects_missing_or_mismatched_sni_before_http() {
        for server_name in [None, Some("other.example.com")] {
            let (_root, root_issuer) = root_issuer("Trust egress root");
            let (intermediate, intermediate_key) = signed_intermediate(&root_issuer);
            let signer = Arc::new(
                EgressSigner::from_pem(
                    intermediate.pem().as_bytes(),
                    intermediate_key.serialize_pem().as_bytes(),
                    Duration::from_secs(3600),
                )
                .unwrap(),
            );
            let cache = Arc::new(
                LeafCertificateCache::new(
                    signer,
                    ["api.example.com".to_string()],
                    Duration::from_secs(60),
                    1,
                )
                .unwrap(),
            );
            let upstream = intercepted_upstream("api.example.com");
            let state = Arc::new(AtomicU8::new(HandshakeState::Pending as u8));
            let callbacks: pingora::listeners::TlsAcceptCallbacks = Box::new(MitmTlsCallbacks {
                expected_host: "api.example.com".to_string(),
                cache,
                context: Arc::new(MitmConnectionContext {
                    upstream,
                    authority_host: "api.example.com".to_string(),
                    authority_port: 443,
                    upstream_addresses: vec!["127.0.0.1:443".parse().unwrap()],
                    subject: "sandbox".to_string(),
                    scopes: ScopeSet::parse("provider").unwrap(),
                    expires_at: u64::MAX,
                }),
                metrics: Arc::new(ProxyMetrics::new()),
                upstream_name: "provider".to_string(),
                handshake_state: state.clone(),
            });
            let acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
                .unwrap()
                .build();
            let (client, server) = tokio::io::duplex(8 * 1024);
            let server_name = server_name.map(str::to_string);
            let client_task = tokio::spawn(async move {
                let context = SslContext::builder(SslMethod::tls()).unwrap().build();
                let mut ssl = Ssl::new(&context).unwrap();
                if let Some(server_name) = server_name {
                    ssl.set_hostname(&server_name).unwrap();
                }
                ssl.set_verify(SslVerifyMode::NONE);
                let mut stream = SslStream::new(ssl, client).unwrap();
                Pin::new(&mut stream).connect().await
            });

            assert!(
                handshake_with_callback(&acceptor, server, &callbacks)
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_secs(5), client_task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert_eq!(
                state.load(Ordering::Acquire),
                HandshakeState::SniMismatch as u8
            );
        }
    }

    #[tokio::test]
    async fn intercepts_a_bound_connect_and_injects_the_trust_credential() {
        let temp = TempDir::new().unwrap();
        let (egress_root, egress_issuer) = root_issuer("Trust egress root");
        let (egress_intermediate, egress_intermediate_key) = signed_intermediate(&egress_issuer);
        let intermediate_path = temp.path().join("egress-intermediate.pem");
        let intermediate_key_path = temp.path().join("egress-intermediate.key");
        std::fs::write(&intermediate_path, egress_intermediate.pem()).unwrap();
        std::fs::write(
            &intermediate_key_path,
            egress_intermediate_key.serialize_pem(),
        )
        .unwrap();

        let (origin_root, origin_issuer) = root_issuer("Origin test root");
        let mut origin_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        origin_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        origin_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let origin_key = KeyPair::generate().unwrap();
        let origin_certificate = origin_params
            .signed_by(&origin_key, &origin_issuer)
            .unwrap();
        let origin_root_path = temp.path().join("origin-root.pem");
        std::fs::write(&origin_root_path, origin_root.pem()).unwrap();

        // Pingora resolves localhost to IPv6 first in this test environment.
        // Bind the origin to that address so the test exercises the TLS proxy
        // rather than a DNS-family fallback.
        let origin_listener = TcpListener::bind("[::1]:0").await.unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_tls = TlsAcceptor::from(tls_server_config(&origin_certificate, &origin_key));
        let (request_tx, mut request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let mut stream = origin_tls.accept(stream).await.unwrap();
            let request = read_headers(&mut stream).await;
            request_tx.send(request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let upstream = Arc::new(Upstream {
            name: "provider".to_string(),
            kind: UpstreamKind::Api,
            listen_host: "provider.trust.internal".to_string(),
            origin: Origin {
                host: "localhost".to_string(),
                port: origin_port,
                tls: true,
                sni: "localhost".to_string(),
            },
            mode: UpstreamMode::Inject,
            credential: Some(CredentialSource::StaticSecret {
                secret_ref: "provider-key".to_string(),
            }),
            injection: Some(Injection {
                header: "x-api-key".to_string(),
                scheme: InjectionScheme::Raw,
            }),
            resource: None,
            git: None,
            allowed_methods: vec!["GET".to_string()],
            allow_connect: false,
            intercept_connect: true,
        });
        let forward = ForwardProxyConfig {
            addr: "127.0.0.1:0".to_string(),
            tls: false,
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(5),
            max_tunnel_duration: Duration::from_secs(30),
            max_concurrent_tunnels: 10,
            allow_private_ips: true,
            audit_unmatched: None,
            mitm: Some(ForwardProxyMitmConfig {
                issuer_cert_chain_path: intermediate_path.to_string_lossy().into_owned(),
                issuer_key_path: intermediate_key_path.to_string_lossy().into_owned(),
                leaf_ttl: Duration::from_secs(60),
                refresh_before: Duration::from_secs(10),
                leaf_cache_capacity: 1,
                handshake_timeout: Duration::from_secs(5),
            }),
        };
        let server_conf = Arc::new(ServerConf {
            ca_file: Some(origin_root_path.to_string_lossy().into_owned()),
            ..ServerConf::default()
        });
        let metrics = Arc::new(ProxyMetrics::new());
        let runtime = MitmRuntime::new(
            &server_conf,
            &forward,
            std::slice::from_ref(&upstream),
            Arc::new(StaticCredentials),
            metrics.clone(),
        )
        .unwrap();

        let keystore = Arc::new(Keystore::new());
        let jwt_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        keystore.store(build_key_material(&jwt_key.serialize_pem(), None).unwrap());
        let jwt_keys = keystore.load().unwrap();
        let jwt_issuer = JwtIssuer::new("trust".into(), "proxy".into(), Duration::from_secs(60));
        let token = jwt_issuer
            .mint(
                &jwt_keys,
                "sandbox-test",
                &ScopeSet::parse("provider").unwrap(),
                jsonwebtoken::get_current_timestamp(),
            )
            .unwrap();
        let audit_token = jwt_issuer
            .mint(
                &jwt_keys,
                "sandbox-test",
                &ScopeSet::parse("outbound-audit").unwrap(),
                jsonwebtoken::get_current_timestamp(),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let state = Arc::new(ConnectProxy::with_mitm(
            Arc::new(Router::new(std::slice::from_ref(&upstream))),
            Arc::new(Verifier::new("trust".into(), "proxy".into())),
            keystore,
            metrics,
            forward,
            Some(runtime.clone()),
        ));
        runtime.start_background_refresh();
        let proxy_task = tokio::spawn(serve_connect(listener, None, state));

        let authority = format!("localhost:{origin_port}");

        // An audit token authorizes only the unmatched opaque fallback. It
        // cannot select a configured interception route or cause injection.
        let mut audit_stream = TcpStream::connect(proxy_addr).await.unwrap();
        audit_stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {audit_token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_headers(&mut audit_stream)
                .await
                .starts_with("HTTP/1.1 403")
        );

        // The TLS SNI has to agree with the CONNECT authority before Trust
        // makes an upstream connection.
        let mut wrong_sni_stream = TcpStream::connect(proxy_addr).await.unwrap();
        wrong_sni_stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_headers(&mut wrong_sni_stream)
                .await
                .starts_with("HTTP/1.1 200")
        );
        let wrong_sni = ServerName::try_from("wrong.example".to_string()).unwrap();
        assert!(
            TlsConnector::from(tls_client_config(&egress_root))
                .connect(wrong_sni, wrong_sni_stream)
                .await
                .is_err()
        );

        // The decrypted HTTP Host is also bound to the CONNECT authority;
        // a mismatch must be rejected locally before it reaches the origin.
        let mut wrong_host_stream = TcpStream::connect(proxy_addr).await.unwrap();
        wrong_host_stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_headers(&mut wrong_host_stream)
                .await
                .starts_with("HTTP/1.1 200")
        );
        let server_name = ServerName::try_from("localhost".to_string()).unwrap();
        let mut wrong_host_stream = TlsConnector::from(tls_client_config(&egress_root))
            .connect(server_name, wrong_host_stream)
            .await
            .unwrap();
        wrong_host_stream
            .write_all(
                b"GET /v1/messages HTTP/1.1\r\nHost: wrong.example\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        assert!(
            read_headers(&mut wrong_host_stream)
                .await
                .starts_with("HTTP/1.1 421")
        );
        assert!(matches!(
            request_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(read_headers(&mut stream).await.starts_with("HTTP/1.1 200"));

        let connector = TlsConnector::from(tls_client_config(&egress_root));
        let server_name = ServerName::try_from("localhost".to_string()).unwrap();
        let mut stream = connector.connect(server_name, stream).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /v1/messages HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer sandbox-provider-key\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_headers(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        let mut body = [0_u8; 2];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");

        let origin_request = tokio::time::timeout(Duration::from_secs(5), request_rx)
            .await
            .unwrap()
            .unwrap();
        let origin_request = origin_request.to_ascii_lowercase();
        assert!(origin_request.contains("x-api-key: trust-injected-key\r\n"));
        assert!(origin_request.contains(&format!("host: localhost:{origin_port}\r\n")));
        assert!(!origin_request.contains("authorization: bearer sandbox-provider-key"));
        assert!(!origin_request.contains("proxy-authorization"));

        proxy_task.abort();
    }
}
