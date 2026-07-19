use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;

use trust::config::{Config, UpstreamKind};
use trust::connect::{ConnectProxy, serve_connect};
use trust::credentials::{CredentialManager, CredentialProvider};
use trust::git::mirror::MirrorStore;
use trust::git::sync::SyncManager;
use trust::issuance::policy::ClientPolicy;
use trust::issuance::server::{
    IssuanceState, ManagementState, build_mtls_server_config, build_tls_server_config,
    install_crypto_provider, serve_management, serve_token,
};
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{Keystore, fetch};
use trust::metrics::ProxyMetrics;
use trust::mitm::runtime::MitmRuntime;
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::gcp::GcpSecretProvider;
use trust::secrets::{CachingSecretProvider, SecretProvider};

fn main() {
    env_logger::init();

    let config_path = std::env::var("TRUST_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path).expect("failed to load config");

    let keystore = Arc::new(Keystore::new());
    let metrics = Arc::new(ProxyMetrics::new());
    let proxy_ready = Arc::new(AtomicBool::new(false));

    // Management stack on its own runtime/thread with its own secret provider.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    {
        let keystore = keystore.clone();
        let metrics = metrics.clone();
        let proxy_ready = proxy_ready.clone();
        let config = config.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("management runtime");
            rt.block_on(async move {
                install_crypto_provider();

                // 1. Start liveness/metrics immediately. Readiness remains false until
                // the signing key is loaded and the proxy lifecycle has started.
                let management_addr: std::net::SocketAddr =
                    config.issuance.jwks_addr.parse().expect("jwks_addr");
                let management_state = Arc::new(ManagementState {
                    keystore: keystore.clone(),
                    metrics,
                    proxy_ready,
                });
                tokio::spawn(async move {
                    let result = serve_management(management_addr, management_state).await;
                    log::error!("management server exited: {result:?}");
                    std::process::exit(1);
                });

                // 2. Load signing key and store it.
                let key_provider: Arc<dyn SecretProvider> = Arc::new(GcpSecretProvider::new());
                let km = fetch(key_provider.as_ref(), &config.auth.signing)
                    .await
                    .expect("failed to load signing key");
                keystore.store(km);

                // 3. All fallible issuance setup before signalling ready.
                let tls_cfg = config.tls.as_ref().expect("validated present");
                let server_cert = std::fs::read_to_string(&tls_cfg.cert_path)
                    .expect("issuance needs a server cert (reuse [tls] cert/key)");
                let server_key = std::fs::read_to_string(&tls_cfg.key_path)
                    .expect("issuance needs a server key");
                let client_ca = std::fs::read_to_string(&config.issuance.client_ca_path)
                    .expect("read client CA");
                let mtls_cfg = build_mtls_server_config(&server_cert, &server_key, &client_ca)
                    .expect("mtls server config");

                let token_addr: std::net::SocketAddr =
                    config.issuance.mtls_addr.parse().expect("mtls_addr");

                let issuer = Issuer::new(
                    config.auth.issuer.clone(),
                    config.auth.audience.clone(),
                    config.auth.signing.token_ttl,
                );
                let policy = ClientPolicy::new(&config.issuance.clients)
                    .expect("invalid issuance client policy");
                let state = Arc::new(IssuanceState {
                    keystore: keystore.clone(),
                    issuer,
                    policy,
                });

                // 4. Signal ready only after all setup succeeds.
                ready_tx.send(()).expect("signal ready");

                // 5. Background key refresh (rotation) every 10 minutes.
                {
                    let keystore = keystore.clone();
                    let provider = key_provider.clone();
                    let signing = config.auth.signing.clone();
                    tokio::spawn(async move {
                        let mut tick = tokio::time::interval(Duration::from_secs(600));
                        loop {
                            tick.tick().await;
                            match fetch(provider.as_ref(), &signing).await {
                                Ok(km) => keystore.store(km),
                                Err(e) => log::error!("key refresh failed: {e}"),
                            }
                        }
                    });
                }

                // 6. Serve token issuance; if it exits the process must stop.
                let result = serve_token(token_addr, mtls_cfg, state).await;
                log::error!("token server exited: {result:?}");
                std::process::exit(1);
            });
        });
    }

    // Wait for the first key load so the verifier has keys before serving.
    ready_rx
        .recv()
        .expect("management stack failed to load keys");

    let router = Router::new(&config.upstreams);
    let verifier = Verifier::new(config.auth.issuer.clone(), config.auth.audience.clone());
    let proxy_secrets: Arc<dyn SecretProvider> = Arc::new(CachingSecretProvider::new(
        Arc::new(GcpSecretProvider::new()),
        Duration::from_secs(300),
    ));
    let credentials = Arc::new(CredentialManager::new(
        proxy_secrets,
        config.github_app.clone(),
    ));

    // Use the storage_path from the first git-cache upstream that has a git block.
    // A single MirrorStore root is sufficient: MirrorStore.path_for already
    // namespaces by <upstream>/<owner>/<repo>.git, so all git-cache upstreams
    // can share one root. If no git-cache upstream is present at runtime,
    // MirrorStore is constructed anyway (with a fallback path) but never used.
    let mirror_root = config
        .upstreams
        .iter()
        .find(|u| u.kind == UpstreamKind::GitCache)
        .and_then(|u| u.git.as_ref())
        .map(|g| g.storage_path.clone())
        .unwrap_or_else(|| "/var/cache/trust/mirrors".to_string());
    let mirrors = Arc::new(MirrorStore::new(mirror_root));
    let sync = Arc::new(SyncManager::new());
    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();

    if let Some(forward) = config.forward_proxy.clone() {
        let listener = std::net::TcpListener::bind(&forward.addr).unwrap_or_else(|error| {
            panic!("failed to bind forward proxy {}: {error}", forward.addr)
        });
        listener
            .set_nonblocking(true)
            .expect("set forward proxy listener nonblocking");
        let tls = if forward.tls {
            let tls_config = config.tls.as_ref().expect("validated TLS configuration");
            let certificate = std::fs::read_to_string(&tls_config.cert_path)
                .expect("read forward proxy TLS certificate");
            let key =
                std::fs::read_to_string(&tls_config.key_path).expect("read forward proxy TLS key");
            Some(
                build_tls_server_config(&certificate, &key)
                    .expect("build forward proxy TLS configuration"),
            )
        } else {
            log::warn!(
                "forward proxy is using plaintext HTTP; Proxy-Authorization is not encrypted"
            );
            None
        };
        let mitm = forward.mitm.as_ref().map(|_| {
            let credentials: Arc<dyn CredentialProvider> = credentials.clone();
            MitmRuntime::new(
                &server.configuration,
                &forward,
                &config.upstreams,
                credentials,
                metrics.clone(),
            )
            .expect("initialize forward-proxy TLS interception")
        });
        let state = Arc::new(ConnectProxy::with_mitm(
            Arc::new(Router::new(&config.upstreams)),
            Arc::new(Verifier::new(
                config.auth.issuer.clone(),
                config.auth.audience.clone(),
            )),
            keystore.clone(),
            metrics.clone(),
            forward,
            mitm.clone(),
        ));
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("forward proxy runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("create forward proxy listener");
                if let Err(error) = serve_connect(listener, tls, state).await {
                    log::error!("forward proxy server exited: {error}");
                    std::process::exit(1);
                }
            });
        });
    }

    let service = ProxyService::with_credentials_and_metrics(
        router,
        verifier,
        keystore,
        credentials,
        mirrors,
        sync,
        metrics,
    );

    let mut proxy = http_proxy_service(&server.configuration, service);
    if let Some(tcp) = &config.listen.tcp {
        proxy.add_tcp(tcp);
    }
    if let Some(tls) = &config.tls {
        let settings = TlsSettings::intermediate(&tls.cert_path, &tls.key_path)
            .expect("failed to build TLS settings");
        proxy.add_tls_with_settings(&tls.addr, None, settings);
    }
    server.add_service(proxy);
    proxy_ready.store(true, Ordering::Release);
    log::info!("trust starting (config: {config_path})");
    server.run_forever();
}
