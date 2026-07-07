use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;

use trust::config::Config;
use trust::issuance::policy::ClientPolicy;
use trust::issuance::server::{
    IssuanceState, build_mtls_server_config, install_crypto_provider, serve_jwks, serve_token,
};
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{Keystore, fetch};
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::gcp::GcpSecretProvider;
use trust::secrets::{CachingSecretProvider, SecretProvider};

fn main() {
    env_logger::init();

    let config_path = std::env::var("TRUST_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path).expect("failed to load config");

    let keystore = Arc::new(Keystore::new());

    // Management stack on its own runtime/thread with its own secret provider.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    {
        let keystore = keystore.clone();
        let config = config.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("management runtime");
            rt.block_on(async move {
                install_crypto_provider();

                let key_provider: Arc<dyn SecretProvider> = Arc::new(GcpSecretProvider::new());
                let km = fetch(key_provider.as_ref(), &config.auth.signing)
                    .await
                    .expect("failed to load signing key");
                keystore.store(km);
                ready_tx.send(()).expect("signal ready");

                // Background key refresh (rotation) every 10 minutes.
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

                let server_cert = std::fs::read_to_string(
                    config
                        .tls
                        .as_ref()
                        .map(|t| t.cert_path.as_str())
                        .unwrap_or(""),
                )
                .expect("issuance needs a server cert (reuse [tls] cert/key)");
                let server_key = std::fs::read_to_string(
                    config
                        .tls
                        .as_ref()
                        .map(|t| t.key_path.as_str())
                        .unwrap_or(""),
                )
                .expect("issuance needs a server key");
                let client_ca = std::fs::read_to_string(&config.issuance.client_ca_path)
                    .expect("read client CA");
                let tls = build_mtls_server_config(&server_cert, &server_key, &client_ca)
                    .expect("mtls server config");

                let token_addr = config.issuance.mtls_addr.parse().expect("mtls_addr");
                let jwks_addr = config.issuance.jwks_addr.parse().expect("jwks_addr");
                let jwks_ks = keystore.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_jwks(jwks_addr, jwks_ks).await {
                        log::error!("jwks server exited: {e}");
                    }
                });
                if let Err(e) = serve_token(token_addr, tls, state).await {
                    log::error!("token server exited: {e}");
                }
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
    let service = ProxyService::new(router, verifier, keystore, proxy_secrets);

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();
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
    log::info!("trust starting (config: {config_path})");
    server.run_forever();
}
