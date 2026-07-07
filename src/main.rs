use std::sync::Arc;
use std::time::Duration;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;

use trust::auth::TokenMap;
use trust::config::Config;
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::gcp::GcpSecretProvider;
use trust::secrets::{CachingSecretProvider, SecretProvider};

fn main() {
    env_logger::init();

    let config_path = std::env::var("TRUST_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path).expect("failed to load config");

    let router = Router::new(&config.upstreams);
    let tokens = TokenMap::new(&config.tokens);

    let base: Arc<dyn SecretProvider> = Arc::new(GcpSecretProvider::new());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(CachingSecretProvider::new(base, Duration::from_secs(300)));

    let service = ProxyService::new(router, tokens, secrets);

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
