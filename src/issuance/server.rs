use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_server_mtls::PeerCertificates;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;

use crate::issuance::mtls::extract_spiffe;
use crate::issuance::policy::ClientPolicy;
use crate::jwt::Issuer;
use crate::keystore::Keystore;
use crate::metrics::ProxyMetrics;
use crate::scope::{ScopeSet, grant};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("tls config error: {0}")]
    Tls(String),
    #[error("bind/serve error: {0}")]
    Serve(String),
}

pub struct IssuanceState {
    pub keystore: Arc<Keystore>,
    pub issuer: Issuer,
    pub policy: ClientPolicy,
}

pub struct ManagementState {
    pub keystore: Arc<Keystore>,
    pub metrics: Arc<ProxyMetrics>,
    pub proxy_ready: Arc<AtomicBool>,
}

/// Install the rustls aws-lc-rs crypto provider (idempotent).
pub fn install_crypto_provider() {
    // Ignore the error if a provider is already installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(e.to_string()))
}

pub fn build_mtls_server_config(
    server_cert_pem: &str,
    server_key_pem: &str,
    client_ca_pem: &str,
) -> Result<Arc<ServerConfig>, ServerError> {
    let mut roots = RootCertStore::empty();
    for ca in certs_from_pem(client_ca_pem)? {
        roots.add(ca).map_err(|e| ServerError::Tls(e.to_string()))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| ServerError::Tls(e.to_string()))?;

    let server_certs = certs_from_pem(server_cert_pem)?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut server_key_pem.as_bytes())
        .map_err(|e| ServerError::Tls(e.to_string()))?
        .ok_or_else(|| ServerError::Tls("no private key in server key PEM".into()))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

pub fn build_tls_server_config(
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<Arc<ServerConfig>, ServerError> {
    let server_certs = certs_from_pem(server_cert_pem)?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut server_key_pem.as_bytes())
        .map_err(|e| ServerError::Tls(e.to_string()))?
        .ok_or_else(|| ServerError::Tls("no private key in server key PEM".into()))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(serde::Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
}

async fn token_handler(
    State(state): State<Arc<IssuanceState>>,
    Extension(certs): Extension<PeerCertificates>,
    Form(form): Form<TokenForm>,
) -> axum::response::Response {
    if form.grant_type != "client_credentials" {
        return (StatusCode::BAD_REQUEST, "unsupported_grant_type").into_response();
    }
    // Extract SPIFFE identity from the mTLS client leaf cert.
    let Some(leaf) = certs.leaf() else {
        return (StatusCode::UNAUTHORIZED, "no client certificate").into_response();
    };
    let Some(spiffe) = extract_spiffe(leaf.as_ref()) else {
        return (StatusCode::UNAUTHORIZED, "no spiffe identity").into_response();
    };
    let Some(allowed) = state.policy.allowed_scopes(&spiffe) else {
        return (StatusCode::FORBIDDEN, "identity not authorized").into_response();
    };

    // Requested scopes default to the full allowed set.
    let requested = match &form.scope {
        Some(s) => match ScopeSet::parse(s) {
            Ok(rs) => rs,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid_scope").into_response(),
        },
        None => allowed.clone(),
    };
    if let Err(bad) = grant(allowed, &requested) {
        return (StatusCode::BAD_REQUEST, format!("invalid_scope: {bad}")).into_response();
    }

    let Some(km) = state.keystore.load() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "signing key unavailable").into_response();
    };
    let now = jsonwebtoken::get_current_timestamp();
    match state.issuer.mint(&km, &spiffe, &requested, now) {
        Ok(token) => Json(TokenResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in: state.issuer.ttl_secs(),
            scope: requested.to_scope_string(),
        })
        .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "mint failed").into_response(),
    }
}

async fn jwks_handler(State(state): State<Arc<ManagementState>>) -> axum::response::Response {
    match state.keystore.load() {
        Some(km) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            km.jwks_json.clone(),
        )
            .into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "no keys").into_response(),
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn readiness_handler(State(state): State<Arc<ManagementState>>) -> axum::response::Response {
    if state.proxy_ready.load(Ordering::Acquire) && state.keystore.load().is_some() {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
    }
}

async fn metrics_handler(State(state): State<Arc<ManagementState>>) -> axum::response::Response {
    match state.metrics.encode() {
        Ok(body) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(e) => {
            log::error!("failed to encode metrics: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable\n").into_response()
        }
    }
}

pub fn token_router(state: Arc<IssuanceState>) -> Router {
    Router::new()
        .route("/token", post(token_handler))
        .with_state(state)
}

pub fn management_router(state: Arc<ManagementState>) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/healthz", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

pub async fn serve_token(
    addr: std::net::SocketAddr,
    tls: Arc<ServerConfig>,
    state: Arc<IssuanceState>,
) -> Result<(), ServerError> {
    use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
    use axum_server_mtls::MtlsAcceptor;

    let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(RustlsConfig::from_config(tls)));
    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(token_router(state).into_make_service())
        .await
        .map_err(|e| ServerError::Serve(e.to_string()))
}

pub async fn serve_management(
    addr: std::net::SocketAddr,
    state: Arc<ManagementState>,
) -> Result<(), ServerError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ServerError::Serve(e.to_string()))?;
    axum::serve(listener, management_router(state).into_make_service())
        .await
        .map_err(|e| ServerError::Serve(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::build_key_material;

    fn management_state(keystore: Arc<Keystore>, ready: bool) -> Arc<ManagementState> {
        Arc::new(ManagementState {
            keystore,
            metrics: Arc::new(ProxyMetrics::new()),
            proxy_ready: Arc::new(AtomicBool::new(ready)),
        })
    }

    fn gen_rcgen_cert_and_key() -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    #[test]
    fn build_mtls_server_config_ok() {
        install_crypto_provider();

        let (server_cert, server_key) = gen_rcgen_cert_and_key();
        let (ca_cert, _ca_key) = gen_rcgen_cert_and_key();

        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();
        let ca_pem = ca_cert.pem();

        let result = build_mtls_server_config(&server_cert_pem, &server_key_pem, &ca_pem);
        assert!(
            result.is_ok(),
            "build_mtls_server_config failed: {result:?}"
        );
    }

    #[test]
    fn build_mtls_server_config_bad_ca_rejected() {
        install_crypto_provider();

        let (server_cert, server_key) = gen_rcgen_cert_and_key();
        let result =
            build_mtls_server_config(&server_cert.pem(), &server_key.serialize_pem(), "not-a-pem");
        // Empty CA roots should cause WebPkiClientVerifier::build() to fail.
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn jwks_router_returns_503_when_empty() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let ks = Arc::new(Keystore::new());
        let router = management_router(management_state(ks, false));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    }

    #[tokio::test]
    async fn jwks_router_returns_200_when_loaded() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let km = build_key_material(&key.serialize_pem(), None).unwrap();
        let ks = Arc::new(Keystore::new());
        ks.store(km);
        let router = management_router(management_state(ks, true));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("keys").is_some());
    }

    #[tokio::test]
    async fn health_is_live_while_readiness_tracks_proxy_and_keys() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let ks = Arc::new(Keystore::new());
        let state = management_state(ks.clone(), false);
        let router = management_router(state.clone());

        let live = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live.status(), StatusCode::OK);

        let not_ready = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        ks.store(build_key_material(&key.serialize_pem(), None).unwrap());
        state.proxy_ready.store(true, Ordering::Release);

        let ready = router
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_uses_prometheus_content_type() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = management_state(Arc::new(Keystore::new()), false);
        state.metrics.request_started();
        state.metrics.request_finished("unrouted", 404, 0.01);

        let response = management_router(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("trust_proxy_requests_total"));
    }
}
