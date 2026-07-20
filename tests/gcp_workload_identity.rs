//! Integration coverage for the two-token GKE Workload Identity flow.
//!
//! The trust JWT authenticates the CONNECT request. A separate Google OAuth
//! access token travels inside the tunnel and must reach the Google API without
//! the trust JWT or CONNECT headers being forwarded.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use trust::config::{ForwardProxyConfig, Origin, Upstream, UpstreamKind, UpstreamMode};
use trust::connect::{ConnectProxy, serve_connect};
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{Keystore, build_key_material};
use trust::metrics::ProxyMetrics;
use trust::router::Router;
use trust::scope::ScopeSet;

async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        assert!(head.len() < 16 * 1024, "oversized HTTP header");
    }
    head
}

#[tokio::test]
async fn connect_consumes_trust_jwt_and_preserves_google_oauth_token() {
    let google_api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let google_api_port = google_api.local_addr().unwrap().port();
    let (request_tx, request_rx) = oneshot::channel();
    let google_api_task = tokio::spawn(async move {
        let (mut stream, _) = google_api.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        request_tx.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let upstream = Arc::new(Upstream {
        name: "gcp-pubsub".into(),
        kind: UpstreamKind::Api,
        listen_host: "pubsub.proxy.internal".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: google_api_port,
            tls: true,
            sni: "pubsub.googleapis.com".into(),
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

    let keystore = Arc::new(Keystore::new());
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    keystore.store(build_key_material(&key.serialize_pem(), None).unwrap());
    let keys = keystore.load().unwrap();
    let issuer = Issuer::new(
        "trust".into(),
        "trust-proxy".into(),
        Duration::from_secs(60),
    );
    let trust_jwt = issuer
        .mint(
            &keys,
            "spiffe://example/workloads/sandbox",
            &ScopeSet::parse("gcp-pubsub").unwrap(),
            jsonwebtoken::get_current_timestamp(),
        )
        .unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy = Arc::new(ConnectProxy::new(
        Arc::new(Router::new(&[upstream])),
        Arc::new(Verifier::new("trust".into(), "trust-proxy".into())),
        keystore,
        Arc::new(ProxyMetrics::new()),
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
    let proxy_task = tokio::spawn(serve_connect(proxy_listener, None, proxy));

    let authority = format!("127.0.0.1:{google_api_port}");
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Bearer {trust_jwt}\r\nX-Connect-Only: must-not-reach-google\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_head(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let google_oauth_token = "ya29.mock-workload-identity-access-token";
    client
        .write_all(
            format!(
                "POST /v1/projects/example/topics/events:publish HTTP/1.1\r\nHost: pubsub.googleapis.com\r\nAuthorization: Bearer {google_oauth_token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let captured = timeout(Duration::from_secs(2), request_rx)
        .await
        .expect("mock Google API timed out")
        .expect("mock Google API dropped captured request");
    let captured = String::from_utf8(captured).unwrap();
    assert!(
        captured.contains(&format!("Authorization: Bearer {google_oauth_token}")),
        "Google OAuth token was not preserved: {captured}"
    );
    assert!(!captured.contains(&trust_jwt), "trust JWT leaked upstream");
    assert!(!captured.contains("Proxy-Authorization"));
    assert!(!captured.contains("X-Connect-Only"));

    google_api_task.await.unwrap();
    proxy_task.abort();
}
