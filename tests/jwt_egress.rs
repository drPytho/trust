use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::prelude::*;
use trust::config::{
    CredentialSource, Injection, InjectionScheme, Origin, Upstream, UpstreamKind, UpstreamMode,
};
use trust::git::mirror::MirrorStore;
use trust::git::sync::SyncManager;
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{Keystore, build_key_material};
use trust::metrics::ProxyMetrics;
use trust::proxy::ProxyService;
use trust::resource::ResourceKind;
use trust::router::Router;
use trust::scope::ScopeSet;
use trust::secrets::SecretProvider;
use trust::secrets::fake::FakeSecretProvider;

fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_pem()
}

fn start_mock_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = received.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            sink.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&request).to_string());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, received)
}

fn raw_json_request(
    proxy_port: u16,
    host: &str,
    path: &str,
    auth_scheme: &str,
    token: &str,
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {auth_scheme} {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let status = resp
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn raw_request(proxy_port: u16, host: &str, path: &str, bearer: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(b) = bearer {
        req.push_str(&format!("Authorization: Bearer {b}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp)
}

fn raw_request_with_authorization(
    proxy_port: u16,
    host: &str,
    path: &str,
    authorization: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let status = resp
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp)
}

fn passthrough_request(
    proxy_port: u16,
    host: &str,
    proxy_bearer: Option<&str>,
    authorization: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let mut req = format!("GET /resource HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(token) = proxy_bearer {
        req.push_str(&format!("Proxy-Authorization: Bearer {token}\r\n"));
    }
    if let Some(value) = authorization {
        req.push_str(&format!("Authorization: {value}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let status = resp
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp)
}

fn scoped_upstream(mock_port: u16) -> Arc<Upstream> {
    Arc::new(Upstream {
        name: "github".into(),
        kind: UpstreamKind::Api,
        listen_host: "gh.test".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: mock_port,
            tls: false,
            sni: String::new(),
        },
        mode: UpstreamMode::Inject,
        credential: Some(CredentialSource::StaticSecret {
            secret_ref: "ref/gh".into(),
        }),
        injection: Some(Injection {
            header: "authorization".into(),
            scheme: InjectionScheme::Bearer,
        }),
        resource: Some(ResourceKind::GithubRepo),
        git: None,
        allowed_methods: Vec::new(),
        allow_connect: false,
    })
}

fn passthrough_upstream(mock_port: u16) -> Arc<Upstream> {
    Arc::new(Upstream {
        name: "public-api".into(),
        kind: UpstreamKind::Api,
        listen_host: "public.test".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: mock_port,
            tls: false,
            sni: String::new(),
        },
        mode: UpstreamMode::Passthrough,
        credential: None,
        injection: None,
        resource: None,
        git: None,
        allowed_methods: vec!["GET".into()],
        allow_connect: false,
    })
}

#[test]
fn jwt_scoped_egress_end_to_end() {
    let (mock_port, upstream_reqs) = start_mock_upstream();

    // Shared keystore with a freshly generated signing key.
    let keystore = Arc::new(Keystore::new());
    keystore.store(build_key_material(&signing_key_pem(), None).unwrap());
    let km = keystore.load().unwrap();

    // Mint a token scoped to github:example-org/example-repo.
    let issuer = Issuer::new(
        "trust".into(),
        "trust-proxy".into(),
        Duration::from_secs(3600),
    );
    let now = jsonwebtoken::get_current_timestamp();
    let scopes = ScopeSet::parse("github:example-org/example-repo").unwrap();
    let token = issuer
        .mint(&km, "spiffe://example/ci/example-repo", &scopes, now)
        .unwrap();
    let expired = issuer.mint(&km, "s", &scopes, now - 100_000).unwrap();

    // Build the proxy with the same keystore + a github upstream pointing at the mock.
    let router = Router::new(&[scoped_upstream(mock_port)]);
    let verifier = Verifier::new("trust".into(), "trust-proxy".into());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(FakeSecretProvider::new(&[("ref/gh", "INJECTED-TOKEN")]));
    // The JWT egress test doesn't exercise git-cache; /tmp is a valid placeholder.
    let mirrors = Arc::new(MirrorStore::new("/tmp"));
    let sync = Arc::new(SyncManager::new());
    let metrics = Arc::new(ProxyMetrics::new());
    let service = ProxyService::with_metrics(
        router,
        verifier,
        keystore,
        secrets,
        mirrors,
        sync,
        metrics.clone(),
    );

    let proxy_port = free_port();
    let addr = format!("127.0.0.1:{proxy_port}");
    std::thread::spawn(move || {
        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut proxy = http_proxy_service(&server.configuration, service);
        proxy.add_tcp(&addr);
        server.add_service(proxy);
        server.run_forever();
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Unknown host → 404.
    assert_eq!(raw_request(proxy_port, "unknown.test", "/", None).0, 404);
    // Missing token → 401.
    assert_eq!(
        raw_request(
            proxy_port,
            "gh.test",
            "/repos/example-org/example-repo/x",
            None
        )
        .0,
        401
    );
    // Expired token → 401.
    assert_eq!(
        raw_request(
            proxy_port,
            "gh.test",
            "/repos/example-org/example-repo/x",
            Some(&expired)
        )
        .0,
        401
    );
    // Valid token, repo OUT of scope → 403.
    assert_eq!(
        raw_request(
            proxy_port,
            "gh.test",
            "/repos/example-org/other/x",
            Some(&token)
        )
        .0,
        403
    );
    // Valid token, repo IN scope → 200.
    let (status, _) = raw_request(
        proxy_port,
        "gh.test",
        "/repos/example-org/example-repo/x",
        Some(&token),
    );
    assert_eq!(status, 200);

    std::thread::sleep(Duration::from_millis(100));
    let rendered_metrics = String::from_utf8(metrics.encode().unwrap()).unwrap();
    for expected in [
        "trust_proxy_rejections_total{reason=\"unknown_host\",status=\"404\",upstream=\"unrouted\"} 1",
        "trust_proxy_rejections_total{reason=\"missing_token\",status=\"401\",upstream=\"github\"} 1",
        "trust_proxy_rejections_total{reason=\"invalid_token\",status=\"401\",upstream=\"github\"} 1",
        "trust_proxy_rejections_total{reason=\"forbidden_scope\",status=\"403\",upstream=\"github\"} 1",
    ] {
        assert!(
            rendered_metrics.contains(expected),
            "missing rejection metric: {expected}"
        );
    }

    let reqs = upstream_reqs.lock().unwrap();
    let last = reqs.last().expect("upstream got a request");
    let lower = last.to_lowercase();
    assert!(
        lower.contains("authorization: bearer injected-token"),
        "secret not injected: {last}"
    );
    assert!(
        !lower.contains(&token.to_lowercase()),
        "client JWT leaked upstream: {last}"
    );
    assert!(
        lower.contains("host: 127.0.0.1"),
        "host not rewritten: {last}"
    );
}

#[test]
fn github_cli_rest_and_repo_rooted_graphql_are_proxied_without_connect() {
    let (mock_port, upstream_reqs) = start_mock_upstream();
    let keystore = Arc::new(Keystore::new());
    keystore.store(build_key_material(&signing_key_pem(), None).unwrap());
    let km = keystore.load().unwrap();
    let issuer = Issuer::new(
        "trust".into(),
        "trust-proxy".into(),
        Duration::from_secs(3600),
    );
    let token = issuer
        .mint(
            &km,
            "spiffe://example/sandbox/test",
            &ScopeSet::parse("github:example-org/example-repo").unwrap(),
            jsonwebtoken::get_current_timestamp(),
        )
        .unwrap();

    let mut upstream = (*scoped_upstream(mock_port)).clone();
    upstream.resource = Some(ResourceKind::GithubCliRepo);
    upstream.listen_host = "github-cli.test".into();
    let service = ProxyService::new(
        Router::new(&[Arc::new(upstream)]),
        Verifier::new("trust".into(), "trust-proxy".into()),
        keystore,
        Arc::new(FakeSecretProvider::new(&[(
            "ref/gh",
            "INJECTED-INSTALLATION-TOKEN",
        )])),
        Arc::new(MirrorStore::new("/tmp")),
        Arc::new(SyncManager::new()),
    );
    let proxy_port = free_port();
    let addr = format!("127.0.0.1:{proxy_port}");
    std::thread::spawn(move || {
        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut proxy = http_proxy_service(&server.configuration, service);
        proxy.add_tcp(&addr);
        server.add_service(proxy);
        server.run_forever();
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // `gh api` uses the Enterprise REST prefix and the `token` auth scheme.
    assert_eq!(
        raw_request_with_authorization(
            proxy_port,
            "github-cli.test",
            "/api/v3/repos/example-org/example-repo/pulls",
            &format!("token {token}"),
        )
        .0,
        200
    );
    assert_eq!(
        raw_request_with_authorization(
            proxy_port,
            "github-cli.test",
            "/api/v3/repos/example-org/other/pulls",
            &format!("token {token}"),
        )
        .0,
        403
    );

    let graphql = serde_json::json!({
        "query": "query PullRequestList($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { pullRequests(first: 10) { totalCount } } }",
        "variables": {"owner": "example-org", "repo": "example-repo"}
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &graphql,
        )
        .0,
        200
    );

    // Global GraphQL operations fail before reaching the upstream.
    let global = serde_json::json!({
        "query": "query Viewer { viewer { login } }",
        "variables": {"owner": "example-org", "repo": "example-repo"}
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &global,
        )
        .0,
        403
    );

    std::thread::sleep(Duration::from_millis(100));
    let requests = upstream_reqs.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /repos/example-org/example-repo/pulls HTTP/1.1"));
    assert!(requests[1].starts_with("POST /graphql HTTP/1.1"));
    assert!(requests[1].ends_with(&graphql));
    for request in requests.iter() {
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer injected-installation-token"));
        assert!(!request.contains(&token));
    }
}

#[test]
fn authenticated_passthrough_preserves_caller_authorization() {
    let (mock_port, upstream_reqs) = start_mock_upstream();
    let keystore = Arc::new(Keystore::new());
    keystore.store(build_key_material(&signing_key_pem(), None).unwrap());
    let km = keystore.load().unwrap();
    let issuer = Issuer::new(
        "trust".into(),
        "trust-proxy".into(),
        Duration::from_secs(3600),
    );
    let token = issuer
        .mint(
            &km,
            "spiffe://example/workloads/client",
            &ScopeSet::parse("public-api").unwrap(),
            jsonwebtoken::get_current_timestamp(),
        )
        .unwrap();

    let router = Router::new(&[passthrough_upstream(mock_port)]);
    let verifier = Verifier::new("trust".into(), "trust-proxy".into());
    let secrets: Arc<dyn SecretProvider> = Arc::new(FakeSecretProvider::new(&[]));
    let service = ProxyService::new(
        router,
        verifier,
        keystore,
        secrets,
        Arc::new(MirrorStore::new("/tmp")),
        Arc::new(SyncManager::new()),
    );
    let proxy_port = free_port();
    let addr = format!("127.0.0.1:{proxy_port}");
    std::thread::spawn(move || {
        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut proxy = http_proxy_service(&server.configuration, service);
        proxy.add_tcp(&addr);
        server.add_service(proxy);
        server.run_forever();
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // A caller Authorization header is not accepted as proxy authentication in
    // passthrough mode because it must remain available to the upstream.
    assert_eq!(
        passthrough_request(proxy_port, "public.test", None, Some("Bearer caller-token")).0,
        401
    );
    assert_eq!(
        passthrough_request(
            proxy_port,
            "public.test",
            Some(&token),
            Some("Bearer caller-token"),
        )
        .0,
        200
    );

    std::thread::sleep(Duration::from_millis(100));
    let requests = upstream_reqs.lock().unwrap();
    let request = requests.last().expect("upstream got passthrough request");
    let lower = request.to_lowercase();
    assert!(lower.contains("authorization: bearer caller-token"));
    assert!(!lower.contains("proxy-authorization"));
    assert!(!lower.contains(&token.to_lowercase()));
}

/// Issuance sub-test: proves the `ClientPolicy` → `grant` → `Issuer::mint` path.
///
/// Approach: direct composition (not axum oneshot with PeerCertificates).
/// We drive the decision functions directly — `ClientPolicy::allowed_scopes`, `scope::grant`,
/// and `Issuer::mint` — then verify the result via `Verifier::verify`.
///
/// Why not `tower::ServiceExt::oneshot`? `PeerCertificates::new()` IS public (axum-server-mtls
/// 0.1.2 exposes it), so injection into a `oneshot` would be feasible. However, doing it directly
/// via the policy/grant/mint path is simpler, faster, and tests the exact same decision logic that
/// `token_handler` calls. The mTLS transport is already covered by unit tests in
/// `src/issuance/mtls.rs` (`extract_spiffe`) and `src/issuance/server.rs`
/// (`build_mtls_server_config_ok`).
#[test]
fn issuance_policy_and_grant_decision() {
    use trust::config::ClientEntry;
    use trust::issuance::policy::ClientPolicy;
    use trust::scope::grant;

    let km = {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        build_key_material(&key.serialize_pem(), None).unwrap()
    };

    // Build a policy granting `github:example-org/*` to `spiffe://example/ci/example-repo`.
    let policy = ClientPolicy::new(&[ClientEntry {
        spiffe: "spiffe://example/ci/example-repo".into(),
        allowed_scopes: vec!["github:example-org/*".into()],
    }])
    .unwrap();

    let spiffe = "spiffe://example/ci/example-repo";

    // --- Happy path: request github:example-org/example-repo ---
    let allowed = policy
        .allowed_scopes(spiffe)
        .expect("policy should know this identity");
    let requested_good = ScopeSet::parse("github:example-org/example-repo").unwrap();
    grant(allowed, &requested_good)
        .expect("github:example-org/example-repo should be covered by github:example-org/*");

    let issuer = Issuer::new(
        "trust".into(),
        "trust-proxy".into(),
        Duration::from_secs(3600),
    );
    let now = jsonwebtoken::get_current_timestamp();
    let token = issuer.mint(&km, spiffe, &requested_good, now).unwrap();

    let verifier = Verifier::new("trust".into(), "trust-proxy".into());
    let got_scopes = verifier
        .verify(&km, &token)
        .expect("minted token should verify");
    assert_eq!(
        got_scopes.to_scope_string(),
        "github:example-org/example-repo"
    );

    // --- Denied: request mistral (not in policy) ---
    let requested_bad = ScopeSet::parse("mistral").unwrap();
    let err = grant(allowed, &requested_bad).expect_err("mistral should be denied");
    assert_eq!(err, "mistral");
}
