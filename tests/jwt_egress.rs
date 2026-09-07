use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::prelude::*;
use trust::config::{
    CredentialSource, Injection, InjectionScheme, Origin, Upstream, UpstreamKind, UpstreamMode,
};
use trust::credentials::{
    CredentialError, CredentialProvider, ResolutionOutcome, ResolvedCredential,
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
use trust::secrets::fake::FakeSecretProvider;
use trust::secrets::{Secret, SecretProvider};

fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_pem()
}

struct RecordingCredentials {
    resolved_paths: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl CredentialProvider for RecordingCredentials {
    async fn resolve(
        &self,
        _upstream: &Upstream,
        _method: &str,
        path: &str,
        _selector: Option<&str>,
    ) -> Result<ResolvedCredential, CredentialError> {
        self.resolved_paths.lock().unwrap().push(path.to_string());
        Ok(ResolvedCredential {
            secret: Secret::new("INJECTED-INSTALLATION-TOKEN".to_string()),
            cache_key: None,
            result: ResolutionOutcome::Static,
        })
    }
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

fn raw_json_rest_request(
    proxy_port: u16,
    host: &str,
    method: &str,
    path: &str,
    authorization: &str,
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    raw_request_with_method_and_authorization(proxy_port, host, "GET", path, authorization)
}

fn raw_request_with_method_and_authorization(
    proxy_port: u16,
    host: &str,
    method: &str,
    path: &str,
    authorization: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
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
        allowed_paths: Vec::new(),
        allow_connect: false,
        intercept_connect: false,
    })
}

fn linear_upstream(mock_port: u16) -> Arc<Upstream> {
    Arc::new(Upstream {
        name: "linear".into(),
        kind: UpstreamKind::Api,
        listen_host: "linear.test".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: mock_port,
            tls: false,
            sni: String::new(),
        },
        mode: UpstreamMode::Inject,
        credential: Some(CredentialSource::LinearPat {
            secret_refs: [
                ("pit".to_string(), "ref/linear-pit".to_string()),
                ("voi".to_string(), "ref/linear-voi".to_string()),
            ]
            .into_iter()
            .collect(),
        }),
        injection: Some(Injection {
            header: "authorization".into(),
            scheme: InjectionScheme::Raw,
        }),
        resource: None,
        git: None,
        allowed_methods: vec!["POST".into()],
        allowed_paths: Vec::new(),
        allow_connect: false,
        intercept_connect: false,
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
        allowed_paths: Vec::new(),
        allow_connect: false,
        intercept_connect: false,
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
fn linear_personal_api_key_is_injected_verbatim() {
    let (mock_port, upstream_reqs) = start_mock_upstream();
    let keystore = Arc::new(Keystore::new());
    keystore.store(build_key_material(&signing_key_pem(), None).unwrap());
    let km = keystore.load().unwrap();
    let issuer = Issuer::new(
        "trust".into(),
        "trust-proxy".into(),
        Duration::from_secs(3600),
    );
    let now = jsonwebtoken::get_current_timestamp();
    let token = issuer
        .mint(
            &km,
            "spiffe://example/workloads/linear-client",
            &ScopeSet::parse("linear:pit").unwrap(),
            now,
        )
        .unwrap();
    let ambiguous = issuer
        .mint(
            &km,
            "spiffe://example/workloads/linear-client",
            &ScopeSet::parse("linear:pit linear:voi").unwrap(),
            now,
        )
        .unwrap();

    let service = ProxyService::new(
        Router::new(&[linear_upstream(mock_port)]),
        Verifier::new("trust".into(), "trust-proxy".into()),
        keystore,
        Arc::new(FakeSecretProvider::new(&[
            ("ref/linear-pit", "lin_api_PIT_SECRET"),
            ("ref/linear-voi", "lin_api_VOI_SECRET"),
        ])),
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

    let graphql = r#"{"query":"{ viewer { id name } }"}"#;
    assert_eq!(
        raw_json_request(
            proxy_port,
            "linear.test",
            "/graphql",
            "Bearer",
            &ambiguous,
            graphql,
        )
        .0,
        403
    );
    assert_eq!(
        raw_json_request(
            proxy_port,
            "linear.test",
            "/graphql",
            "Bearer",
            &token,
            graphql,
        )
        .0,
        200
    );

    std::thread::sleep(Duration::from_millis(100));
    let requests = upstream_reqs.lock().unwrap();
    let request = requests.last().expect("upstream got a request");
    let lower = request.to_ascii_lowercase();
    assert!(request.starts_with("POST /graphql HTTP/1.1"));
    assert!(lower.contains("authorization: lin_api_pit_secret"));
    assert!(!lower.contains("lin_api_voi_secret"));
    assert!(!request.contains(&token));
}

#[test]
fn github_cli_repository_capabilities_are_bounded_and_scoped() {
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
            &ScopeSet::parse("github-cli:example-org/example-repo").unwrap(),
            jsonwebtoken::get_current_timestamp(),
        )
        .unwrap();
    let wildcard_token = issuer
        .mint(
            &km,
            "spiffe://example/sandbox/test",
            &ScopeSet::parse("github-cli:example-org/*").unwrap(),
            jsonwebtoken::get_current_timestamp(),
        )
        .unwrap();

    let mut upstream = (*scoped_upstream(mock_port)).clone();
    upstream.name = "github-cli".into();
    upstream.resource = Some(ResourceKind::GithubCliRepo);
    upstream.listen_host = "github-cli.test".into();
    let resolved_paths = Arc::new(Mutex::new(Vec::new()));
    let service = ProxyService::with_credentials_and_metrics(
        Router::new(&[Arc::new(upstream)]),
        Verifier::new("trust".into(), "trust-proxy".into()),
        keystore,
        Arc::new(RecordingCredentials {
            resolved_paths: resolved_paths.clone(),
        }),
        Arc::new(MirrorStore::new("/tmp")),
        Arc::new(SyncManager::new()),
        Arc::new(ProxyMetrics::new()),
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

    // `gh label create --force` first creates the repository label, then
    // updates it when GitHub reports that the name already exists. Both
    // writes remain bound to the repository extracted from the path.
    let create_label = serde_json::json!({
        "name": "auto-merge-allowed",
        "color": "1f883d",
        "description": "Allows policy-driven auto merge"
    })
    .to_string();
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "POST",
            "/api/v3/repos/example-org/example-repo/labels",
            &format!("token {token}"),
            &create_label,
        )
        .0,
        200
    );
    let update_label = serde_json::json!({
        "color": "1f883d",
        "description": "Allows policy-driven auto merge"
    })
    .to_string();
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "PATCH",
            "/api/v3/repos/example-org/example-repo/labels/auto-merge-allowed",
            &format!("token {token}"),
            &update_label,
        )
        .0,
        200
    );
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "POST",
            "/api/v3/repos/example-org/other/labels",
            &format!("token {token}"),
            &create_label,
        )
        .0,
        403
    );
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "PATCH",
            "/api/v3/repos/example-org/example-repo/labels/auto-merge-allowed",
            &format!("token {token}"),
            r#"{"new_name":"renamed"}"#,
        )
        .0,
        400
    );

    // Sandbox review automation uses both a top-level issue/PR comment and
    // the dedicated inline review-comment reply endpoint.
    let comment_body = r#"{"body":"Fixed in abc123"}"#;
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "POST",
            "/api/v3/repos/example-org/example-repo/issues/42/comments",
            &format!("token {token}"),
            comment_body,
        )
        .0,
        200
    );
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "POST",
            "/api/v3/repos/example-org/example-repo/pulls/42/comments/99/replies",
            &format!("token {token}"),
            comment_body,
        )
        .0,
        200
    );
    assert_eq!(
        raw_json_rest_request(
            proxy_port,
            "github-cli.test",
            "POST",
            "/api/v3/repos/example-org/other/issues/42/comments",
            &format!("token {token}"),
            comment_body,
        )
        .0,
        403
    );

    // CI inspection is read-only. These representative list, jobs, and log
    // endpoints exercise the paths used by `gh run list/view` and `gh pr checks`.
    for path in [
        "/api/v3/repos/example-org/example-repo/actions/runs",
        "/api/v3/repos/example-org/example-repo/actions/runs/123/jobs",
        "/api/v3/repos/example-org/example-repo/actions/jobs/456/logs",
    ] {
        assert_eq!(
            raw_request_with_authorization(
                proxy_port,
                "github-cli.test",
                path,
                &format!("token {token}"),
            )
            .0,
            200,
            "{path}"
        );
    }

    // The GitHub CLI route does not expose arbitrary REST writes, even when
    // the GitHub App itself has pull-request/content write permissions.
    assert_eq!(
        raw_request_with_method_and_authorization(
            proxy_port,
            "github-cli.test",
            "PATCH",
            "/repos/example-org/example-repo/pulls/1",
            &format!("token {token}"),
        )
        .0,
        405
    );
    assert_eq!(
        raw_request_with_method_and_authorization(
            proxy_port,
            "github-cli.test",
            "PUT",
            "/api/v3/repos/example-org/example-repo/contents/unexpected.txt",
            &format!("token {token}"),
        )
        .0,
        405
    );
    assert_eq!(
        raw_request_with_method_and_authorization(
            proxy_port,
            "github-cli.test",
            "POST",
            "/api/v3/repos/example-org/example-repo/actions/workflows/ci.yml/dispatches",
            &format!("token {token}"),
        )
        .0,
        405
    );
    assert_eq!(
        raw_request_with_method_and_authorization(
            proxy_port,
            "github-cli.test",
            "DELETE",
            "/api/v3/repos/example-org/example-repo/issues/comments/99",
            &format!("token {token}"),
        )
        .0,
        405
    );

    // A custom GH_HOST is treated as GitHub Enterprise. `gh pr create` first
    // probes /meta; Trust answers the bounded local compatibility response
    // rather than forwarding a client JWT or a broad GitHub credential.
    let meta = raw_request_with_authorization(
        proxy_port,
        "github-cli.test",
        "/api/v3/meta",
        &format!("token {token}"),
    );
    assert_eq!(meta.0, 200);
    assert!(meta.1.contains(r#"{"installed_version":"3.17.0"}"#));
    assert_eq!(
        raw_request_with_authorization(
            proxy_port,
            "github-cli.test",
            "/api/v3/meta",
            &format!("token {wildcard_token}"),
        )
        .0,
        403
    );

    let issue_fields = serde_json::json!({
        "query": "query Issue_fields { Issue: __type(name: \"Issue\") { fields(includeDeprecated: true) { name } } }",
        "variables": {}
    })
    .to_string();
    let issue_feature_response = raw_json_request(
        proxy_port,
        "github-cli.test",
        "/api/graphql",
        "token",
        &token,
        &issue_fields,
    );
    assert_eq!(issue_feature_response.0, 200);
    assert!(
        issue_feature_response
            .1
            .contains(r#"{"data":{"Issue":{"fields":[]}}}"#)
    );
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &wildcard_token,
            &issue_fields,
        )
        .0,
        403
    );

    let pull_request_fields = serde_json::json!({
        "query": "query PullRequest_fields { PullRequest: __type(name: \"PullRequest\") { fields(includeDeprecated: true) { name } } StatusCheckRollupContextConnection: __type(name: \"StatusCheckRollupContextConnection\") { fields(includeDeprecated: true) { name } } }",
        "variables": {}
    })
    .to_string();
    let pull_request_feature_response = raw_json_request(
        proxy_port,
        "github-cli.test",
        "/api/graphql",
        "token",
        &token,
        &pull_request_fields,
    );
    assert_eq!(pull_request_feature_response.0, 200);
    assert!(pull_request_feature_response.1.contains(
        r#"{"data":{"PullRequest":{"fields":[]},"StatusCheckRollupContextConnection":{"fields":[]}}}"#
    ));

    let workflow_run_fields = serde_json::json!({
        "query": "query PullRequest_fields2 { WorkflowRun: __type(name: \"WorkflowRun\") { fields(includeDeprecated: true) { name } } }",
        "variables": {}
    })
    .to_string();
    let workflow_run_feature_response = raw_json_request(
        proxy_port,
        "github-cli.test",
        "/api/graphql",
        "token",
        &token,
        &workflow_run_fields,
    );
    assert_eq!(workflow_run_feature_response.0, 200);
    assert!(
        workflow_run_feature_response
            .1
            .contains(r#"{"data":{"WorkflowRun":{"fields":[]}}}"#)
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

    // `gh pr create` sends an opaque repository node ID. Trust accepts only
    // this root mutation and binds it to the sole exact repository scope
    // before minting the injected installation token.
    let create_pull_request = serde_json::json!({
        "query": "mutation PullRequestCreate($input: CreatePullRequestInput!) { createPullRequest(input: $input) { pullRequest { id url } } }",
        "variables": {
            "input": {
                "repositoryId": "R_kgDOExample",
                "title": "Create from Trust",
                "body": "Scoped GitHub App token injection",
                "baseRefName": "main",
                "headRefName": "agent-branch"
            }
        }
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &create_pull_request,
        )
        .0,
        200
    );
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &wildcard_token,
            &create_pull_request,
        )
        .0,
        403
    );

    // `gh pr edit --add-label/--remove-label` uses these two bounded
    // mutations. Their opaque node IDs are authorized through the sole exact
    // repository scope and the repository-restricted installation token.
    let add_labels = serde_json::json!({
        "query": "mutation LabelAdd($input: AddLabelsToLabelableInput!) { addLabelsToLabelable(input: $input) { __typename } }",
        "variables": {
            "input": {
                "labelableId": "PR_kwDOExample",
                "labelIds": ["LA_kwDOAllowed", "LA_kwDOHead"]
            }
        }
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &add_labels,
        )
        .0,
        200
    );
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &wildcard_token,
            &add_labels,
        )
        .0,
        403
    );

    let remove_labels = serde_json::json!({
        "query": "mutation LabelRemove($input: RemoveLabelsFromLabelableInput!) { removeLabelsFromLabelable(input: $input) { __typename } }",
        "variables": {
            "input": {
                "labelableId": "PR_kwDOExample",
                "labelIds": ["LA_kwDOStale"]
            }
        }
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &remove_labels,
        )
        .0,
        200
    );

    // `gh pr checks` uses a bounded node query after its local feature probes.
    // The opaque PR ID is accepted only with one exact repository scope.
    let status_checks = serde_json::json!({
        "query": "query PullRequestStatusChecks($id: ID!, $endCursor: String) { node(id: $id) { ... on PullRequest { statusCheckRollup: commits(last: 1) { nodes { commit { statusCheckRollup { contexts(first: 100, after: $endCursor) { nodes { __typename ... on StatusContext { context state targetUrl createdAt description isRequired(pullRequestId: $id) } ... on CheckRun { name checkSuite { workflowRun { workflow { name } } } status conclusion startedAt completedAt detailsUrl isRequired(pullRequestId: $id) } } pageInfo { hasNextPage endCursor } } } } } } } } }",
        "variables": {"id": "PR_kwDOExample", "endCursor": null}
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &status_checks,
        )
        .0,
        200
    );
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &wildcard_token,
            &status_checks,
        )
        .0,
        403
    );

    // Non-governance PR authoring is bounded to title/body edits, marking a
    // draft ready, and adding a discussion comment.
    let update_pull_request = serde_json::json!({
        "query": "mutation PullRequestUpdate($input: UpdatePullRequestInput!) { updatePullRequest(input: $input) { pullRequest { id } } }",
        "variables": {"input": {
            "pullRequestId": "PR_kwDOExample",
            "title": "Updated title",
            "body": "Updated body"
        }}
    })
    .to_string();
    let mark_ready = serde_json::json!({
        "query": "mutation PullRequestReadyForReview($input: MarkPullRequestReadyForReviewInput!) { markPullRequestReadyForReview(input: $input) { pullRequest { id } } }",
        "variables": {"input": {"pullRequestId": "PR_kwDOExample"}}
    })
    .to_string();
    let add_comment = serde_json::json!({
        "query": "mutation CommentCreate($input: AddCommentInput!) { addComment(input: $input) { commentEdge { node { url } } } }",
        "variables": {"input": {
            "subjectId": "PR_kwDOExample",
            "body": "Review follow-up"
        }}
    })
    .to_string();
    for operation in [&update_pull_request, &mark_ready, &add_comment] {
        assert_eq!(
            raw_json_request(
                proxy_port,
                "github-cli.test",
                "/api/graphql",
                "token",
                &token,
                operation,
            )
            .0,
            200
        );
    }

    // Merge governance and base-branch changes remain blocked.
    let destructive = serde_json::json!({
        "query": "mutation Blocked($input: EnablePullRequestAutoMergeInput!) { enablePullRequestAutoMerge(input: $input) { pullRequest { id } } }",
        "variables": {"input": {
            "pullRequestId": "PR_kwDOExample",
            "mergeMethod": "SQUASH"
        }}
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &destructive,
        )
        .0,
        403
    );

    let base_change = serde_json::json!({
        "query": "mutation PullRequestUpdate($input: UpdatePullRequestInput!) { updatePullRequest(input: $input) { pullRequest { id } } }",
        "variables": {"input": {
            "pullRequestId": "PR_kwDOExample",
            "baseRefName": "release"
        }}
    })
    .to_string();
    assert_eq!(
        raw_json_request(
            proxy_port,
            "github-cli.test",
            "/api/graphql",
            "token",
            &token,
            &base_change,
        )
        .0,
        403
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
    assert_eq!(requests.len(), 16);
    assert!(requests[0].starts_with("GET /repos/example-org/example-repo/pulls HTTP/1.1"));
    assert!(requests[1].starts_with("POST /repos/example-org/example-repo/labels HTTP/1.1"));
    assert!(requests[1].ends_with(&create_label));
    assert!(
        requests[2].starts_with(
            "PATCH /repos/example-org/example-repo/labels/auto-merge-allowed HTTP/1.1"
        )
    );
    assert!(requests[2].ends_with(&update_label));
    assert!(
        requests[3].starts_with("POST /repos/example-org/example-repo/issues/42/comments HTTP/1.1")
    );
    assert!(
        requests[4].starts_with(
            "POST /repos/example-org/example-repo/pulls/42/comments/99/replies HTTP/1.1"
        )
    );
    assert!(requests[5].starts_with("GET /repos/example-org/example-repo/actions/runs HTTP/1.1"));
    assert!(
        requests[6]
            .starts_with("GET /repos/example-org/example-repo/actions/runs/123/jobs HTTP/1.1")
    );
    assert!(
        requests[7]
            .starts_with("GET /repos/example-org/example-repo/actions/jobs/456/logs HTTP/1.1")
    );
    for (request, body) in [
        (&requests[8], &graphql),
        (&requests[9], &create_pull_request),
        (&requests[10], &add_labels),
        (&requests[11], &remove_labels),
        (&requests[12], &status_checks),
        (&requests[13], &update_pull_request),
        (&requests[14], &mark_ready),
        (&requests[15], &add_comment),
    ] {
        assert!(request.starts_with("POST /graphql HTTP/1.1"));
        assert!(request.ends_with(body));
    }
    for request in requests.iter() {
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer injected-installation-token"));
        assert!(!request.contains(&token));
    }
    assert_eq!(
        *resolved_paths.lock().unwrap(),
        vec![
            "/repos/example-org/example-repo/pulls",
            "/repos/example-org/example-repo/labels",
            "/repos/example-org/example-repo/labels/auto-merge-allowed",
            "/repos/example-org/example-repo/issues/42/comments",
            "/repos/example-org/example-repo/pulls/42/comments/99/replies",
            "/repos/example-org/example-repo/actions/runs",
            "/repos/example-org/example-repo/actions/runs/123/jobs",
            "/repos/example-org/example-repo/actions/jobs/456/logs",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
            "/repos/example-org/example-repo",
        ]
    );
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
