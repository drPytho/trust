use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::prelude::*;
use trust::auth::{TokenEntry, TokenMap};
use trust::config::{Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
use trust::proxy::ProxyService;
use trust::router::Router;
use trust::secrets::SecretProvider;
use trust::secrets::fake::FakeSecretProvider;

/// Mock upstream: records the first request it receives, replies 200.
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
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            sink.lock().unwrap().push(req);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, received)
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Send a raw HTTP/1.1 request to the proxy; return (status_code, full_response).
fn raw_request(proxy_port: u16, host: &str, auth: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    let mut req = format!("GET /v1/thing HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
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

#[test]
fn api_egress_end_to_end() {
    let (mock_port, upstream_reqs) = start_mock_upstream();

    let upstream = Arc::new(Upstream {
        name: "api".into(),
        kind: UpstreamKind::Api,
        listen_host: "api.test".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: mock_port,
            tls: false,
            sni: String::new(),
        },
        secret_ref: "ref/api".into(),
        injection: Injection {
            header: "x-api-key".into(),
            scheme: InjectionScheme::Raw,
        },
        resource: None,
    });

    let router = Router::new(&[upstream]);
    let tokens = TokenMap::new(&[TokenEntry {
        token: "good".into(),
        principal: "team".into(),
        allowed_upstreams: vec!["api".into()],
    }]);
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(FakeSecretProvider::new(&[("ref/api", "INJECTED-SECRET")]));
    let service = ProxyService::new(router, tokens, secrets);

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

    // Wait until the proxy is accepting connections.
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 404 unknown host.
    assert_eq!(
        raw_request(proxy_port, "nope.test", Some("Bearer good")).0,
        404
    );
    // 401 missing token.
    assert_eq!(raw_request(proxy_port, "api.test", None).0, 401);
    // 401 wrong token.
    assert_eq!(
        raw_request(proxy_port, "api.test", Some("Bearer wrong")).0,
        401
    );

    // 200 happy path.
    let (status, _resp) = raw_request(proxy_port, "api.test", Some("Bearer good"));
    assert_eq!(status, 200);

    // Give the mock a moment to record.
    std::thread::sleep(Duration::from_millis(100));
    let reqs = upstream_reqs.lock().unwrap();
    let last = reqs.last().expect("upstream received a request");
    let lower = last.to_lowercase();
    // Secret injected...
    assert!(
        lower.contains("x-api-key: injected-secret"),
        "missing injected secret: {last}"
    );
    // ...and the client's proxy token stripped.
    assert!(
        !lower.contains("bearer good"),
        "client token leaked upstream: {last}"
    );
    // ...and Host rewritten to the real upstream.
    assert!(
        lower.contains("host: 127.0.0.1"),
        "host not rewritten: {last}"
    );
}
