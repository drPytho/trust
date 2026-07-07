//! End-to-end integration test for the git-cache upstream.
//!
//! # Architecture
//!
//! ## Origin server
//! We spin a local HTTP server (one thread per connection, raw TCP) that
//! delegates every request to `git http-backend` against a temp bare repo.
//! This lets `MirrorStore::ensure` clone via `http://127.0.0.1:{PORT}/…` and
//! lets the proxy push passthrough land on the same origin.
//!
//! ## Multi-chunk validation (C1/I1 regression guard)
//! We seed the origin with a ~210 KiB binary blob so the clone packfile body
//! spans multiple 64 KiB streaming chunks (well above the HEAD_CAP constant in
//! proxy.rs, which is also 64 KiB).  This guards against regressions of the
//! C1 (stdin loop) and I1 (incremental stdout streaming) fixes.
//!
//! ## Origin URL
//! `git clone --mirror` (inside MirrorStore::ensure) fetches from
//! `http://127.0.0.1:{origin_port}/testorg/testrepo.git`.  We run a minimal
//! HTTP server backed by `git http-backend` on that port, which means the proxy
//! can clone the mirror from a real HTTP git server that we fully control.
//!
//! ## Push
//! git-cache classifies push requests (GET info/refs?service=git-receive-pack,
//! POST git-receive-pack) as `GitRequest::Push` and forwards them through the
//! normal Pingora proxy path to the origin.  We verify a push through the proxy
//! lands on the origin by: push via proxy → directly clone the bare origin →
//! confirm the new commit is present.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use pingora::prelude::*;
use trust::config::{GitConfig, Injection, InjectionScheme, Origin, Upstream, UpstreamKind};
use trust::git::mirror::MirrorStore;
use trust::git::sync::SyncManager;
use trust::jwt::{Issuer, Verifier};
use trust::keystore::{Keystore, build_key_material};
use trust::proxy::ProxyService;
use trust::resource::ResourceKind;
use trust::router::Router;
use trust::scope::ScopeSet;
use trust::secrets::SecretProvider;
use trust::secrets::fake::FakeSecretProvider;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_pem()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Run a `git` command, panic on failure, return stdout.
fn git(args: &[&str], cwd: &Path, envs: &[(&str, &str)]) -> String {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CREDENTIAL_HELPER", "")
        .env("HOME", "/tmp"); // avoid picking up user git config
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    if !out.status.success() {
        panic!(
            "git {args:?} failed (exit {:?}):\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Same as `git()` but returns the exit code rather than panicking.
fn git_status(args: &[&str], cwd: &Path, envs: &[(&str, &str)]) -> i32 {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CREDENTIAL_HELPER", "")
        .env("HOME", "/tmp");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    out.status.code().unwrap_or(1)
}

/// Like `git_status()` but also returns stderr as a String for assertion.
fn git_status_with_stderr(args: &[&str], cwd: &Path, envs: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CREDENTIAL_HELPER", "")
        .env("HOME", "/tmp");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    let code = out.status.code().unwrap_or(1);
    let mut output = String::from_utf8_lossy(&out.stderr).into_owned();
    output.push_str("\n--- STDOUT ---\n");
    output.push_str(&String::from_utf8_lossy(&out.stdout));
    (code, output)
}

// ---------------------------------------------------------------------------
// Local git-http-backend HTTP server
// ---------------------------------------------------------------------------

/// Serve a bare git repo over HTTP (smart-HTTP via `git http-backend`).
///
/// Each inbound TCP connection is handled synchronously in a new thread.
/// `GIT_PROJECT_ROOT` is set to `storage_root` so that PATH_INFO of the form
/// `/<owner>/<repo>.git/<suffix>` resolves to the correct bare repo.
///
/// Returns the listening port.
fn start_git_http_server(storage_root: PathBuf) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let root = storage_root.clone();
            std::thread::spawn(move || handle_git_http_conn(stream, &root));
        }
    });
    port
}

/// Handle one HTTP connection: read the full request, delegate to
/// `git http-backend`, relay the CGI response as an HTTP response.
///
/// Supports both `Content-Length` and chunked `Transfer-Encoding` for the
/// request body, so it works for both smart-HTTP clone (read) and push (write).
fn handle_git_http_conn(mut stream: TcpStream, storage_root: &Path) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));

    let mut buf: Vec<u8> = Vec::new();
    let mut headers_done = false;
    let mut content_length: usize = 0;
    let mut chunked = false;
    let mut header_end = 0usize;

    // Read until we have the complete request (headers + body).
    loop {
        let mut tmp = [0u8; 8192];
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }

        if !headers_done {
            if let Some(pos) = find_header_end_bytes(&buf) {
                headers_done = true;
                header_end = pos;
                if let Ok(hdr) = std::str::from_utf8(&buf[..header_end]) {
                    for line in hdr.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("content-length:") {
                            if let Some(v) = line.splitn(2, ':').nth(1) {
                                content_length = v.trim().parse().unwrap_or(0);
                            }
                        }
                        if lower.contains("transfer-encoding") && lower.contains("chunked") {
                            chunked = true;
                        }
                    }
                }
            }
        }

        if headers_done {
            if chunked {
                if is_chunked_complete(&buf[header_end..]) {
                    break;
                }
            } else {
                if buf.len().saturating_sub(header_end) >= content_length {
                    break;
                }
            }
        }
    }

    // Parse only the header portion as UTF-8 (body may be binary).
    let safe_hdr_end = header_end.min(buf.len());
    let req_str = match std::str::from_utf8(&buf[..safe_hdr_end]) {
        Ok(s) => s,
        Err(_) => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        }
    };
    if req_str.is_empty() {
        return; // empty / keep-alive probe, ignore
    }

    // Parse request line.
    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let raw_path = parts.next().unwrap_or("/").to_string();
    let (path_only, query) = if let Some(q) = raw_path.find('?') {
        (&raw_path[..q], &raw_path[q + 1..])
    } else {
        (raw_path.as_str(), "")
    };

    // Extract relevant request headers.
    let mut content_type_val = String::new();
    let mut git_protocol_val = String::new();
    for line in req_str.lines().skip(1) {
        let lower = line.to_lowercase();
        if lower.starts_with("content-type:") {
            content_type_val = line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
        if lower.starts_with("git-protocol:") {
            git_protocol_val = line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        }
    }

    // Build CGI environment.
    let mut env: Vec<(String, String)> = vec![
        ("GIT_PROJECT_ROOT".to_owned(), storage_root.to_string_lossy().into_owned()),
        ("GIT_HTTP_EXPORT_ALL".to_owned(), "1".to_owned()),
        ("PATH_INFO".to_owned(), path_only.to_owned()),
        ("QUERY_STRING".to_owned(), query.to_owned()),
        ("REQUEST_METHOD".to_owned(), method.clone()),
    ];
    if !content_type_val.is_empty() {
        env.push(("CONTENT_TYPE".to_owned(), content_type_val));
    }
    if !git_protocol_val.is_empty() {
        env.push(("GIT_PROTOCOL".to_owned(), git_protocol_val));
    }

    // Decode the request body.
    let body: Vec<u8> = if headers_done && header_end < buf.len() {
        let raw = &buf[header_end..];
        if chunked {
            decode_chunked(raw)
        } else {
            raw[..content_length.min(raw.len())].to_vec()
        }
    } else {
        vec![]
    };
    if !body.is_empty() {
        env.push(("CONTENT_LENGTH".to_owned(), body.len().to_string()));
    }

    // Spawn git http-backend.
    let mut child = std::process::Command::new("git")
        .arg("http-backend")
        .env_clear()
        .envs(env)
        .current_dir(storage_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("git http-backend spawn failed");

    // Feed body to stdin, then close it.
    if !body.is_empty() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&body);
        }
    } else {
        drop(child.stdin.take());
    }

    // Read CGI response.
    let mut cgi_out = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_end(&mut cgi_out);
    }
    let _ = child.wait();

    // Convert CGI response to HTTP.
    let Some(cgi_body_offset) = find_header_end_bytes(&cgi_out) else {
        let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n");
        return;
    };
    let cgi_header_str = std::str::from_utf8(&cgi_out[..cgi_body_offset]).unwrap_or("");
    let cgi_body = &cgi_out[cgi_body_offset..];

    let mut http_status = 200u16;
    let mut response_headers: Vec<String> = Vec::new();
    for line in cgi_header_str.lines() {
        if line.is_empty() {
            break;
        }
        if line.to_lowercase().starts_with("status:") {
            if let Some(val) = line.splitn(2, ':').nth(1) {
                if let Some(code_str) = val.trim().split_whitespace().next() {
                    http_status = code_str.parse().unwrap_or(200);
                }
            }
        } else {
            response_headers.push(line.to_string());
        }
    }

    let status_text = match http_status {
        200 => "OK",
        201 => "Created",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut resp = format!("HTTP/1.1 {http_status} {status_text}\r\n");
    for h in &response_headers {
        resp.push_str(h);
        resp.push_str("\r\n");
    }
    resp.push_str(&format!("Content-Length: {}\r\n", cgi_body.len()));
    resp.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(cgi_body);
}

// ---------------------------------------------------------------------------
// HTTP framing helpers
// ---------------------------------------------------------------------------

/// Return the byte offset immediately after the HTTP/CGI header separator
/// (`\r\n\r\n` or `\n\n`).
fn find_header_end_bytes(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
    }
    None
}

/// Returns `true` if the chunked body (without HTTP headers) ends with the
/// final-chunk marker `0\r\n\r\n`.
fn is_chunked_complete(body: &[u8]) -> bool {
    body.len() >= 5 && body.ends_with(b"0\r\n\r\n")
}

/// Decode a `Transfer-Encoding: chunked` body into raw bytes.
fn decode_chunked(chunked: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < chunked.len() {
        let rel = chunked[pos..].iter().position(|&b| b == b'\n');
        let Some(rel) = rel else { break };
        let line = &chunked[pos..pos + rel];
        let line_str = std::str::from_utf8(line).unwrap_or("0").trim_end_matches('\r');
        let size_str = line_str.split(';').next().unwrap_or("0").trim();
        let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);
        pos += rel + 1;
        if chunk_size == 0 {
            break;
        }
        if pos + chunk_size > chunked.len() {
            result.extend_from_slice(&chunked[pos..]);
            break;
        }
        result.extend_from_slice(&chunked[pos..pos + chunk_size]);
        pos += chunk_size;
        if pos < chunked.len() && chunked[pos] == b'\r' {
            pos += 1;
        }
        if pos < chunked.len() && chunked[pos] == b'\n' {
            pos += 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Proxy setup
// ---------------------------------------------------------------------------

/// Build the git-cache upstream configuration.
///
/// `listen_host = "127.0.0.1"` matches what git sends as the `Host` header
/// when cloning from `http://127.0.0.1:{proxy_port}/…`.  The router strips
/// the port, so `127.0.0.1` matches.
///
/// `name = "github"` must match the upstream field in JWT scopes, e.g.
/// `"github:testorg/testrepo"`.
fn build_proxy_upstream(origin_port: u16, storage_path: &Path) -> Arc<Upstream> {
    Arc::new(Upstream {
        name: "github".into(),
        kind: UpstreamKind::GitCache,
        listen_host: "127.0.0.1".into(),
        origin: Origin {
            host: "127.0.0.1".into(),
            port: origin_port,
            tls: false,
            sni: String::new(),
        },
        secret_ref: "ref/git".into(),
        injection: Injection {
            header: "authorization".into(),
            scheme: InjectionScheme::Bearer,
        },
        resource: Some(ResourceKind::GitRepo),
        git: Some(GitConfig {
            storage_path: storage_path.to_string_lossy().into_owned(),
        }),
    })
}

fn start_proxy(upstream: Arc<Upstream>, keystore: Arc<Keystore>, mirrors_dir: PathBuf) -> u16 {
    let proxy_port = free_port();
    let addr = format!("127.0.0.1:{proxy_port}");
    let router = Router::new(&[upstream]);
    let verifier = Verifier::new("trust".into(), "trust-proxy".into());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(FakeSecretProvider::new(&[("ref/git", "fake-git-token")]));
    let mirrors = Arc::new(MirrorStore::new(mirrors_dir));
    let sync = Arc::new(SyncManager::new());
    let service = ProxyService::new(router, verifier, keystore, secrets, mirrors, sync);

    std::thread::spawn(move || {
        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut proxy = http_proxy_service(&server.configuration, service);
        proxy.add_tcp(&addr);
        server.add_service(proxy);
        server.run_forever();
    });

    // Wait for the proxy to accept connections.
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", proxy_port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    proxy_port
}

// ---------------------------------------------------------------------------
// JWT minting
// ---------------------------------------------------------------------------

fn mint_jwt(keystore: &Keystore, scope: &str) -> String {
    let km = keystore.load().unwrap();
    let issuer = Issuer::new("trust".into(), "trust-proxy".into(), Duration::from_secs(3600));
    let now = jsonwebtoken::get_current_timestamp();
    let scopes = ScopeSet::parse(scope).unwrap();
    issuer.mint(&km, "spiffe://pit/ci/test", &scopes, now).unwrap()
}

// ---------------------------------------------------------------------------
// Main test
// ---------------------------------------------------------------------------

#[test]
fn git_cache_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path();

    // ---- 1. Create bare origin repo ----
    //
    // Layout: tmp/testorg/testrepo.git  (bare)
    // GIT_PROJECT_ROOT = tmp → PATH_INFO /testorg/testrepo.git/… resolves.
    let origin_dir = tmp_path.join("testorg").join("testrepo.git");
    std::fs::create_dir_all(&origin_dir).unwrap();
    git(&["init", "--bare", "."], &origin_dir, &[]);
    // Set default branch to 'main' so HEAD is not "unborn" after push.
    git(&["symbolic-ref", "HEAD", "refs/heads/main"], &origin_dir, &[]);
    // Enable push (receive-pack) over HTTP — disabled by default in git http-backend.
    git(&["config", "http.receivepack", "true"], &origin_dir, &[]);

    // Clone into a working copy to add commits.
    let work_dir = tmp_path.join("work");
    git(
        &["clone", origin_dir.to_str().unwrap(), work_dir.to_str().unwrap()],
        tmp_path,
        &[],
    );
    git(&["config", "user.email", "test@test.com"], &work_dir, &[]);
    git(&["config", "user.name", "Test"], &work_dir, &[]);
    git(&["checkout", "-B", "main"], &work_dir, &[]);

    // ---- Seed: create a ~210 KiB binary file to force multi-chunk streaming ----
    //
    // The proxy reads the response body from git http-backend in 64 KiB chunks
    // (HEAD_CAP = CHUNK = 64 KiB in proxy.rs).  A 210 KiB pack body will span
    // ≥3 chunks, exercising the C1/I1 streaming path.
    let large_data: Vec<u8> = (0u32..)
        .flat_map(|i| i.to_le_bytes())
        .take(210 * 1024)
        .collect();
    std::fs::write(work_dir.join("large_file.bin"), &large_data).unwrap();
    git(&["add", "."], &work_dir, &[]);
    git(&["commit", "-m", "initial: add large file"], &work_dir, &[]);
    git(&["push", "origin", "main"], &work_dir, &[]);

    println!("Origin seeded with {} KiB file", large_data.len() / 1024);

    // ---- 2. Start git HTTP origin server ----
    let origin_port = start_git_http_server(tmp_path.to_path_buf());
    println!("Origin HTTP server on port {origin_port}");

    // Sanity: verify git can clone directly from the origin over HTTP.
    {
        let sanity_dir = tmp_path.join("sanity_clone");
        let url = format!("http://127.0.0.1:{origin_port}/testorg/testrepo.git");
        git(&["clone", &url, sanity_dir.to_str().unwrap()], tmp_path, &[]);
        let data = std::fs::read(sanity_dir.join("large_file.bin")).unwrap();
        assert_eq!(data, large_data, "sanity clone: large_file.bin content mismatch");
        println!("Origin HTTP sanity check passed");
    }

    // ---- 3. Build keystore + proxy ----
    let keystore = Arc::new(Keystore::new());
    keystore.store(build_key_material(&signing_key_pem(), None).unwrap());

    let mirrors_dir = tmp_path.join("mirrors");
    std::fs::create_dir_all(&mirrors_dir).unwrap();

    let upstream = build_proxy_upstream(origin_port, &mirrors_dir);
    let proxy_port = start_proxy(upstream, keystore.clone(), mirrors_dir.clone());
    println!("Proxy on port {proxy_port}");

    // ---- 4. Mint JWTs ----
    // good_jwt: scoped to testorg/testrepo (authorized for that repo only)
    let good_jwt = mint_jwt(&keystore, "github:testorg/testrepo");
    let proxy_url = format!("http://127.0.0.1:{proxy_port}/testorg/testrepo.git");
    let other_url = format!("http://127.0.0.1:{proxy_port}/testorg/other.git");

    // ---- ASSERTION 4a: No JWT → 401 ----
    {
        let no_auth_dir = tmp_path.join("no_auth_clone");
        let (code, stderr) = git_status_with_stderr(
            &["-c", "credential.helper=", "clone", &proxy_url, no_auth_dir.to_str().unwrap()],
            tmp_path,
            &[],
        );
        assert_ne!(code, 0, "clone without JWT should fail");
        assert!(
            stderr.contains("could not read Username"),
            "clone without JWT should trigger 401 auth challenge; actual stderr:\n{stderr}"
        );
        println!("401 check (no JWT): git exited {code} with auth challenge ✓");
    }

    // ---- ASSERTION 4b: Out-of-scope repo → 403 ----
    // Use good_jwt (scoped to testorg/testrepo) to clone testorg/other.git → 403.
    {
        let oos_dir = tmp_path.join("oos_clone");
        let auth_header = format!("Authorization: Bearer {good_jwt}");
        let (code, stderr) = git_status_with_stderr(
            &[
                "-c", "credential.helper=",
                "-c", &format!("http.extraHeader={auth_header}"),
                "clone", &other_url, oos_dir.to_str().unwrap(),
            ],
            tmp_path,
            &[],
        );
        assert_ne!(code, 0, "clone of out-of-scope repo should fail");
        assert!(
            stderr.contains("403"),
            "clone of out-of-scope repo should return 403; actual stderr:\n{stderr}"
        );
        println!("403 check (wrong scope): git exited {code} with 403 ✓");
    }

    // ---- ASSERTION 1: Clone through proxy succeeds + multi-chunk validation ----
    let clone_dir = tmp_path.join("proxy_clone");
    {
        let auth_header = format!("Authorization: Bearer {good_jwt}");
        git(
            &[
                "-c", &format!("http.extraHeader={auth_header}"),
                "clone", &proxy_url, clone_dir.to_str().unwrap(),
            ],
            tmp_path,
            &[],
        );

        let cloned_data = std::fs::read(clone_dir.join("large_file.bin")).unwrap();
        assert_eq!(
            cloned_data.len(),
            large_data.len(),
            "proxy clone: file size mismatch (multi-chunk streaming broken?)"
        );
        assert_eq!(
            cloned_data, large_data,
            "proxy clone: file content mismatch (multi-chunk streaming broken?)"
        );
        println!("Assertion 1 (clone + multi-chunk): ✓ ({} KiB)", cloned_data.len() / 1024);
    }

    git(&["config", "user.email", "test@test.com"], &clone_dir, &[]);
    git(&["config", "user.name", "Test"], &clone_dir, &[]);

    // ---- ASSERTION 2: Push new commit to origin, fetch through proxy sees it ----
    {
        // Push a second commit directly to origin (bypassing proxy).
        std::fs::write(work_dir.join("second_commit.txt"), b"second commit content").unwrap();
        git(&["add", "."], &work_dir, &[]);
        git(&["commit", "-m", "second commit"], &work_dir, &[]);
        git(&["push", "origin", "main"], &work_dir, &[]);

        // Fetch through proxy → the proxy syncs the mirror then serves fresh refs.
        let auth_header = format!("Authorization: Bearer {good_jwt}");
        git(
            &["-c", &format!("http.extraHeader={auth_header}"), "fetch", "origin"],
            &clone_dir,
            &[],
        );
        git(&["merge", "origin/main"], &clone_dir, &[]);

        let content = std::fs::read_to_string(clone_dir.join("second_commit.txt")).unwrap();
        assert_eq!(content, "second commit content");
        println!("Assertion 2 (fetch sees new commit): ✓");
    }

    // ---- ASSERTION 3: Push through proxy lands on origin ----
    {
        // Point the clone's origin remote at the proxy.
        git(&["remote", "set-url", "origin", &proxy_url], &clone_dir, &[]);

        // Commit a new file in the clone.
        std::fs::write(clone_dir.join("via_proxy.txt"), b"pushed through proxy").unwrap();
        git(&["add", "."], &clone_dir, &[]);
        git(&["commit", "-m", "push via proxy"], &clone_dir, &[]);

        // Push through the proxy.  The proxy's push passthrough forwards to the origin.
        let auth_header = format!("Authorization: Bearer {good_jwt}");
        git(
            &[
                "-c", &format!("http.extraHeader={auth_header}"),
                "push", "origin", "main",
            ],
            &clone_dir,
            &[],
        );

        // Verify the commit arrived on the bare origin by cloning it directly.
        let verify_dir = tmp_path.join("verify_push_clone");
        git(
            &["clone", origin_dir.to_str().unwrap(), verify_dir.to_str().unwrap()],
            tmp_path,
            &[],
        );
        let content = std::fs::read_to_string(verify_dir.join("via_proxy.txt")).unwrap();
        assert_eq!(content, "pushed through proxy");
        println!("Assertion 3 (push via proxy): ✓");
    }

    println!("All git-cache assertions passed.");
}
