use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Upstream, UpstreamKind};
use crate::decision::{authorize, extract_bearer};
use crate::git::backend;
use crate::git::classify::{GitRequest, classify};
use crate::git::mirror::MirrorStore;
use crate::git::sync::SyncManager;
use crate::inject::{inject, injection_value};
use crate::jwt::Verifier;
use crate::keystore::Keystore;
use crate::resource::{ResourceKind, extract};
use crate::router::Router;
use crate::secrets::{Secret, SecretProvider};

#[derive(Default)]
pub struct RequestCtx {
    pub upstream: Option<Arc<Upstream>>,
    pub secret: Option<Secret>,
    /// Set for git-cache push requests so `response_filter` can trigger a
    /// background mirror sync after the upstream push succeeds.
    /// Tuple: (upstream_name, owner, repo).
    pub push_repo: Option<(String, String, String)>,
}

pub struct ProxyService {
    pub router: Router,
    pub verifier: Verifier,
    pub keystore: Arc<Keystore>,
    pub secrets: Arc<dyn SecretProvider>,
    pub mirrors: Arc<MirrorStore>,
    pub sync: Arc<SyncManager>,
}

impl ProxyService {
    pub fn new(
        router: Router,
        verifier: Verifier,
        keystore: Arc<Keystore>,
        secrets: Arc<dyn SecretProvider>,
        mirrors: Arc<MirrorStore>,
        sync: Arc<SyncManager>,
    ) -> ProxyService {
        ProxyService {
            router,
            verifier,
            keystore,
            secrets,
            mirrors,
            sync,
        }
    }
}

// ---------------------------------------------------------------------------
// Git tail extraction
// ---------------------------------------------------------------------------

/// Extract the git path suffix after `/<owner>/<repo>[.git]/`.
///
/// E.g. `/pitorg/pit-ts.git/info/refs` → `info/refs`
///       `/pitorg/pit-ts/git-upload-pack` → `git-upload-pack`
fn git_tail<'a>(path: &'a str, owner: &str, repo: &str) -> Option<&'a str> {
    // Build the two prefix variants to strip: with and without `.git`.
    let prefix_with = format!("/{owner}/{repo}.git/");
    let prefix_without = format!("/{owner}/{repo}/");
    if let Some(t) = path.strip_prefix(prefix_with.as_str()) {
        return Some(t);
    }
    if let Some(t) = path.strip_prefix(prefix_without.as_str()) {
        return Some(t);
    }
    None
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let Some(host) = host else {
            session
                .respond_error_with_body(404, Bytes::from_static(b"unknown host"))
                .await?;
            return Ok(true);
        };
        let Some(upstream) = self.router.resolve(&host) else {
            session
                .respond_error_with_body(404, Bytes::from_static(b"unknown host"))
                .await?;
            return Ok(true);
        };

        // Verify the JWT.
        let auth = session
            .req_header()
            .headers
            .get("authorization")
            .map(|v| v.as_bytes().to_vec());
        let Some(token) = extract_bearer(auth.as_deref()) else {
            session
                .respond_error_with_body(401, Bytes::from_static(b"missing token"))
                .await?;
            return Ok(true);
        };
        let Some(km) = self.keystore.load() else {
            session
                .respond_error_with_body(503, Bytes::from_static(b"keys unavailable"))
                .await?;
            return Ok(true);
        };
        let scopes = match self.verifier.verify(&km, &token) {
            Ok(s) => s,
            Err(_) => {
                session
                    .respond_error_with_body(401, Bytes::from_static(b"invalid token"))
                    .await?;
                return Ok(true);
            }
        };

        // Authorize by scope (+ resource path).
        let path = session.req_header().uri.path().to_string();
        if !authorize(&scopes, &upstream, &path) {
            session
                .respond_error_with_body(403, Bytes::from_static(b"not allowed"))
                .await?;
            return Ok(true);
        }

        // --- git-cache branch ---
        if upstream.kind == UpstreamKind::GitCache {
            return self
                .handle_git_cache(session, ctx, upstream, &path)
                .await;
        }

        // --- api branch (unchanged) ---
        match self.secrets.get(&upstream.secret_ref).await {
            Ok(secret) => {
                ctx.secret = Some(secret);
                ctx.upstream = Some(upstream);
                Ok(false)
            }
            Err(e) => {
                log::error!("secret fetch failed for {}: {e}", upstream.name);
                session
                    .respond_error_with_body(
                        502,
                        Bytes::from_static(b"upstream secret unavailable"),
                    )
                    .await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let o = &upstream.origin;
        Ok(Box::new(HttpPeer::new(
            (o.host.as_str(), o.port),
            o.tls,
            o.sni.clone(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("authorization");
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        let secret = ctx
            .secret
            .as_ref()
            .ok_or_else(|| Error::new_str("secret missing in ctx"))?;
        inject(upstream_request, &upstream.injection, secret.expose())
            .map_err(|_| Error::new_str("secret injection failed"))?;
        upstream_request
            .insert_header("host", upstream.origin.host.as_str())
            .map_err(|_| Error::new_str("failed to set host header"))?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // If this was a git push passthrough and it succeeded, trigger a
        // background mirror sync so the local bare repo is updated.
        if let Some((ref name, ref owner, ref repo)) = ctx.push_repo {
            let status = upstream_response.status.as_u16();
            if (200..300).contains(&status) {
                // Clone the pieces we need for the background task.
                // ctx.upstream is set in handle_git_push, so it is always Some here.
                let upstream_arc = match ctx.upstream.clone() {
                    Some(u) => u,
                    None => {
                        log::warn!(
                            "post-push sync: upstream missing in ctx for {name}/{owner}/{repo}"
                        );
                        return Ok(());
                    }
                };
                let secrets = self.secrets.clone();
                let mirrors = self.mirrors.clone();
                let sync = self.sync.clone();
                let owner = owner.clone();
                let repo = repo.clone();

                // SECURITY: auth_header is never logged inside this task.
                tokio::spawn(async move {
                    let mirror_path = match mirrors.path_for(&upstream_arc.name, &owner, &repo) {
                        Some(p) => p,
                        None => {
                            log::warn!(
                                "post-push sync: no mirror path for {}/{}/{}",
                                upstream_arc.name, owner, repo
                            );
                            return;
                        }
                    };

                    // Re-resolve the git credential (secret).
                    let secret = match secrets.get(&upstream_arc.secret_ref).await {
                        Ok(s) => s,
                        Err(e) => {
                            log::warn!(
                                "post-push sync: secret fetch failed for {}: {e}",
                                upstream_arc.name
                            );
                            return;
                        }
                    };
                    // Build the auth header — SECURITY: never log this value.
                    let auth_header =
                        match injection_value(&upstream_arc.injection, secret.expose()) {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!(
                                    "post-push sync: injection failed for {}: {e}",
                                    upstream_arc.name
                                );
                                return;
                            }
                        };

                    let key =
                        format!("{}/{}/{}", upstream_arc.name, owner, repo);
                    if let Err(e) = sync.sync(&key, &mirror_path, &auth_header).await {
                        // SECURITY: `e` contains key/path only, never auth_header.
                        log::warn!("post-push sync failed for {key}: {e}");
                    }
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// git-cache handler
// ---------------------------------------------------------------------------

impl ProxyService {
    async fn handle_git_cache(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        upstream: Arc<Upstream>,
        path: &str,
    ) -> Result<bool> {
        let method = session.req_header().method.as_str().to_string();
        let query = session
            .req_header()
            .uri
            .query()
            .unwrap_or("")
            .to_string();

        match classify(&method, path, &query) {
            GitRequest::Read => {
                self.handle_git_read(session, ctx, upstream, path, &method, &query)
                    .await
            }
            GitRequest::Push => {
                self.handle_git_push(session, ctx, upstream, path)
                    .await
            }
            GitRequest::Other => {
                session
                    .respond_error_with_body(400, Bytes::from_static(b"unsupported git request"))
                    .await?;
                Ok(true)
            }
        }
    }

    /// Serve a git READ request (clone/fetch) from the local bare mirror.
    ///
    /// SECURITY: The client JWT is never forwarded upstream.  Only the injected
    /// `auth_header` (git credential) is passed to `git` via `ensure`/`sync`.
    async fn handle_git_read(
        &self,
        session: &mut Session,
        _ctx: &mut RequestCtx,
        upstream: Arc<Upstream>,
        path: &str,
        method: &str,
        query: &str,
    ) -> Result<bool> {
        // --- Resolve owner/repo ---
        let resource = extract(ResourceKind::GitRepo, path);
        let Some(res) = resource else {
            session
                .respond_error_with_body(404, Bytes::from_static(b"repo not found"))
                .await?;
            return Ok(true);
        };
        let owner = res.owner;
        let repo = res.repo;

        // --- Fetch the git credential (secret).  The JWT is NOT used here. ---
        let secret = match self.secrets.get(&upstream.secret_ref).await {
            Ok(s) => s,
            Err(e) => {
                log::error!("git-cache secret fetch failed for {}: {e}", upstream.name);
                session
                    .respond_error_with_body(502, Bytes::from_static(b"upstream secret unavailable"))
                    .await?;
                return Ok(true);
            }
        };
        // SECURITY: auth_header is the injected git credential — never logged.
        let auth_header = match injection_value(&upstream.injection, secret.expose()) {
            Ok(v) => v,
            Err(e) => {
                log::error!("git-cache injection failed for {}: {e}", upstream.name);
                session
                    .respond_error_with_body(500, Bytes::from_static(b"injection error"))
                    .await?;
                return Ok(true);
            }
        };

        // --- Resolve the mirror path ---
        let mirror_path = match self.mirrors.path_for(&upstream.name, &owner, &repo) {
            Some(p) => p,
            None => {
                log::error!(
                    "git-cache: invalid mirror path components for {}/{}/{}",
                    upstream.name, owner, repo
                );
                session
                    .respond_error_with_body(500, Bytes::from_static(b"internal error"))
                    .await?;
                return Ok(true);
            }
        };

        // --- Build the upstream clone URL ---
        let clone_url = {
            let o = &upstream.origin;
            let scheme = if o.tls { "https" } else { "http" };
            if (o.tls && o.port == 443) || (!o.tls && o.port == 80) {
                format!("{scheme}://{}/{owner}/{repo}.git", o.host)
            } else {
                format!("{scheme}://{}:{}/{owner}/{repo}.git", o.host, o.port)
            }
        };

        // --- Ensure the bare mirror exists (clone if absent) ---
        if let Err(e) = self.mirrors.ensure(&mirror_path, &clone_url, &auth_header).await {
            log::error!(
                "git-cache ensure failed for {}/{}/{}: {e}",
                upstream.name, owner, repo
            );
            session
                .respond_error_with_body(502, Bytes::from_static(b"mirror unavailable"))
                .await?;
            return Ok(true);
        }

        // --- Sync (incremental fetch) ---
        let sync_key = format!("{}/{}/{}", upstream.name, owner, repo);
        if let Err(e) = self.sync.sync(&sync_key, &mirror_path, &auth_header).await {
            log::error!("git-cache sync failed for {sync_key}: {e}");
            session
                .respond_error_with_body(502, Bytes::from_static(b"mirror sync failed"))
                .await?;
            return Ok(true);
        }

        // --- Build CGI environment ---
        let git_config = match upstream.git.as_ref() {
            Some(g) => g,
            None => {
                log::error!(
                    "git-cache upstream {} has no git config block",
                    upstream.name
                );
                session
                    .respond_error_with_body(500, Bytes::from_static(b"internal error"))
                    .await?;
                return Ok(true);
            }
        };
        let storage_path = std::path::Path::new(&git_config.storage_path);

        let tail = match git_tail(path, &owner, &repo) {
            Some(t) => t.to_string(),
            None => {
                session
                    .respond_error_with_body(400, Bytes::from_static(b"bad git path"))
                    .await?;
                return Ok(true);
            }
        };

        let content_type = session
            .req_header()
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let git_protocol = session
            .req_header()
            .headers
            .get("git-protocol")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let env = backend::cgi_env(
            storage_path,
            &owner,
            &repo,
            &tail,
            query,
            method,
            content_type.as_deref(),
            git_protocol.as_deref(),
            None, // remote_user: principal not available (JWT verified but sub not extracted)
        );

        // --- Spawn git http-backend ---
        let mut child = match backend::spawn(storage_path, &env).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("git-cache spawn failed: {e}");
                session
                    .respond_error_with_body(500, Bytes::from_static(b"backend spawn failed"))
                    .await?;
                return Ok(true);
            }
        };

        // --- Pump request body → child stdin ---
        if let Some(mut stdin) = child.stdin.take() {
            // Read whatever body the client sent (may be None for GET requests).
            let body_opt = session.read_request_body().await;
            match body_opt {
                Ok(Some(body)) => {
                    if let Err(e) = stdin.write_all(&body).await {
                        log::error!("git-cache: write to child stdin failed: {e}");
                        let _ = child.kill().await;
                        session
                            .respond_error_with_body(500, Bytes::from_static(b"backend io error"))
                            .await?;
                        return Ok(true);
                    }
                }
                Ok(None) => {
                    // No body — drop stdin to signal EOF.
                }
                Err(e) => {
                    log::error!("git-cache: read request body failed: {e}");
                    let _ = child.kill().await;
                    session
                        .respond_error_with_body(500, Bytes::from_static(b"body read error"))
                        .await?;
                    return Ok(true);
                }
            }
            // stdin is dropped here → EOF sent to child.
        }

        // --- Read all child stdout ---
        let stdout_bytes = if let Some(mut stdout) = child.stdout.take() {
            let mut buf = Vec::new();
            match stdout.read_to_end(&mut buf).await {
                Ok(_) => Bytes::from(buf),
                Err(e) => {
                    log::error!("git-cache: read from child stdout failed: {e}");
                    let _ = child.kill().await;
                    session
                        .respond_error_with_body(500, Bytes::from_static(b"backend read error"))
                        .await?;
                    return Ok(true);
                }
            }
        } else {
            Bytes::new()
        };

        // Wait for the child to exit.
        match child.wait().await {
            Ok(status) if !status.success() => {
                log::warn!("git http-backend exited with status: {status}");
                // Still serve whatever the CGI produced — git may have written
                // a useful error response before exiting non-zero.
            }
            Err(e) => {
                log::warn!("git http-backend wait error: {e}");
            }
            _ => {}
        }

        // --- Parse CGI response head ---
        let (cgi_status, cgi_headers, body_offset) =
            match backend::parse_cgi_head(&stdout_bytes) {
                Some(parsed) => parsed,
                None => {
                    log::error!("git-cache: could not parse CGI response head");
                    session
                        .respond_error_with_body(
                            500,
                            Bytes::from_static(b"invalid backend response"),
                        )
                        .await?;
                    return Ok(true);
                }
            };

        let body = stdout_bytes.slice(body_offset..);

        // --- Stream the response to the client ---
        // Confirmed Pingora streaming API (plan §Global Constraints):
        //   session.write_response_header(Box<ResponseHeader>, false)
        //   loop: session.write_response_body(Some(chunk), false)
        //   session.write_response_body(None, true)
        let mut resp = match pingora::http::ResponseHeader::build(cgi_status, Some(cgi_headers.len())) {
            Ok(r) => r,
            Err(e) => {
                log::error!("git-cache: build response header failed: {e}");
                session
                    .respond_error_with_body(500, Bytes::from_static(b"response build error"))
                    .await?;
                return Ok(true);
            }
        };
        for (k, v) in cgi_headers {
            if let Err(e) = resp.insert_header(k, v.as_str()) {
                log::warn!("git-cache: could not insert header: {e}");
            }
        }
        session
            .write_response_header(Box::new(resp), false)
            .await?;

        if !body.is_empty() {
            session.write_response_body(Some(body), false).await?;
        }
        session.write_response_body(None, true).await?;

        Ok(true)
    }

    /// Handle a git PUSH by letting the normal proxy path forward the request
    /// upstream (with JWT stripped and credential injected).  Record
    /// `ctx.push_repo` so `response_filter` can trigger a background sync.
    async fn handle_git_push(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        upstream: Arc<Upstream>,
        path: &str,
    ) -> Result<bool> {
        // Resolve owner/repo so we can record them for the post-push sync.
        let resource = extract(ResourceKind::GitRepo, path);
        let Some(res) = resource else {
            session
                .respond_error_with_body(404, Bytes::from_static(b"repo not found"))
                .await?;
            return Ok(true);
        };

        // Fetch the secret so the normal proxy path (upstream_request_filter)
        // can inject it.
        let secret = match self.secrets.get(&upstream.secret_ref).await {
            Ok(s) => s,
            Err(e) => {
                log::error!(
                    "git-cache push: secret fetch failed for {}: {e}",
                    upstream.name
                );
                session
                    .respond_error_with_body(502, Bytes::from_static(b"upstream secret unavailable"))
                    .await?;
                return Ok(true);
            }
        };

        // Record push info for the background post-push sync in response_filter.
        ctx.push_repo = Some((upstream.name.clone(), res.owner, res.repo));
        ctx.secret = Some(secret);
        ctx.upstream = Some(upstream);

        // Return false → normal proxy path continues (upstream_peer +
        // upstream_request_filter strips JWT + injects credential).
        Ok(false)
    }
}
