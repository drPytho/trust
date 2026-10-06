use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{GithubBotIdentity, Upstream, UpstreamKind, UpstreamMode};
use crate::credentials::{CredentialManager, CredentialProvider};
use crate::decision::{authorize, extract_bearer, extract_client_token};
use crate::git::backend;
use crate::git::classify::{GitRequest, classify};
use crate::git::mirror::MirrorStore;
use crate::git::sync::SyncManager;
use crate::github_cli::{
    GithubCliGraphqlOperation, MAX_GRAPHQL_BODY_BYTES, MAX_REST_BODY_BYTES, classify_graphql,
    classify_rest_request, graphql_operation_label, is_graphql_path, rest_search_repository,
    rest_upstream_path, rewrite_link_header, validate_rest_body,
};
use crate::inject::{inject, injection_value};
use crate::jwt::Verifier;
use crate::keystore::Keystore;
use crate::metrics::ProxyMetrics;
use crate::resource::{ResourceKind, extract};
use crate::router::Router;
use crate::scope::ScopeSet;
use crate::secrets::{Secret, SecretProvider};

pub struct RequestCtx {
    pub upstream: Option<Arc<Upstream>>,
    pub secret: Option<Secret>,
    pub credential_cache_key: Option<String>,
    npm_rewrite: Option<NpmRewrite>,
    /// GitHub CLI REST requests rewrite pagination links back to Trust.
    link_rewrite: Option<LinkRewrite>,
    /// GraphQL `name/rootField` label, included in rejection logs.
    github_operation: Option<String>,
    /// Set for git-cache push requests so `response_filter` can trigger a
    /// background mirror sync after the upstream push succeeds.
    /// Tuple: (upstream_name, owner, repo).
    pub push_repo: Option<(String, String, String)>,
    started_at: Instant,
    metrics: Arc<ProxyMetrics>,
    metrics_finished: bool,
}

impl RequestCtx {
    fn new(metrics: Arc<ProxyMetrics>) -> RequestCtx {
        metrics.request_started();
        RequestCtx {
            upstream: None,
            secret: None,
            credential_cache_key: None,
            npm_rewrite: None,
            link_rewrite: None,
            github_operation: None,
            push_repo: None,
            started_at: Instant::now(),
            metrics,
            metrics_finished: false,
        }
    }

    fn finish_metrics(&mut self, upstream: &str, status: u16) {
        if self.metrics_finished {
            return;
        }
        self.metrics
            .request_finished(upstream, status, self.started_at.elapsed().as_secs_f64());
        self.metrics_finished = true;
    }
}

const MAX_NPM_METADATA_BYTES: usize = 64 * 1024 * 1024;
const GITHUB_CLI_META_RESPONSE: &[u8] = br#"{"installed_version":"3.17.0"}"#;
const GITHUB_CLI_ISSUE_FEATURE_RESPONSE: &[u8] = br#"{"data":{"Issue":{"fields":[]}}}"#;
// Advertising `isInMergeQueue` makes `gh pr merge` take its merge-queue path
// (enablePullRequestAutoMerge) instead of a direct merge on queued branches.
const GITHUB_CLI_PULL_REQUEST_FEATURE_RESPONSE: &[u8] = br#"{"data":{"PullRequest":{"fields":[{"name":"isInMergeQueue"}]},"StatusCheckRollupContextConnection":{"fields":[]}}}"#;
const GITHUB_CLI_WORKFLOW_RUN_FEATURE_RESPONSE: &[u8] =
    br#"{"data":{"WorkflowRun":{"fields":[]}}}"#;

struct LinkRewrite {
    /// Upstream origin as it appears in GitHub's links.
    origin: String,
    /// Scheme and Host the client used to reach Trust.
    base: String,
    client_path: String,
    upstream_path: String,
}

fn origin_base(origin: &crate::config::Origin) -> String {
    let scheme = if origin.tls { "https" } else { "http" };
    if (origin.tls && origin.port == 443) || (!origin.tls && origin.port == 80) {
        format!("{scheme}://{}", origin.host)
    } else {
        format!("{scheme}://{}:{}", origin.host, origin.port)
    }
}

struct NpmRewrite {
    from: String,
    to: String,
    buffer_body: bool,
    buffer: Vec<u8>,
}

/// Outcome of GitHub CLI compatibility routing.
enum GithubCliRoute {
    /// A response was already written; propagate as request_filter's return.
    Responded(bool),
    /// Continue: authorize against `policy_path`, optionally rewrite the
    /// upstream request path.
    Forward {
        policy_path: String,
        upstream_path: Option<String>,
    },
}

fn rewrite_registry_json(body: &[u8], from: &str, to: &str) -> Result<Vec<u8>, serde_json::Error> {
    fn rewrite(value: &mut serde_json::Value, from: &str, to: &str) {
        match value {
            serde_json::Value::String(value) if value.starts_with(from) => {
                *value = format!("{to}{}", &value[from.len()..]);
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    rewrite(value, from, to);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values_mut() {
                    rewrite(value, from, to);
                }
            }
            _ => {}
        }
    }

    let mut value: serde_json::Value = serde_json::from_slice(body)?;
    rewrite(&mut value, from, to);
    serde_json::to_vec(&value)
}

impl Drop for RequestCtx {
    fn drop(&mut self) {
        if !self.metrics_finished {
            self.metrics.request_abandoned();
        }
    }
}

pub struct ProxyService {
    pub router: Router,
    pub verifier: Verifier,
    pub keystore: Arc<Keystore>,
    pub credentials: Arc<dyn CredentialProvider>,
    pub mirrors: Arc<MirrorStore>,
    pub sync: Arc<SyncManager>,
    pub metrics: Arc<ProxyMetrics>,
    pub github_bot: Option<GithubBotIdentity>,
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
        Self::with_metrics(
            router,
            verifier,
            keystore,
            secrets,
            mirrors,
            sync,
            Arc::new(ProxyMetrics::new()),
        )
    }

    pub fn with_metrics(
        router: Router,
        verifier: Verifier,
        keystore: Arc<Keystore>,
        secrets: Arc<dyn SecretProvider>,
        mirrors: Arc<MirrorStore>,
        sync: Arc<SyncManager>,
        metrics: Arc<ProxyMetrics>,
    ) -> ProxyService {
        Self::with_credentials_and_metrics(
            router,
            verifier,
            keystore,
            Arc::new(CredentialManager::new(secrets, None)),
            mirrors,
            sync,
            metrics,
        )
    }

    pub fn with_credentials_and_metrics(
        router: Router,
        verifier: Verifier,
        keystore: Arc<Keystore>,
        credentials: Arc<dyn CredentialProvider>,
        mirrors: Arc<MirrorStore>,
        sync: Arc<SyncManager>,
        metrics: Arc<ProxyMetrics>,
    ) -> ProxyService {
        ProxyService {
            router,
            verifier,
            keystore,
            credentials,
            mirrors,
            sync,
            metrics,
            github_bot: None,
        }
    }

    /// Answer `GET /user` and `viewer { login }` on GitHub CLI upstreams.
    pub fn with_github_bot(mut self, bot: Option<GithubBotIdentity>) -> ProxyService {
        self.github_bot = bot;
        self
    }

    async fn reject(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        status: u16,
        reason: &'static str,
        body: &'static [u8],
    ) -> Result<bool> {
        let upstream = ctx
            .upstream
            .as_ref()
            .map(|upstream| upstream.name.as_str())
            .unwrap_or("unrouted");
        self.metrics.rejection(upstream, reason, status);

        let request = session.req_header();
        let method = request.method.as_str();
        let host = request.headers.get("host").and_then(|v| v.to_str().ok());
        let path = request.uri.path();
        let client = session.client_addr();
        let operation = ctx.github_operation.as_deref();
        log::warn!(
            "proxy request rejected status={status} reason={reason} upstream={upstream} \
             client={client:?} method={method:?} host={host:?} path={path:?} \
             graphql_operation={operation:?}"
        );

        session
            .respond_error_with_body(status, Bytes::from_static(body))
            .await?;
        Ok(true)
    }

    /// Reply to the two static GitHub Enterprise capability probes emitted by
    /// `gh` for a custom `GH_HOST`. The caller has already presented exactly
    /// one repository scope; these bodies contain no upstream data and merely
    /// disable optional GHES-only metadata paths before basic PR creation.
    async fn respond_github_cli_feature(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        upstream: Arc<Upstream>,
        body: impl Into<Bytes>,
    ) -> Result<bool> {
        let body = body.into();
        let mut response = pingora::http::ResponseHeader::build(200, Some(2))
            .map_err(|_| Error::new_str("failed to build GitHub CLI feature response"))?;
        response
            .insert_header("content-type", "application/json")
            .map_err(|_| Error::new_str("failed to set GitHub CLI feature content type"))?;
        response
            .insert_header("content-length", body.len().to_string())
            .map_err(|_| Error::new_str("failed to set GitHub CLI feature content length"))?;
        ctx.upstream = Some(upstream);
        session
            .write_response_header(Box::new(response), false)
            .await?;
        session.write_response_body(Some(body), true).await?;
        Ok(true)
    }

    /// Answer the App bot's own identity, which GitHub refuses to installation
    /// tokens. The response holds only static configuration, but still
    /// requires a grant for this upstream.
    async fn respond_github_bot_identity(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        upstream: &Arc<Upstream>,
        scopes: &ScopeSet,
        graphql: bool,
    ) -> Result<bool> {
        if !scopes.grants_upstream(&upstream.name) {
            return self
                .reject(session, ctx, 403, "forbidden_scope", b"not allowed")
                .await;
        }
        let Some(bot) = &self.github_bot else {
            return self
                .reject(
                    session,
                    ctx,
                    403,
                    "github_bot_identity_unconfigured",
                    b"GitHub bot identity is not configured",
                )
                .await;
        };
        let body = if graphql {
            serde_json::json!({"data": {"viewer": {"login": bot.login}}})
        } else {
            serde_json::json!({"login": bot.login, "id": bot.id, "type": "Bot"})
        };
        let body = serde_json::to_vec(&body)
            .map_err(|_| Error::new_str("failed to encode GitHub bot identity"))?;
        self.respond_github_cli_feature(session, ctx, upstream.clone(), body)
            .await
    }

    /// GitHub CLI treats a custom GH_HOST as an Enterprise host. In the
    /// explicit compatibility mode, translate its REST prefix and inspect
    /// bounded GraphQL request bodies before authorizing or minting a token.
    async fn route_github_cli(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        upstream: &Arc<Upstream>,
        scopes: &ScopeSet,
        method: &str,
        original_path: &str,
    ) -> Result<GithubCliRoute> {
        if original_path == "/api/v3/meta" {
            if method != "GET" || scopes.sole_exact_resource(&upstream.name).is_none() {
                return self
                    .reject(session, ctx, 403, "forbidden_scope", b"not allowed")
                    .await
                    .map(GithubCliRoute::Responded);
            }
            return self
                .respond_github_cli_feature(
                    session,
                    ctx,
                    upstream.clone(),
                    GITHUB_CLI_META_RESPONSE,
                )
                .await
                .map(GithubCliRoute::Responded);
        }
        if matches!(original_path, "/api/v3/user" | "/user") {
            if method != "GET" {
                return self
                    .reject(
                        session,
                        ctx,
                        405,
                        "unsupported_github_cli_rest_method",
                        b"unsupported GitHub CLI REST method",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }
            return self
                .respond_github_bot_identity(session, ctx, upstream, scopes, false)
                .await
                .map(GithubCliRoute::Responded);
        }
        if is_graphql_path(original_path) {
            if method != "POST" {
                return self
                    .reject(
                        session,
                        ctx,
                        405,
                        "unsupported_github_graphql",
                        b"unsupported GitHub GraphQL request",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }
            if session
                .req_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > MAX_GRAPHQL_BODY_BYTES)
            {
                return self
                    .reject(
                        session,
                        ctx,
                        413,
                        "github_graphql_body_too_large",
                        b"GitHub GraphQL request too large",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }
            let mut body = Vec::new();
            session.as_mut().enable_retry_buffering();
            loop {
                match session.read_request_body().await {
                    Ok(Some(chunk)) => {
                        if body.len() + chunk.len() > MAX_GRAPHQL_BODY_BYTES {
                            return self
                                .reject(
                                    session,
                                    ctx,
                                    413,
                                    "github_graphql_body_too_large",
                                    b"GitHub GraphQL request too large",
                                )
                                .await
                                .map(GithubCliRoute::Responded);
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        return self
                            .reject(
                                session,
                                ctx,
                                400,
                                "invalid_github_graphql",
                                b"invalid GitHub GraphQL request",
                            )
                            .await
                            .map(GithubCliRoute::Responded);
                    }
                }
            }
            ctx.github_operation = graphql_operation_label(&body);
            let resource = match classify_graphql(&body) {
                Ok(
                    GithubCliGraphqlOperation::RepositoryQuery(resource)
                    | GithubCliGraphqlOperation::Search(resource),
                ) => resource,
                Ok(GithubCliGraphqlOperation::Viewer) => {
                    return self
                        .respond_github_bot_identity(session, ctx, upstream, scopes, true)
                        .await
                        .map(GithubCliRoute::Responded);
                }
                Ok(
                    operation @ (GithubCliGraphqlOperation::IssueFeatureDetection
                    | GithubCliGraphqlOperation::PullRequestFeatureDetection
                    | GithubCliGraphqlOperation::WorkflowRunFeatureDetection),
                ) => {
                    if scopes.sole_exact_resource(&upstream.name).is_none() {
                        log::warn!(
                            "GitHub CLI feature detection rejected upstream={} reason=ambiguous_or_wildcard_scope",
                            upstream.name
                        );
                        return self
                            .reject(session, ctx, 403, "forbidden_scope", b"not allowed")
                            .await
                            .map(GithubCliRoute::Responded);
                    }
                    let response = match operation {
                        GithubCliGraphqlOperation::IssueFeatureDetection => {
                            GITHUB_CLI_ISSUE_FEATURE_RESPONSE
                        }
                        GithubCliGraphqlOperation::PullRequestFeatureDetection => {
                            GITHUB_CLI_PULL_REQUEST_FEATURE_RESPONSE
                        }
                        GithubCliGraphqlOperation::WorkflowRunFeatureDetection => {
                            GITHUB_CLI_WORKFLOW_RUN_FEATURE_RESPONSE
                        }
                        _ => unreachable!(),
                    };
                    return self
                        .respond_github_cli_feature(session, ctx, upstream.clone(), response)
                        .await
                        .map(GithubCliRoute::Responded);
                }
                Ok(
                    GithubCliGraphqlOperation::StatusChecks
                    | GithubCliGraphqlOperation::CreatePullRequest
                    | GithubCliGraphqlOperation::UpdatePullRequest
                    | GithubCliGraphqlOperation::MarkPullRequestReady
                    | GithubCliGraphqlOperation::CreateComment
                    | GithubCliGraphqlOperation::UpdateLabels
                    | GithubCliGraphqlOperation::ResolveReviewThread
                    | GithubCliGraphqlOperation::ConvertPullRequestToDraft
                    | GithubCliGraphqlOperation::EnableAutoMerge
                    | GithubCliGraphqlOperation::EnqueuePullRequest,
                ) => {
                    // These operations carry opaque node IDs rather than an
                    // owner/repository pair. Bind them to exactly one explicit
                    // JWT scope, then let authorization and credential
                    // resolution enforce that synthesized repository path.
                    let Some(resource) = scopes.sole_exact_resource(&upstream.name) else {
                        log::warn!(
                            "GitHub CLI repository-bound mutation rejected upstream={} reason=ambiguous_or_wildcard_scope",
                            upstream.name
                        );
                        return self
                            .reject(session, ctx, 403, "forbidden_scope", b"not allowed")
                            .await
                            .map(GithubCliRoute::Responded);
                    };
                    resource
                }
                Err(error) => {
                    log::warn!(
                        "GitHub CLI GraphQL request rejected upstream={} operation={:?} reason={error}",
                        upstream.name,
                        ctx.github_operation
                    );
                    return self
                        .reject(
                            session,
                            ctx,
                            403,
                            "unsupported_github_graphql",
                            b"unsupported GitHub GraphQL request",
                        )
                        .await
                        .map(GithubCliRoute::Responded);
                }
            };
            return Ok(GithubCliRoute::Forward {
                policy_path: format!("/repos/{}/{}", resource.owner, resource.repo),
                upstream_path: Some("/graphql".to_string()),
            });
        }
        // Do not turn the repository-scoped GitHub App token into a general
        // REST write capability through `gh api -X ...`.
        let rest_operation = match classify_rest_request(method, original_path) {
            Ok(operation) => operation,
            Err(error) => {
                log::warn!(
                    "GitHub CLI REST request rejected upstream={} reason={error}",
                    upstream.name
                );
                return self
                    .reject(
                        session,
                        ctx,
                        405,
                        "unsupported_github_cli_rest_method",
                        b"unsupported GitHub CLI REST method",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }
        };
        if rest_operation.requires_body() {
            if session
                .req_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > MAX_REST_BODY_BYTES)
            {
                return self
                    .reject(
                        session,
                        ctx,
                        413,
                        "github_cli_rest_body_too_large",
                        b"GitHub CLI REST request too large",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }

            let mut body = Vec::new();
            session.as_mut().enable_retry_buffering();
            loop {
                match session.read_request_body().await {
                    Ok(Some(chunk)) => {
                        if body.len() + chunk.len() > MAX_REST_BODY_BYTES {
                            return self
                                .reject(
                                    session,
                                    ctx,
                                    413,
                                    "github_cli_rest_body_too_large",
                                    b"GitHub CLI REST request too large",
                                )
                                .await
                                .map(GithubCliRoute::Responded);
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        return self
                            .reject(
                                session,
                                ctx,
                                400,
                                "invalid_github_cli_rest_body",
                                b"invalid GitHub CLI REST request",
                            )
                            .await
                            .map(GithubCliRoute::Responded);
                    }
                }
            }
            if let Err(error) = validate_rest_body(rest_operation, &body) {
                log::warn!(
                    "GitHub CLI REST body rejected upstream={} reason={error}",
                    upstream.name
                );
                return self
                    .reject(
                        session,
                        ctx,
                        400,
                        "invalid_github_cli_rest_body",
                        b"invalid GitHub CLI REST request",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }
        }
        let upstream_path = rest_upstream_path(original_path).unwrap_or(original_path);
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or(&upstream.listen_host);
        let scheme = if session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some())
        {
            "https"
        } else {
            "http"
        };
        ctx.link_rewrite = Some(LinkRewrite {
            origin: origin_base(&upstream.origin),
            base: format!("{scheme}://{host}"),
            client_path: original_path.to_string(),
            upstream_path: upstream_path.to_string(),
        });

        // Issue search has no repository path. Bind it to the one repository
        // its query string is confined to.
        let search = rest_search_repository(original_path, session.req_header().uri.query());
        let policy_path = match search {
            Some(Ok(resource)) => format!("/repos/{}/{}", resource.owner, resource.repo),
            Some(Err(error)) => {
                log::warn!(
                    "GitHub CLI REST search rejected upstream={} reason={error}",
                    upstream.name
                );
                return self
                    .reject(
                        session,
                        ctx,
                        403,
                        "unsupported_github_search",
                        b"unsupported GitHub search",
                    )
                    .await
                    .map(GithubCliRoute::Responded);
            }
            None => upstream_path.to_string(),
        };
        Ok(GithubCliRoute::Forward {
            policy_path,
            upstream_path: (upstream_path != original_path).then(|| upstream_path.to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// Git tail extraction
// ---------------------------------------------------------------------------

/// Extract the git path suffix after `/<owner>/<repo>[.git]/`.
///
/// E.g. `/example-org/example-repo.git/info/refs` → `info/refs`
///       `/example-org/example-repo/git-upload-pack` → `git-upload-pack`
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

fn rewrite_request_path(session: &mut Session, path: &str) -> Result<()> {
    let path_and_query = match session.req_header().uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    session
        .req_header_mut()
        .set_raw_path(path_and_query.as_bytes())
        .map_err(|_| Error::new_str("failed to rewrite request path"))
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::new(self.metrics.clone())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let Some(host) = host else {
            return self
                .reject(session, ctx, 404, "missing_host", b"unknown host")
                .await;
        };
        let Some(upstream) = self.router.resolve(&host) else {
            return self
                .reject(session, ctx, 404, "unknown_host", b"unknown host")
                .await;
        };
        ctx.upstream = Some(upstream.clone());
        if let Some(crate::config::CredentialSource::GcpAdc {
            rewrite_registry_to: Some(to),
        }) = &upstream.credential
        {
            ctx.npm_rewrite = Some(NpmRewrite {
                from: origin_base(&upstream.origin),
                to: to.trim_end_matches('/').to_string(),
                buffer_body: false,
                buffer: Vec::new(),
            });
        }

        // Verify the JWT. Proxy-Authorization is accepted for every mode and
        // required for passthrough so the caller's Authorization header can be
        // forwarded unchanged. Inject mode retains Authorization compatibility.
        let github_cli = upstream.resource == Some(ResourceKind::GithubCliRepo);
        let headers = &session.req_header().headers;
        let proxy_auth = headers.get("proxy-authorization");
        let token = if let Some(proxy_auth) = proxy_auth {
            extract_bearer(Some(proxy_auth.as_bytes()))
        } else if upstream.mode == UpstreamMode::Inject {
            extract_client_token(
                headers.get("authorization").map(|value| value.as_bytes()),
                github_cli,
            )
        } else {
            None
        };
        let Some(token) = token else {
            return self
                .reject(session, ctx, 401, "missing_token", b"missing token")
                .await;
        };
        let Some(km) = self.keystore.load() else {
            return self
                .reject(
                    session,
                    ctx,
                    503,
                    "signing_keys_unavailable",
                    b"keys unavailable",
                )
                .await;
        };
        let scopes = match self.verifier.verify(&km, &token) {
            Ok(s) => s,
            Err(_) => {
                return self
                    .reject(session, ctx, 401, "invalid_token", b"invalid token")
                    .await;
            }
        };

        let original_path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();
        let mut policy_path = original_path.clone();
        let mut upstream_path: Option<String> = None;
        if github_cli {
            match self
                .route_github_cli(session, ctx, &upstream, &scopes, &method, &original_path)
                .await?
            {
                GithubCliRoute::Responded(done) => return Ok(done),
                GithubCliRoute::Forward {
                    policy_path: p,
                    upstream_path: u,
                } => {
                    policy_path = p;
                    upstream_path = u;
                }
            }
        }

        // Authorize by scope (+ the normalized or body-derived resource path).
        if !authorize(&scopes, &upstream, &method, &policy_path) {
            return self
                .reject(session, ctx, 403, "forbidden_scope", b"not allowed")
                .await;
        }

        if let Some(path) = upstream_path {
            rewrite_request_path(session, &path)?;
        }

        // --- git-cache branch ---
        if upstream.kind == UpstreamKind::GitCache {
            return self
                .handle_git_cache(session, ctx, upstream, &policy_path)
                .await;
        }

        if upstream.mode == UpstreamMode::Passthrough {
            ctx.upstream = Some(upstream);
            return Ok(false);
        }

        // --- credential-injecting API branch ---
        // authorize() already proved selector presence and map membership for
        // linear-pat; the credential provider checks both again defensively.
        let credential_selector = match &upstream.credential {
            Some(crate::config::CredentialSource::LinearPat { .. }) => {
                scopes.sole_selector(&upstream.name)
            }
            _ => None,
        };
        let credential_started = Instant::now();
        let provider = upstream
            .credential
            .as_ref()
            .ok_or_else(|| Error::new_str("inject upstream missing credential"))?
            .provider_name();
        match self
            .credentials
            .resolve(&upstream, &method, &policy_path, credential_selector)
            .await
        {
            Ok(credential) => {
                self.metrics.credential_resolution(
                    &upstream.name,
                    provider,
                    credential.result.as_str(),
                    credential_started.elapsed().as_secs_f64(),
                );
                ctx.secret = Some(credential.secret);
                ctx.credential_cache_key = credential.cache_key;
                ctx.upstream = Some(upstream);
                Ok(false)
            }
            Err(e) => {
                self.metrics.credential_resolution(
                    &upstream.name,
                    provider,
                    "error",
                    credential_started.elapsed().as_secs_f64(),
                );
                log::error!("credential resolution failed for {}: {e}", upstream.name);
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
        // Proxy credentials are hop-local and must never reach any upstream.
        upstream_request.remove_header("proxy-authorization");
        let upstream = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::new_str("upstream missing in ctx"))?;
        if upstream.mode == UpstreamMode::Inject {
            upstream_request.remove_header("authorization");
            let secret = ctx
                .secret
                .as_ref()
                .ok_or_else(|| Error::new_str("secret missing in ctx"))?;
            let injection = upstream
                .injection
                .as_ref()
                .ok_or_else(|| Error::new_str("inject upstream missing injection"))?;
            inject(upstream_request, injection, secret.expose())
                .map_err(|_| Error::new_str("secret injection failed"))?;
        }
        if matches!(
            upstream.credential,
            Some(crate::config::CredentialSource::GcpAdc { .. })
        ) {
            // Metadata must be uncompressed so absolute tarball URLs can be
            // rewritten without exposing a direct Artifact Registry bypass.
            upstream_request.remove_header("accept-encoding");
        }
        upstream_request
            .insert_header("host", upstream.origin.host.as_str())
            .map_err(|_| Error::new_str("failed to set host header"))?;
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        if status == 401
            && let Some(cache_key) = ctx.credential_cache_key.as_deref()
        {
            self.credentials.invalidate(cache_key).await;
        }

        if let Some(rewrite) = ctx.link_rewrite.as_ref()
            && let Some(link) = upstream_response
                .headers
                .get("link")
                .and_then(|value| value.to_str().ok())
        {
            let link = rewrite_link_header(
                link,
                &rewrite.origin,
                &rewrite.base,
                &rewrite.client_path,
                &rewrite.upstream_path,
            );
            upstream_response
                .insert_header("link", link)
                .map_err(|_| Error::new_str("failed to rewrite GitHub pagination link"))?;
        }

        if let Some(rewrite) = ctx.npm_rewrite.as_mut() {
            if let Some(location) = upstream_response
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
            {
                if location.starts_with(&rewrite.from) {
                    let location = format!("{}{}", rewrite.to, &location[rewrite.from.len()..]);
                    upstream_response
                        .insert_header("location", location)
                        .map_err(|_| Error::new_str("failed to rewrite registry redirect"))?;
                } else if location.starts_with("http://") || location.starts_with("https://") {
                    // Never hand a credential-bearing signed redirect URL to an
                    // untrusted npm client. Same-origin redirects are rewritten;
                    // other absolute redirects fail closed.
                    return Err(Error::new_str("external registry redirect refused"));
                }
            }

            let is_json = upstream_response
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().contains("json"));
            if is_json
                && (200..300).contains(&status)
                && status != 204
                && session.req_header().method.as_str() != "HEAD"
            {
                if upstream_response.headers.contains_key("content-encoding") {
                    return Err(Error::new_str(
                        "compressed registry metadata cannot be rewritten",
                    ));
                }
                rewrite.buffer_body = true;
                upstream_response.remove_header("content-length");
            }
        }

        // If this was a git push passthrough and it succeeded, trigger a
        // background mirror sync so the local bare repo is updated.
        if let Some((ref name, ref owner, ref repo)) = ctx.push_repo
            && (200..300).contains(&status)
        {
            // Clone the pieces we need for the background task.
            // ctx.upstream is set in handle_git_push, so it is always Some here.
            let upstream_arc = match ctx.upstream.clone() {
                Some(u) => u,
                None => {
                    log::warn!("post-push sync: upstream missing in ctx for {name}/{owner}/{repo}");
                    return Ok(());
                }
            };
            let credentials = self.credentials.clone();
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
                            upstream_arc.name,
                            owner,
                            repo
                        );
                        return;
                    }
                };

                let path = format!("/{owner}/{repo}.git/info/refs");
                let credential = match credentials.resolve(&upstream_arc, "GET", &path, None).await
                {
                    Ok(credential) => credential,
                    Err(e) => {
                        log::warn!(
                            "post-push sync: credential resolution failed for {}: {e}",
                            upstream_arc.name
                        );
                        return;
                    }
                };
                // Build the auth header — SECURITY: never log this value.
                let Some(injection) = upstream_arc.injection.as_ref() else {
                    log::warn!(
                        "post-push sync: injection missing for {}",
                        upstream_arc.name
                    );
                    return;
                };
                let auth_header = match injection_value(injection, credential.secret.expose()) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!(
                            "post-push sync: injection failed for {}: {e}",
                            upstream_arc.name
                        );
                        return;
                    }
                };

                let key = format!("{}/{}/{}", upstream_arc.name, owner, repo);
                if let Err(e) = sync.sync(&key, &mirror_path, &auth_header).await {
                    // SECURITY: `e` contains key/path only, never auth_header.
                    log::warn!("post-push sync failed for {key}: {e}");
                }
            });
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        let Some(rewrite) = ctx.npm_rewrite.as_mut() else {
            return Ok(None);
        };
        if !rewrite.buffer_body {
            return Ok(None);
        }
        if let Some(chunk) = body.as_mut() {
            if rewrite.buffer.len() + chunk.len() > MAX_NPM_METADATA_BYTES {
                return Err(Error::new_str("registry metadata exceeds rewrite limit"));
            }
            rewrite.buffer.extend_from_slice(chunk);
            chunk.clear();
        }
        if end_of_stream {
            let rewritten = rewrite_registry_json(&rewrite.buffer, &rewrite.from, &rewrite.to)
                .map_err(|_| Error::new_str("invalid registry metadata JSON"))?;
            *body = Some(Bytes::from(rewritten));
        }
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let status = session
            .response_written()
            .map(|response| response.status.as_u16())
            .unwrap_or(0);
        let upstream = ctx
            .upstream
            .as_ref()
            .map(|upstream| upstream.name.clone())
            .unwrap_or_else(|| "unrouted".to_string());
        ctx.finish_metrics(&upstream, status);
    }
}

// ---------------------------------------------------------------------------
// git-cache handler
// ---------------------------------------------------------------------------

/// Buffer the full request body. Returns Err(()) after having logged; the
/// caller responds 500. SECURITY: body bytes are never logged.
async fn buffer_request_body(session: &mut Session) -> std::result::Result<Vec<u8>, ()> {
    let mut body = Vec::new();
    loop {
        match session.read_request_body().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) => return Ok(body),
            Err(e) => {
                log::error!("git-cache: read request body failed: {e}");
                return Err(());
            }
        }
    }
}

/// Phase 1: read child stdout until the CGI header terminator, capped at
/// HEAD_CAP. Ok(Some((status, headers, body_offset, head_buf))) on success;
/// Ok(None) on EOF-before-terminator or cap exceeded (logged); Err on io
/// error (logged).
async fn read_cgi_head(
    stdout: &mut tokio::process::ChildStdout,
) -> std::result::Result<Option<(u16, Vec<(String, String)>, usize, Vec<u8>)>, ()> {
    const HEAD_CAP: usize = 64 * 1024; // 64 KiB head-read limit
    let mut head_buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        let mut tmp = [0u8; 512];
        let n = match stdout.read(&mut tmp).await {
            Ok(n) => n,
            Err(e) => {
                log::error!("git-cache: stdout head-read failed: {e}");
                return Err(());
            }
        };
        if n == 0 {
            // EOF before finding header terminator.
            log::error!("git-cache: stdout EOF before CGI header terminator");
            return Ok(None);
        }
        head_buf.extend_from_slice(&tmp[..n]);
        if head_buf.len() > HEAD_CAP {
            log::error!("git-cache: CGI head exceeded {HEAD_CAP} bytes without terminator");
            return Ok(None);
        }
        // Parse once per iteration; on success the returned tuple is the
        // definitive parse — no second call needed after the loop.
        if let Some((status, headers, body_offset)) = backend::parse_cgi_head(&head_buf) {
            return Ok(Some((status, headers, body_offset, head_buf)));
        }
    }
}

impl ProxyService {
    async fn handle_git_cache(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        upstream: Arc<Upstream>,
        path: &str,
    ) -> Result<bool> {
        let method = session.req_header().method.as_str().to_string();
        let query = session.req_header().uri.query().unwrap_or("").to_string();

        match classify(&method, path, &query) {
            GitRequest::Read => {
                self.handle_git_read(session, ctx, upstream, path, &method, &query)
                    .await
            }
            GitRequest::Push => self.handle_git_push(session, ctx, upstream, path).await,
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
        let credential = match self
            .credentials
            .resolve(&upstream, method, path, None)
            .await
        {
            Ok(credential) => credential,
            Err(e) => {
                log::error!(
                    "git-cache credential resolution failed for {}: {e}",
                    upstream.name
                );
                session
                    .respond_error_with_body(
                        502,
                        Bytes::from_static(b"upstream secret unavailable"),
                    )
                    .await?;
                return Ok(true);
            }
        };
        // SECURITY: auth_header is the injected git credential — never logged.
        let Some(injection) = upstream.injection.as_ref() else {
            log::error!("git-cache upstream {} has no injection", upstream.name);
            session
                .respond_error_with_body(500, Bytes::from_static(b"injection error"))
                .await?;
            return Ok(true);
        };
        let auth_header = match injection_value(injection, credential.secret.expose()) {
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
        // m2: path_for returns None for invalid/unknown repo path → 404, not 500.
        let mirror_path = match self.mirrors.path_for(&upstream.name, &owner, &repo) {
            Some(p) => p,
            None => {
                session
                    .respond_error_with_body(404, Bytes::from_static(b"repo not found"))
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
        if let Err(e) = self
            .mirrors
            .ensure(&mirror_path, &clone_url, &auth_header)
            .await
        {
            log::error!(
                "git-cache ensure failed for {}/{}/{}: {e}",
                upstream.name,
                owner,
                repo
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
        // MirrorStore stores mirrors at <storage_path>/<upstream_name>/<owner>/<repo>.git.
        // git http-backend needs GIT_PROJECT_ROOT = <storage_path>/<upstream_name> so that
        // the PATH_INFO /owner/repo.git/tail resolves to the correct mirror directory.
        let storage_root = std::path::PathBuf::from(&git_config.storage_path).join(&upstream.name);
        let storage_path = storage_root.as_path();

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
        // Git clients may gzip smart-HTTP POST bodies. `git http-backend`
        // knows how to inflate them, but only when the CGI
        // `HTTP_CONTENT_ENCODING` environment variable is populated.
        let content_encoding = session
            .req_header()
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let git_protocol = session
            .req_header()
            .headers
            .get("git-protocol")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // --- Buffer the FULL request body BEFORE touching child stdin/stdout ---
        //
        // DEADLOCK FIX: The previous code wrote stdin in a loop, dropped stdin,
        // THEN read stdout. This is a classic two-pipe deadlock: git http-backend
        // can start writing stdout (packfile) before draining all of stdin; if its
        // stdout pipe (kernel 64 KiB) fills while trust is still blocked writing
        // stdin, both sides wedge. Reachable on fetch with a large "have" set.
        //
        // Fix: buffer the entire request body (negotiation body — modest in size)
        // into an owned Vec<u8> FIRST, using CONTENT_LENGTH derived from the
        // ACTUAL buffered bytes (not the client header — avoids client spoofing).
        // Then spawn a concurrent task to drain stdin while the main task streams
        // stdout. The ordering constraint is removed entirely.
        //
        // SECURITY: request body bytes are never logged.
        let req_body = match buffer_request_body(session).await {
            Ok(body) => body,
            Err(()) => {
                session
                    .respond_error_with_body(500, Bytes::from_static(b"body read error"))
                    .await?;
                return Ok(true);
            }
        };

        // Build CGI env now that we know the actual body length.
        // CONTENT_LENGTH is derived from the buffered bytes — NOT from the client's
        // Content-Length header — so a malicious client cannot forge it.
        let mut env = backend::cgi_env(
            storage_path,
            &owner,
            &repo,
            &tail,
            query,
            method,
            content_type.as_deref(),
            content_encoding.as_deref(),
            git_protocol.as_deref(),
            None, // remote_user: principal not available (JWT verified but sub not extracted)
        );
        if !req_body.is_empty() {
            env.push(("CONTENT_LENGTH".to_owned(), req_body.len().to_string()));
        }

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

        // --- Concurrent stdin pump (spawned task) + stdout stream (main task) ---
        //
        // The spawned task owns child.stdin and the buffered body; it writes and
        // drops stdin (sending EOF) without touching `session`.  The main task
        // concurrently reads and streams stdout.  Because both pipes are drained
        // simultaneously, neither can fill and deadlock.
        //
        // SECURITY: `req_body` (request body bytes) never appear in logs.
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => {
                log::error!("git-cache: child stdin unavailable");
                let _ = child.kill().await;
                session
                    .respond_error_with_body(500, Bytes::from_static(b"backend io error"))
                    .await?;
                return Ok(true);
            }
        };

        let stdin_task: tokio::task::JoinHandle<Result<(), std::io::Error>> =
            tokio::spawn(async move {
                if !req_body.is_empty() {
                    stdin.write_all(&req_body).await?;
                }
                // Drop stdin → EOF to child.
                drop(stdin);
                Ok(())
            });

        // --- I1: Stream child stdout incrementally — no full-body buffering ---
        //
        // Strategy:
        //   1. Read into a growing head-buffer ONLY until the CGI header
        //      terminator (\r\n\r\n or \n\n) is found, capped at 64 KiB.
        //   2. Parse the CGI head (status + headers) once from the loop break value.
        //   3. Write any body bytes already read (past body_offset) as the first
        //      chunk, then loop-read stdout in fixed-size chunks until EOF.
        //   4. Signal end-of-body with write_response_body(None, true).
        //
        // This ensures we never buffer a full packfile (potentially hundreds of
        // MB) in a Vec<u8>.
        const CHUNK: usize = 64 * 1024; // streaming chunk size

        let mut stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                log::error!("git-cache: child stdout unavailable");
                let _ = child.kill().await;
                session
                    .respond_error_with_body(500, Bytes::from_static(b"backend read error"))
                    .await?;
                return Ok(true);
            }
        };

        // Phase 1: read until we have the full CGI header block.
        // The parsed tuple is returned so we avoid a second parse.
        let (cgi_status, cgi_headers, body_offset, head_buf) = match read_cgi_head(&mut stdout)
            .await
        {
            Ok(Some(parsed)) => parsed,
            Ok(None) => {
                let _ = child.kill().await;
                session
                    .respond_error_with_body(500, Bytes::from_static(b"invalid backend response"))
                    .await?;
                return Ok(true);
            }
            Err(()) => {
                let _ = child.kill().await;
                session
                    .respond_error_with_body(500, Bytes::from_static(b"backend read error"))
                    .await?;
                return Ok(true);
            }
        };

        // Phase 2: send response headers (parsed tuple already in hand — no second parse).
        let mut resp =
            match pingora::http::ResponseHeader::build(cgi_status, Some(cgi_headers.len())) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("git-cache: build response header failed: {e}");
                    let _ = child.kill().await;
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
        // Omit Content-Length — body size is unknown (streaming packfile).
        session.write_response_header(Box::new(resp), false).await?;

        // Phase 3: stream body — first flush any bytes already read past body_offset,
        // then continue reading stdout in fixed-size chunks until EOF.
        if body_offset < head_buf.len() {
            let already_read = Bytes::copy_from_slice(&head_buf[body_offset..]);
            session
                .write_response_body(Some(already_read), false)
                .await?;
        }

        let mut chunk_buf = vec![0u8; CHUNK];
        loop {
            let n = match stdout.read(&mut chunk_buf).await {
                Ok(n) => n,
                Err(e) => {
                    log::error!("git-cache: stdout body-read failed: {e}");
                    // Headers already sent — can't switch to error response.
                    // Close the body and let the client detect the truncation.
                    break;
                }
            };
            if n == 0 {
                break; // stdout EOF
            }
            let chunk = Bytes::copy_from_slice(&chunk_buf[..n]);
            session.write_response_body(Some(chunk), false).await?;
        }
        session.write_response_body(None, true).await?;

        // Join the stdin-writer task; surface its error as a warning (headers
        // already sent, so we cannot return a 500 here).
        // SECURITY: join/io errors never carry auth_header or req_body content.
        match stdin_task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                log::warn!("git-cache: stdin writer io error: {e}");
            }
            Err(e) => {
                log::warn!("git-cache: stdin writer task join error: {e}");
            }
        }

        // Wait for the child to exit (best-effort; headers already sent).
        match child.wait().await {
            Ok(status) if !status.success() => {
                log::warn!("git http-backend exited with status: {status}");
            }
            Err(e) => {
                log::warn!("git http-backend wait error: {e}");
            }
            _ => {}
        }

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
        let method = session.req_header().method.as_str().to_string();
        let credential = match self
            .credentials
            .resolve(&upstream, &method, path, None)
            .await
        {
            Ok(credential) => credential,
            Err(e) => {
                log::error!(
                    "git-cache push: credential resolution failed for {}: {e}",
                    upstream.name
                );
                session
                    .respond_error_with_body(
                        502,
                        Bytes::from_static(b"upstream secret unavailable"),
                    )
                    .await?;
                return Ok(true);
            }
        };

        // Record push info for the background post-push sync in response_filter.
        ctx.push_repo = Some((upstream.name.clone(), res.owner, res.repo));
        ctx.secret = Some(credential.secret);
        ctx.credential_cache_key = credential.cache_key;
        ctx.upstream = Some(upstream);

        // Return false → normal proxy path continues (upstream_peer +
        // upstream_request_filter strips JWT + injects credential).
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_registry_json;

    #[test]
    fn rewrites_only_artifact_registry_urls_in_npm_metadata() {
        let input = br#"{
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://europe-north1-npm.pkg.dev/project/repo/pkg/-/pkg.tgz"
                    },
                    "repository": "https://github.com/example/pkg"
                }
            }
        }"#;
        let output = rewrite_registry_json(
            input,
            "https://europe-north1-npm.pkg.dev",
            "http://npm-proxy.workers.svc:6191",
        )
        .unwrap();
        let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            output["versions"]["1.0.0"]["dist"]["tarball"],
            "http://npm-proxy.workers.svc:6191/project/repo/pkg/-/pkg.tgz"
        );
        assert_eq!(
            output["versions"]["1.0.0"]["repository"],
            "https://github.com/example/pkg"
        );
    }
}
