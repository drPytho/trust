use graphql_parser::query::{
    Definition, Mutation, OperationDefinition, Query, Selection, TypeCondition, Value, parse_query,
};
use serde::Deserialize;

use crate::resource::safe_component;
use crate::scope::Resource;

// Pingora's built-in retry buffer is 64 KiB. We enable it before inspecting a
// GraphQL body so the normal proxy pipeline can replay the exact bytes.
pub const MAX_GRAPHQL_BODY_BYTES: usize = 64 * 1024;
pub const MAX_REST_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphqlRequestError {
    #[error("request body is not valid GitHub GraphQL JSON")]
    InvalidJson,
    #[error("GraphQL document is invalid")]
    InvalidDocument,
    #[error("exactly one named supported GraphQL operation is required")]
    UnsupportedOperation,
    #[error("GraphQL query must be rooted exclusively at one repository")]
    UnscopedQuery,
    #[error("GraphQL variables do not identify one safe repository")]
    InvalidRepository,
    #[error("createPullRequest must have one safe repositoryId input variable")]
    InvalidPullRequestCreate,
    #[error("label mutation must have safe labelableId and labelIds input variables")]
    InvalidLabelMutation,
    #[error("pull request update must contain only a safe pullRequestId, title, and body")]
    InvalidPullRequestUpdate,
    #[error("pull request ready mutation must contain one safe pullRequestId")]
    InvalidPullRequestReady,
    #[error("comment mutation must contain one safe subjectId and body")]
    InvalidCommentMutation,
    #[error("pull request status-check query is not the bounded gh query shape")]
    InvalidStatusCheckQuery,
    #[error("review thread mutation must contain one safe threadId")]
    InvalidReviewThreadMutation,
    #[error("pull request draft mutation must contain one safe pullRequestId")]
    InvalidPullRequestDraft,
    #[error(
        "auto-merge and merge-queue mutations must pin a safe pullRequestId and expectedHeadOid"
    )]
    InvalidMergeMutation,
    #[error("search must be one ISSUE search bound by exactly one repo: qualifier")]
    InvalidSearch,
}

/// A GitHub CLI GraphQL operation whose repository authority Trust can bind
/// before it exchanges the caller JWT for an installation token.
#[derive(Debug, PartialEq, Eq)]
pub enum GithubCliGraphqlOperation {
    RepositoryQuery(Resource),
    IssueFeatureDetection,
    PullRequestFeatureDetection,
    WorkflowRunFeatureDetection,
    StatusChecks,
    CreatePullRequest,
    UpdatePullRequest,
    MarkPullRequestReady,
    CreateComment,
    UpdateLabels,
    ResolveReviewThread,
    ConvertPullRequestToDraft,
    EnableAutoMerge,
    EnqueuePullRequest,
    /// `viewer { login }`: answered locally from the configured App bot
    /// identity because installation tokens cannot query the viewer.
    Viewer,
    /// A `search` query whose `repo:` qualifier names the bound repository.
    Search(Resource),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubCliRestOperation {
    Read,
    CreateLabel,
    UpdateLabel,
    CreateIssueComment,
    ReplyReviewComment,
    AddIssueLabels,
    RemoveIssueLabel,
}

impl GithubCliRestOperation {
    pub fn requires_body(self) -> bool {
        !matches!(self, Self::Read | Self::RemoveIssueLabel)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RestRequestError {
    #[error("unsupported GitHub CLI REST request")]
    Unsupported,
    #[error("request body is not valid GitHub REST JSON")]
    InvalidJson,
    #[error("request body is not the bounded GitHub REST shape")]
    InvalidBody,
}

#[derive(Deserialize)]
struct GraphqlRequest {
    query: String,
    #[serde(default)]
    variables: serde_json::Map<String, serde_json::Value>,
}

/// Translate the GitHub Enterprise REST prefix emitted by `gh` for a custom
/// `GH_HOST` into the native GitHub.com API path.
pub fn rest_upstream_path(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix("/api/v3")?;
    if suffix.is_empty() {
        Some("/")
    } else if suffix.starts_with('/') {
        Some(suffix)
    } else {
        None
    }
}

/// Classify read-only REST requests and the exact repository writes needed for
/// labels and review-comment replies. Body validation is performed separately
/// after the proxy enables retry buffering.
pub fn classify_rest_request(
    method: &str,
    path: &str,
) -> Result<GithubCliRestOperation, RestRequestError> {
    if matches!(method, "GET" | "HEAD") {
        return Ok(GithubCliRestOperation::Read);
    }

    let path = rest_upstream_path(path).unwrap_or(path);
    let segments = path.split('/').collect::<Vec<_>>();
    match (method, segments.as_slice()) {
        ("POST", ["", "repos", owner, repo, "labels"])
            if safe_component(owner) && safe_component(repo) =>
        {
            Ok(GithubCliRestOperation::CreateLabel)
        }
        ("PATCH", ["", "repos", owner, repo, "labels", label])
            if safe_component(owner) && safe_component(repo) && safe_component(label) =>
        {
            Ok(GithubCliRestOperation::UpdateLabel)
        }
        ("POST", ["", "repos", owner, repo, "issues", number, "comments"])
            if safe_component(owner) && safe_component(repo) && is_positive_decimal(number) =>
        {
            Ok(GithubCliRestOperation::CreateIssueComment)
        }
        (
            "POST",
            [
                "",
                "repos",
                owner,
                repo,
                "pulls",
                number,
                "comments",
                comment_id,
                "replies",
            ],
        ) if safe_component(owner)
            && safe_component(repo)
            && is_positive_decimal(number)
            && is_positive_decimal(comment_id) =>
        {
            Ok(GithubCliRestOperation::ReplyReviewComment)
        }
        ("POST", ["", "repos", owner, repo, "issues", number, "labels"])
            if safe_component(owner) && safe_component(repo) && is_positive_decimal(number) =>
        {
            Ok(GithubCliRestOperation::AddIssueLabels)
        }
        ("DELETE", ["", "repos", owner, repo, "issues", number, "labels", label])
            if safe_component(owner)
                && safe_component(repo)
                && is_positive_decimal(number)
                && safe_component(label) =>
        {
            Ok(GithubCliRestOperation::RemoveIssueLabel)
        }
        _ => Err(RestRequestError::Unsupported),
    }
}

pub fn validate_rest_body(
    operation: GithubCliRestOperation,
    body: &[u8],
) -> Result<(), RestRequestError> {
    if !operation.requires_body() {
        return Ok(());
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| RestRequestError::InvalidJson)?;
    let input = value.as_object().ok_or(RestRequestError::InvalidBody)?;

    match operation {
        GithubCliRestOperation::Read | GithubCliRestOperation::RemoveIssueLabel => Ok(()),
        GithubCliRestOperation::CreateLabel => {
            if !has_exact_keys(input, &["name", "color", "description"])
                || !input.get("name").is_some_and(valid_nonempty_string)
                || !input.get("color").is_some_and(valid_label_color)
                || !input
                    .get("description")
                    .is_some_and(serde_json::Value::is_string)
            {
                return Err(RestRequestError::InvalidBody);
            }
            Ok(())
        }
        GithubCliRestOperation::UpdateLabel => {
            if input.is_empty()
                || !has_only_keys(input, &["color", "description"])
                || input
                    .get("color")
                    .is_some_and(|value| !valid_label_color(value))
                || input
                    .get("description")
                    .is_some_and(|value| !value.is_string())
            {
                return Err(RestRequestError::InvalidBody);
            }
            Ok(())
        }
        GithubCliRestOperation::CreateIssueComment | GithubCliRestOperation::ReplyReviewComment => {
            if !has_exact_keys(input, &["body"])
                || !input.get("body").is_some_and(valid_nonempty_string)
            {
                return Err(RestRequestError::InvalidBody);
            }
            Ok(())
        }
        GithubCliRestOperation::AddIssueLabels => {
            if !has_exact_keys(input, &["labels"])
                || !input
                    .get("labels")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|labels| {
                        !labels.is_empty() && labels.iter().all(valid_nonempty_string)
                    })
            {
                return Err(RestRequestError::InvalidBody);
            }
            Ok(())
        }
    }
}

/// Bind a REST `GET /search/issues` request to the single repository named
/// by its `q` parameter. Returns `None` for any other path.
pub fn rest_search_repository(
    path: &str,
    query: Option<&str>,
) -> Option<Result<Resource, GraphqlRequestError>> {
    if rest_upstream_path(path).unwrap_or(path) != "/search/issues" {
        return None;
    }
    let mut q = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        if key == "q" {
            if q.is_some() {
                return Some(Err(GraphqlRequestError::InvalidSearch));
            }
            q = Some(value.into_owned());
        }
    }
    Some(
        q.as_deref()
            .and_then(search_query_repository)
            .ok_or(GraphqlRequestError::InvalidSearch),
    )
}

/// Return the repository a GitHub issue/PR search string is confined to.
///
/// The installation token is restricted to the bound repository, but search
/// still covers public repositories, so the query itself must name exactly
/// one `repo:` qualifier. Qualifiers that widen or replace it (`org:`,
/// `user:`, `owner:`, negated `repo:`) and boolean `OR`/grouping, which could
/// escape the implicit AND, are rejected.
pub fn search_query_repository(q: &str) -> Option<Resource> {
    let mut selected = None;
    for token in search_tokens(q)? {
        let bare = token.strip_prefix('-').unwrap_or(&token);
        if token.eq_ignore_ascii_case("or") {
            return None;
        }
        let Some((key, value)) = bare.split_once(':') else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "org" | "user" | "owner" => return None,
            "repo" => {
                if token.starts_with('-') || selected.is_some() {
                    return None;
                }
                let (owner, repo) = value.trim_matches('"').split_once('/')?;
                if !safe_component(owner) || !safe_component(repo) {
                    return None;
                }
                selected = Some(Resource {
                    owner: owner.to_string(),
                    repo: repo.to_string(),
                });
            }
            _ => {}
        }
    }
    selected
}

/// Split a search string on whitespace outside double quotes. Grouping
/// parentheses outside quotes are refused.
fn search_tokens(q: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in q.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            '(' | ')' if !quoted => return None,
            ch if ch.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if quoted {
        return None;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Some(tokens)
}

fn is_positive_decimal(value: &str) -> bool {
    !value.is_empty() && value != "0" && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_nonempty_string(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(|value| !value.is_empty())
}

fn valid_label_color(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .is_some_and(|color| color.len() == 6 && color.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn has_only_keys(input: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) -> bool {
    input.keys().all(|key| allowed.contains(&key.as_str()))
}

fn has_exact_keys(input: &serde_json::Map<String, serde_json::Value>, expected: &[&str]) -> bool {
    input.len() == expected.len() && has_only_keys(input, expected)
}

/// Rewrite GitHub's REST pagination `Link` header so each page URL points
/// back at the Trust host the client used instead of `api.github.com`,
/// which a sandbox cannot reach.
///
/// GitHub often emits next-page links in the `/repositories/{id}/...` form.
/// When that link's tail matches the forwarded `/repos/{owner}/{repo}/...`
/// path, the named form is restored so Trust can still bind the repository.
pub fn rewrite_link_header(
    value: &str,
    origin: &str,
    base: &str,
    client_path: &str,
    upstream_path: &str,
) -> String {
    let prefix = client_path.strip_suffix(upstream_path).unwrap_or("");
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let Some(len) = rest[start + 1..].find('>') else {
            break;
        };
        let target = &rest[start + 1..start + 1 + len];
        out.push_str(&rest[..=start]);
        match target
            .strip_prefix(origin)
            .filter(|path| path.starts_with('/'))
        {
            Some(path_and_query) => {
                let (path, query) = match path_and_query.split_once('?') {
                    Some((path, query)) => (path, Some(query)),
                    None => (path_and_query, None),
                };
                out.push_str(base);
                out.push_str(prefix);
                out.push_str(&named_repository_path(path, upstream_path));
                if let Some(query) = query {
                    out.push('?');
                    out.push_str(query);
                }
            }
            None => out.push_str(target),
        }
        out.push('>');
        rest = &rest[start + 1 + len + 1..];
    }
    out.push_str(rest);
    out
}

fn named_repository_path(path: &str, upstream_path: &str) -> String {
    let link = path.split('/').collect::<Vec<_>>();
    let upstream = upstream_path.split('/').collect::<Vec<_>>();
    match (link.as_slice(), upstream.as_slice()) {
        (["", "repositories", id, link_tail @ ..], ["", "repos", _, _, upstream_tail @ ..])
            if is_positive_decimal(id) && link_tail == upstream_tail =>
        {
            upstream_path.to_string()
        }
        _ => path.to_string(),
    }
}

pub fn is_graphql_path(path: &str) -> bool {
    matches!(path, "/api/graphql" | "/graphql")
}

fn variable_string<'a>(
    variables: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a str> {
    variables.get(name)?.as_str()
}

/// Classify a GitHub CLI GraphQL request. Repository-rooted queries bind their
/// own owner/name variables. Bounded node queries and mutations carry opaque
/// IDs, so the proxy subsequently binds them to one exact repository scope
/// before exchanging the caller JWT for a repository-restricted token.
pub fn classify_graphql(body: &[u8]) -> Result<GithubCliGraphqlOperation, GraphqlRequestError> {
    let request: GraphqlRequest =
        serde_json::from_slice(body).map_err(|_| GraphqlRequestError::InvalidJson)?;
    let document =
        parse_query::<String>(&request.query).map_err(|_| GraphqlRequestError::InvalidDocument)?;

    let operations = document
        .definitions
        .iter()
        .filter_map(|definition| match definition {
            Definition::Operation(operation) => Some(operation),
            Definition::Fragment(_) => None,
        })
        .collect::<Vec<_>>();

    let [operation] = operations.as_slice() else {
        return Err(GraphqlRequestError::UnsupportedOperation);
    };
    match operation {
        OperationDefinition::Query(query) => {
            if is_issue_feature_detection(query) {
                Ok(GithubCliGraphqlOperation::IssueFeatureDetection)
            } else if is_pull_request_feature_detection(query) {
                Ok(GithubCliGraphqlOperation::PullRequestFeatureDetection)
            } else if is_workflow_run_feature_detection(query) {
                Ok(GithubCliGraphqlOperation::WorkflowRunFeatureDetection)
            } else if query.name.as_deref() == Some("PullRequestStatusChecks") {
                validate_status_checks_query(query, &request.variables)?;
                Ok(GithubCliGraphqlOperation::StatusChecks)
            } else if is_viewer_login_query(&query.selection_set.items) {
                Ok(GithubCliGraphqlOperation::Viewer)
            } else if is_search_query(query) {
                search_repository(query, &request.variables).map(GithubCliGraphqlOperation::Search)
            } else {
                repository_from_query(query, &request.variables)
                    .map(GithubCliGraphqlOperation::RepositoryQuery)
            }
        }
        OperationDefinition::Mutation(mutation) => {
            let [Selection::Field(field)] = mutation.selection_set.items.as_slice() else {
                return Err(GraphqlRequestError::UnsupportedOperation);
            };
            match field.name.as_str() {
                "createPullRequest" => {
                    validate_create_pull_request(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::CreatePullRequest)
                }
                "addLabelsToLabelable" | "removeLabelsFromLabelable" => {
                    validate_label_mutation(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::UpdateLabels)
                }
                "updatePullRequest" => {
                    validate_pull_request_update(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::UpdatePullRequest)
                }
                "markPullRequestReadyForReview" => {
                    validate_pull_request_ready(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::MarkPullRequestReady)
                }
                "addComment" => {
                    validate_comment_mutation(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::CreateComment)
                }
                "resolveReviewThread" => {
                    validate_review_thread_mutation(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::ResolveReviewThread)
                }
                "convertPullRequestToDraft" => {
                    validate_pull_request_draft(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::ConvertPullRequestToDraft)
                }
                "enablePullRequestAutoMerge" => {
                    validate_auto_merge(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::EnableAutoMerge)
                }
                "enqueuePullRequest" => {
                    validate_enqueue(mutation, &request.variables)?;
                    Ok(GithubCliGraphqlOperation::EnqueuePullRequest)
                }
                _ => Err(GraphqlRequestError::UnsupportedOperation),
            }
        }
        OperationDefinition::SelectionSet(selection_set) => {
            // `query { viewer { login } }` is the only anonymous shorthand
            // operation Trust understands.
            if is_viewer_login_query(&selection_set.items) {
                Ok(GithubCliGraphqlOperation::Viewer)
            } else {
                Err(GraphqlRequestError::UnsupportedOperation)
            }
        }
        _ => Err(GraphqlRequestError::UnsupportedOperation),
    }
}

/// Best-effort `name/rootField` label for logging a GraphQL request, whether
/// or not Trust accepts it. Never includes variables.
pub fn graphql_operation_label(body: &[u8]) -> Option<String> {
    let request: GraphqlRequest = serde_json::from_slice(body).ok()?;
    let document = parse_query::<String>(&request.query).ok()?;
    let labels = document
        .definitions
        .iter()
        .filter_map(|definition| {
            let (kind, name, selection_set) = match definition {
                Definition::Operation(OperationDefinition::Query(query)) => {
                    ("query", query.name.as_deref(), &query.selection_set)
                }
                Definition::Operation(OperationDefinition::Mutation(mutation)) => (
                    "mutation",
                    mutation.name.as_deref(),
                    &mutation.selection_set,
                ),
                Definition::Operation(OperationDefinition::Subscription(subscription)) => (
                    "subscription",
                    subscription.name.as_deref(),
                    &subscription.selection_set,
                ),
                Definition::Operation(OperationDefinition::SelectionSet(selection_set)) => {
                    ("query", None, selection_set)
                }
                Definition::Fragment(_) => return None,
            };
            let fields = selection_set
                .items
                .iter()
                .filter_map(|selection| match selection {
                    Selection::Field(field) => Some(field.name.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(",");
            Some(format!("{kind} {}/{fields}", name.unwrap_or("<anonymous>")))
        })
        .collect::<Vec<_>>();
    (!labels.is_empty()).then(|| labels.join("; "))
}

/// Compatibility helper for callers that only accept repository-rooted query
/// operations. New code should use [`classify_graphql`] to handle the bounded
/// pull-request creation mutation explicitly.
pub fn repository_from_graphql(body: &[u8]) -> Result<Resource, GraphqlRequestError> {
    match classify_graphql(body)? {
        GithubCliGraphqlOperation::RepositoryQuery(resource) => Ok(resource),
        GithubCliGraphqlOperation::IssueFeatureDetection
        | GithubCliGraphqlOperation::PullRequestFeatureDetection
        | GithubCliGraphqlOperation::WorkflowRunFeatureDetection
        | GithubCliGraphqlOperation::StatusChecks
        | GithubCliGraphqlOperation::CreatePullRequest
        | GithubCliGraphqlOperation::UpdatePullRequest
        | GithubCliGraphqlOperation::MarkPullRequestReady
        | GithubCliGraphqlOperation::CreateComment
        | GithubCliGraphqlOperation::UpdateLabels
        | GithubCliGraphqlOperation::ResolveReviewThread
        | GithubCliGraphqlOperation::ConvertPullRequestToDraft
        | GithubCliGraphqlOperation::EnableAutoMerge
        | GithubCliGraphqlOperation::EnqueuePullRequest
        | GithubCliGraphqlOperation::Viewer
        | GithubCliGraphqlOperation::Search(_) => Err(GraphqlRequestError::UnsupportedOperation),
    }
}

/// `viewer { login }` with no aliases, arguments, or directives.
fn is_viewer_login_query(items: &[Selection<'_, String>]) -> bool {
    let [Selection::Field(viewer)] = items else {
        return false;
    };
    if viewer.name != "viewer"
        || viewer.alias.is_some()
        || !viewer.arguments.is_empty()
        || !viewer.directives.is_empty()
    {
        return false;
    }
    matches!(
        viewer.selection_set.items.as_slice(),
        [Selection::Field(login)]
            if login.name == "login"
                && login.alias.is_none()
                && login.arguments.is_empty()
                && login.directives.is_empty()
                && login.selection_set.items.is_empty()
    )
}

fn is_search_query(query: &Query<'_, String>) -> bool {
    matches!(
        query.selection_set.items.as_slice(),
        [Selection::Field(field)] if field.name == "search"
    )
}

/// Bind the `search(query: $q, type: $type, ...)` root used by
/// `gh pr list --search/--label/--author` to the repository named by its
/// single `repo:` qualifier.
fn search_repository(
    query: &Query<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<Resource, GraphqlRequestError> {
    let [Selection::Field(field)] = query.selection_set.items.as_slice() else {
        return Err(GraphqlRequestError::InvalidSearch);
    };
    if query.name.is_none() || field.alias.is_some() || !field.directives.is_empty() {
        return Err(GraphqlRequestError::InvalidSearch);
    }
    let mut search_string = None;
    let mut search_type = None;
    for (name, value) in &field.arguments {
        let resolved = match value {
            Value::Variable(variable) => variables.get(variable).cloned(),
            Value::String(value) => Some(serde_json::Value::String(value.clone())),
            Value::Enum(value) => Some(serde_json::Value::String(value.clone())),
            Value::Int(_) | Value::Null => None,
            _ => return Err(GraphqlRequestError::InvalidSearch),
        };
        match name.as_str() {
            "query" => search_string = resolved,
            "type" => search_type = resolved,
            "first" | "last" | "after" | "before" => {}
            _ => return Err(GraphqlRequestError::InvalidSearch),
        }
    }
    if !search_type
        .as_ref()
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| matches!(value, "ISSUE" | "ISSUE_ADVANCED"))
    {
        return Err(GraphqlRequestError::InvalidSearch);
    }
    search_string
        .as_ref()
        .and_then(serde_json::Value::as_str)
        .and_then(search_query_repository)
        .ok_or(GraphqlRequestError::InvalidSearch)
}

/// GitHub CLI treats a custom `GH_HOST` as GitHub Enterprise and asks this
/// static schema question before `gh pr create`. It is safe to answer locally:
/// the response contains no account or repository data, and its empty field
/// list disables optional issue metadata features rather than enabling writes.
fn is_issue_feature_detection(query: &Query<'_, String>) -> bool {
    is_type_feature_detection(query, "Issue_fields", &["Issue"])
}

fn is_pull_request_feature_detection(query: &Query<'_, String>) -> bool {
    is_type_feature_detection(
        query,
        "PullRequest_fields",
        &["PullRequest", "StatusCheckRollupContextConnection"],
    )
}

fn is_workflow_run_feature_detection(query: &Query<'_, String>) -> bool {
    is_type_feature_detection(query, "PullRequest_fields2", &["WorkflowRun"])
}

fn is_type_feature_detection(
    query: &Query<'_, String>,
    operation_name: &str,
    type_names: &[&str],
) -> bool {
    if query.name.as_deref() != Some(operation_name)
        || query.selection_set.items.len() != type_names.len()
    {
        return false;
    }
    type_names.iter().all(|type_name| {
        query.selection_set.items.iter().any(|selection| {
            let Selection::Field(type_field) = selection else {
                return false;
            };
            type_field.alias.as_deref() == Some(*type_name)
                && type_field.name == "__type"
                && type_field.arguments.len() == 1
                && type_field.directives.is_empty()
                && matches!(
                    type_field.arguments.as_slice(),
                    [(name, Value::String(selected_type))]
                        if name == "name" && selected_type == type_name
                )
        })
    })
}

fn repository_from_query(
    query: &Query<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<Resource, GraphqlRequestError> {
    if query.name.is_none() || query.selection_set.items.is_empty() {
        return Err(GraphqlRequestError::UnsupportedOperation);
    }

    let mut selected: Option<Resource> = None;
    for selection in &query.selection_set.items {
        let Selection::Field(field) = selection else {
            return Err(GraphqlRequestError::UnscopedQuery);
        };
        if field.name != "repository" {
            return Err(GraphqlRequestError::UnscopedQuery);
        }

        let owner_variable = field
            .arguments
            .iter()
            .find(|(name, _)| name == "owner")
            .and_then(|(_, value)| match value {
                Value::Variable(name) => Some(name.as_str()),
                _ => None,
            })
            .ok_or(GraphqlRequestError::UnscopedQuery)?;
        let repo_variable = field
            .arguments
            .iter()
            .find(|(name, _)| name == "name")
            .and_then(|(_, value)| match value {
                Value::Variable(name) => Some(name.as_str()),
                _ => None,
            })
            .ok_or(GraphqlRequestError::UnscopedQuery)?;

        let owner = variable_string(variables, owner_variable)
            .ok_or(GraphqlRequestError::InvalidRepository)?;
        let repo = variable_string(variables, repo_variable)
            .ok_or(GraphqlRequestError::InvalidRepository)?;
        if !safe_component(owner) || !safe_component(repo) {
            return Err(GraphqlRequestError::InvalidRepository);
        }
        let resource = Resource {
            owner: owner.to_string(),
            repo: repo.to_string(),
        };
        if selected.as_ref().is_some_and(|selected| {
            !selected.owner.eq_ignore_ascii_case(&resource.owner)
                || !selected.repo.eq_ignore_ascii_case(&resource.repo)
        }) {
            return Err(GraphqlRequestError::UnscopedQuery);
        }
        selected = Some(resource);
    }

    selected.ok_or(GraphqlRequestError::UnscopedQuery)
}

fn validate_status_checks_query(
    query: &Query<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    if query.name.as_deref() != Some("PullRequestStatusChecks")
        || query.selection_set.items.len() != 1
        || !variables
            .keys()
            .all(|key| matches!(key.as_str(), "id" | "endCursor"))
        || !variables.get("id").is_some_and(valid_node_id)
        || variables
            .get("endCursor")
            .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(GraphqlRequestError::InvalidStatusCheckQuery);
    }

    let [Selection::Field(node)] = query.selection_set.items.as_slice() else {
        return Err(GraphqlRequestError::InvalidStatusCheckQuery);
    };
    if node.alias.is_some()
        || node.name != "node"
        || !node.directives.is_empty()
        || !matches!(
            node.arguments.as_slice(),
            [(name, Value::Variable(variable))] if name == "id" && variable == "id"
        )
        || node.selection_set.items.len() != 1
    {
        return Err(GraphqlRequestError::InvalidStatusCheckQuery);
    }

    let [Selection::InlineFragment(fragment)] = node.selection_set.items.as_slice() else {
        return Err(GraphqlRequestError::InvalidStatusCheckQuery);
    };
    if !matches!(
        fragment.type_condition.as_ref(),
        Some(TypeCondition::On(type_name)) if type_name == "PullRequest"
    ) || !fragment.directives.is_empty()
        || fragment.selection_set.items.is_empty()
        || !fragment
            .selection_set
            .items
            .iter()
            .all(valid_status_check_selection)
    {
        return Err(GraphqlRequestError::InvalidStatusCheckQuery);
    }

    Ok(())
}

fn valid_status_check_selection(selection: &Selection<'_, String>) -> bool {
    match selection {
        Selection::FragmentSpread(_) => false,
        Selection::InlineFragment(fragment) => {
            matches!(
                fragment.type_condition.as_ref(),
                Some(TypeCondition::On(type_name))
                    if matches!(type_name.as_str(), "StatusContext" | "CheckRun")
            ) && fragment.directives.is_empty()
                && !fragment.selection_set.items.is_empty()
                && fragment
                    .selection_set
                    .items
                    .iter()
                    .all(valid_status_check_selection)
        }
        Selection::Field(field) => {
            if !field.directives.is_empty() {
                return false;
            }

            let is_object = matches!(
                field.name.as_str(),
                "commits"
                    | "nodes"
                    | "commit"
                    | "statusCheckRollup"
                    | "contexts"
                    | "checkSuite"
                    | "workflowRun"
                    | "workflow"
                    | "pageInfo"
            );
            let is_leaf = matches!(
                field.name.as_str(),
                "__typename"
                    | "context"
                    | "state"
                    | "targetUrl"
                    | "createdAt"
                    | "description"
                    | "isRequired"
                    | "name"
                    | "event"
                    | "status"
                    | "conclusion"
                    | "startedAt"
                    | "completedAt"
                    | "detailsUrl"
                    | "hasNextPage"
                    | "endCursor"
            );
            if !is_object && !is_leaf {
                return false;
            }

            let valid_alias = if field.name == "commits" {
                field.alias.as_deref() == Some("statusCheckRollup")
            } else {
                field.alias.is_none()
            };
            let valid_arguments = match field.name.as_str() {
                "commits" => matches!(
                    field.arguments.as_slice(),
                    [(name, Value::Int(value))]
                        if name == "last" && value.as_i64() == Some(1)
                ),
                "contexts" => {
                    let first_count = field
                        .arguments
                        .iter()
                        .filter(|(name, _)| name == "first")
                        .count();
                    let after_count = field
                        .arguments
                        .iter()
                        .filter(|(name, _)| name == "after")
                        .count();
                    first_count == 1
                        && after_count <= 1
                        && field.arguments.len() == first_count + after_count
                }
                "isRequired" => matches!(
                    field.arguments.as_slice(),
                    [(name, Value::Variable(variable))]
                        if name == "pullRequestId" && variable == "id"
                ),
                _ => field.arguments.is_empty(),
            };
            let valid_context_arguments =
                field.name != "contexts" || field.arguments.iter().any(|(name, value)| {
                    name == "first"
                        && matches!(value, Value::Int(value) if value.as_i64() == Some(100))
                }) && field.arguments.iter().all(|(name, value)| {
                    match name.as_str() {
                        "first" => {
                            matches!(value, Value::Int(value) if value.as_i64() == Some(100))
                        }
                        "after" => {
                            matches!(value, Value::Variable(variable) if variable == "endCursor")
                        }
                        _ => false,
                    }
                });
            let valid_selection = if is_object {
                !field.selection_set.items.is_empty()
                    && field
                        .selection_set
                        .items
                        .iter()
                        .all(valid_status_check_selection)
            } else {
                field.selection_set.items.is_empty()
            };

            valid_alias && valid_arguments && valid_context_arguments && valid_selection
        }
    }
}

fn mutation_input<'a>(
    mutation: &Mutation<'_, String>,
    variables: &'a serde_json::Map<String, serde_json::Value>,
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    if mutation.name.is_none() || mutation.selection_set.items.len() != 1 {
        return None;
    }
    let [Selection::Field(field)] = mutation.selection_set.items.as_slice() else {
        return None;
    };
    let [(name, Value::Variable(input_variable))] = field.arguments.as_slice() else {
        return None;
    };
    if name != "input" {
        return None;
    }
    variables.get(input_variable)?.as_object()
}

fn valid_node_id(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(|id| {
        !id.is_empty() && !id.as_bytes().iter().any(|byte| byte.is_ascii_control())
    })
}

fn validate_create_pull_request(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    if mutation.name.is_none() || mutation.selection_set.items.len() != 1 {
        return Err(GraphqlRequestError::UnsupportedOperation);
    }
    let [Selection::Field(field)] = mutation.selection_set.items.as_slice() else {
        return Err(GraphqlRequestError::UnsupportedOperation);
    };
    if field.name != "createPullRequest" {
        return Err(GraphqlRequestError::UnsupportedOperation);
    }

    let Some((_, Value::Variable(input_variable))) =
        field.arguments.iter().find(|(name, _)| name == "input")
    else {
        return Err(GraphqlRequestError::InvalidPullRequestCreate);
    };
    if field.arguments.len() != 1 {
        return Err(GraphqlRequestError::InvalidPullRequestCreate);
    }
    let repository_id = variables
        .get(input_variable)
        .and_then(serde_json::Value::as_object)
        .and_then(|input| input.get("repositoryId"))
        .and_then(serde_json::Value::as_str)
        .filter(|repository_id| {
            !repository_id.is_empty()
                && !repository_id
                    .as_bytes()
                    .iter()
                    .any(|byte| byte.is_ascii_control())
        })
        .ok_or(GraphqlRequestError::InvalidPullRequestCreate)?;

    // Keep the check explicit: GitHub's repository node IDs are opaque, so
    // Trust must never infer a repository from their value. The exact JWT
    // scope is used later to choose the restricted installation token.
    let _ = repository_id;
    Ok(())
}

fn validate_label_mutation(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    if mutation.name.is_none() || mutation.selection_set.items.len() != 1 {
        return Err(GraphqlRequestError::UnsupportedOperation);
    }
    let [Selection::Field(field)] = mutation.selection_set.items.as_slice() else {
        return Err(GraphqlRequestError::UnsupportedOperation);
    };
    if !matches!(
        field.name.as_str(),
        "addLabelsToLabelable" | "removeLabelsFromLabelable"
    ) {
        return Err(GraphqlRequestError::UnsupportedOperation);
    }

    let Some((_, Value::Variable(input_variable))) =
        field.arguments.iter().find(|(name, _)| name == "input")
    else {
        return Err(GraphqlRequestError::InvalidLabelMutation);
    };
    if field.arguments.len() != 1 {
        return Err(GraphqlRequestError::InvalidLabelMutation);
    }

    let input = variables
        .get(input_variable)
        .and_then(serde_json::Value::as_object)
        .ok_or(GraphqlRequestError::InvalidLabelMutation)?;
    if input.len() != 2
        || !input
            .keys()
            .all(|key| matches!(key.as_str(), "labelableId" | "labelIds"))
    {
        return Err(GraphqlRequestError::InvalidLabelMutation);
    }
    if !input.get("labelableId").is_some_and(valid_node_id) {
        return Err(GraphqlRequestError::InvalidLabelMutation);
    }
    let label_ids = input
        .get("labelIds")
        .and_then(serde_json::Value::as_array)
        .filter(|ids| !ids.is_empty())
        .ok_or(GraphqlRequestError::InvalidLabelMutation)?;
    if !label_ids.iter().all(valid_node_id) {
        return Err(GraphqlRequestError::InvalidLabelMutation);
    }

    Ok(())
}

fn validate_pull_request_update(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input =
        mutation_input(mutation, variables).ok_or(GraphqlRequestError::InvalidPullRequestUpdate)?;
    // `gh pr create --label` applies labels through a follow-up
    // `updatePullRequest` carrying only `labelIds`.
    if input.len() < 2
        || !has_only_keys(input, &["pullRequestId", "title", "body", "labelIds"])
        || !input.get("pullRequestId").is_some_and(valid_node_id)
        || input.get("title").is_some_and(|value| !value.is_string())
        || input.get("body").is_some_and(|value| !value.is_string())
        || input.get("labelIds").is_some_and(|value| {
            !value
                .as_array()
                .is_some_and(|ids| !ids.is_empty() && ids.iter().all(valid_node_id))
        })
    {
        return Err(GraphqlRequestError::InvalidPullRequestUpdate);
    }
    Ok(())
}

fn validate_pull_request_ready(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input =
        mutation_input(mutation, variables).ok_or(GraphqlRequestError::InvalidPullRequestReady)?;
    if !has_exact_keys(input, &["pullRequestId"])
        || !input.get("pullRequestId").is_some_and(valid_node_id)
    {
        return Err(GraphqlRequestError::InvalidPullRequestReady);
    }
    Ok(())
}

fn validate_review_thread_mutation(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input = mutation_input(mutation, variables)
        .ok_or(GraphqlRequestError::InvalidReviewThreadMutation)?;
    if !has_exact_keys(input, &["threadId"]) || !input.get("threadId").is_some_and(valid_node_id) {
        return Err(GraphqlRequestError::InvalidReviewThreadMutation);
    }
    Ok(())
}

fn validate_pull_request_draft(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input =
        mutation_input(mutation, variables).ok_or(GraphqlRequestError::InvalidPullRequestDraft)?;
    if !has_exact_keys(input, &["pullRequestId"])
        || !input.get("pullRequestId").is_some_and(valid_node_id)
    {
        return Err(GraphqlRequestError::InvalidPullRequestDraft);
    }
    Ok(())
}

/// A full SHA-1 or SHA-256 git object ID. Requiring it means GitHub merges
/// only the exact head commit the agent checked.
fn valid_git_object_id(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(|oid| {
        matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// `gh pr merge --auto --match-head-commit <sha>`. Merge queues receive the
/// same mutation. Commit author overrides are not accepted.
fn validate_auto_merge(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input =
        mutation_input(mutation, variables).ok_or(GraphqlRequestError::InvalidMergeMutation)?;
    if !has_only_keys(
        input,
        &[
            "pullRequestId",
            "expectedHeadOid",
            "mergeMethod",
            "commitHeadline",
            "commitBody",
        ],
    ) || !input.get("pullRequestId").is_some_and(valid_node_id)
        || !input
            .get("expectedHeadOid")
            .is_some_and(valid_git_object_id)
        || input
            .get("mergeMethod")
            .is_some_and(|value| !matches!(value.as_str(), Some("MERGE" | "SQUASH" | "REBASE")))
        || input
            .get("commitHeadline")
            .is_some_and(|value| !value.is_string())
        || input
            .get("commitBody")
            .is_some_and(|value| !value.is_string())
    {
        return Err(GraphqlRequestError::InvalidMergeMutation);
    }
    Ok(())
}

/// Add a pull request to the merge queue at the pinned head. `jump` (skipping
/// ahead of queued pull requests) is not accepted.
fn validate_enqueue(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input =
        mutation_input(mutation, variables).ok_or(GraphqlRequestError::InvalidMergeMutation)?;
    if !has_exact_keys(input, &["pullRequestId", "expectedHeadOid"])
        || !input.get("pullRequestId").is_some_and(valid_node_id)
        || !input
            .get("expectedHeadOid")
            .is_some_and(valid_git_object_id)
    {
        return Err(GraphqlRequestError::InvalidMergeMutation);
    }
    Ok(())
}

fn validate_comment_mutation(
    mutation: &Mutation<'_, String>,
    variables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), GraphqlRequestError> {
    let input =
        mutation_input(mutation, variables).ok_or(GraphqlRequestError::InvalidCommentMutation)?;
    if !has_exact_keys(input, &["subjectId", "body"])
        || !input.get("subjectId").is_some_and(valid_node_id)
        || !input.get("body").is_some_and(valid_nonempty_string)
    {
        return Err(GraphqlRequestError::InvalidCommentMutation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(query: &str, variables: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({ "query": query, "variables": variables })).unwrap()
    }

    #[test]
    fn extracts_gh_repo_view_shape() {
        let body = request(
            "query RepositoryInfo($owner: String!, $name: String!) { \
             repository(owner: $owner, name: $name) { id name } }",
            json!({"owner": "example-org", "name": "example-repo"}),
        );
        assert_eq!(
            repository_from_graphql(&body).unwrap(),
            Resource {
                owner: "example-org".into(),
                repo: "example-repo".into()
            }
        );
    }

    #[test]
    fn extracts_gh_pr_and_issue_shape_using_repo_variable() {
        let body = request(
            "query PullRequestList($owner: String!, $repo: String!) { \
             repository(owner: $owner, name: $repo) { pullRequests(first: 10) { totalCount } } }",
            json!({"owner": "example-org", "repo": "example-repo"}),
        );
        assert_eq!(repository_from_graphql(&body).unwrap().repo, "example-repo");
    }

    #[test]
    fn rejects_global_or_ambiguous_queries() {
        let global = request(
            "query Viewer { viewer { login email } }",
            json!({"owner": "example-org", "repo": "example-repo"}),
        );
        assert_eq!(
            repository_from_graphql(&global),
            Err(GraphqlRequestError::UnscopedQuery)
        );

        let hard_coded = request(
            "query Repo { repository(owner: \"other\", name: \"repo\") { id } }",
            json!({}),
        );
        assert_eq!(
            repository_from_graphql(&hard_coded),
            Err(GraphqlRequestError::UnscopedQuery)
        );
    }

    #[test]
    fn rejects_mutations_and_multiple_operations() {
        let mutation = request(
            "mutation Close($id: ID!) { closeIssue(input: {issueId: $id}) { issue { id } } }",
            json!({"id": "opaque"}),
        );
        assert_eq!(
            repository_from_graphql(&mutation),
            Err(GraphqlRequestError::UnsupportedOperation)
        );

        let multiple = request(
            "query A($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } } \
             query B($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } }",
            json!({"owner": "example-org", "name": "example-repo"}),
        );
        assert_eq!(
            repository_from_graphql(&multiple),
            Err(GraphqlRequestError::UnsupportedOperation)
        );
    }

    #[test]
    fn classifies_gh_pr_create_mutation() {
        let body = request(
            "mutation PullRequestCreate($input: CreatePullRequestInput!) { \
             createPullRequest(input: $input) { pullRequest { id url } } }",
            json!({
                "input": {
                    "repositoryId": "R_kgDOExample",
                    "title": "Create Trust-routed PR",
                    "baseRefName": "main",
                    "headRefName": "agent-branch"
                }
            }),
        );
        assert_eq!(
            classify_graphql(&body),
            Ok(GithubCliGraphqlOperation::CreatePullRequest)
        );
    }

    #[test]
    fn classifies_gh_label_mutations() {
        for field in ["addLabelsToLabelable", "removeLabelsFromLabelable"] {
            let body = request(
                &format!(
                    "mutation LabelUpdate($input: LabelsInput!) {{ \
                     {field}(input: $input) {{ __typename }} }}"
                ),
                json!({
                    "input": {
                        "labelableId": "PR_kwDOExample",
                        "labelIds": ["LA_kwDOOne", "LA_kwDOTwo"]
                    }
                }),
            );
            assert_eq!(
                classify_graphql(&body),
                Ok(GithubCliGraphqlOperation::UpdateLabels)
            );
        }
    }

    #[test]
    fn rejects_unbounded_label_mutations() {
        for input in [
            json!({"labelIds": ["LA_kwDOOne"]}),
            json!({"labelableId": "PR_kwDOExample", "labelIds": []}),
            json!({
                "labelableId": "PR_kwDOExample",
                "labelIds": ["LA_kwDOOne"],
                "clientMutationId": "extra"
            }),
        ] {
            let body = request(
                "mutation LabelAdd($input: AddLabelsToLabelableInput!) { \
                 addLabelsToLabelable(input: $input) { __typename } }",
                json!({"input": input}),
            );
            assert_eq!(
                classify_graphql(&body),
                Err(GraphqlRequestError::InvalidLabelMutation)
            );
        }
    }

    #[test]
    fn classifies_only_the_gh_issue_feature_probe() {
        let body = request(
            "query Issue_fields { Issue: __type(name: \"Issue\") { \
             fields(includeDeprecated: true) { name } } }",
            json!({}),
        );
        assert_eq!(
            classify_graphql(&body),
            Ok(GithubCliGraphqlOperation::IssueFeatureDetection)
        );

        let other_type = request(
            "query Issue_fields { Issue: __type(name: \"PullRequest\") { fields { name } } }",
            json!({}),
        );
        assert_eq!(
            classify_graphql(&other_type),
            Err(GraphqlRequestError::UnscopedQuery)
        );
    }

    #[test]
    fn classifies_gh_pr_check_feature_probes() {
        let pull_request_fields = request(
            "query PullRequest_fields { \
             PullRequest: __type(name: \"PullRequest\") { fields(includeDeprecated: true) { name } } \
             StatusCheckRollupContextConnection: __type(name: \"StatusCheckRollupContextConnection\") { \
             fields(includeDeprecated: true) { name } } }",
            json!({}),
        );
        assert_eq!(
            classify_graphql(&pull_request_fields),
            Ok(GithubCliGraphqlOperation::PullRequestFeatureDetection)
        );

        let workflow_run_fields = request(
            "query PullRequest_fields2 { \
             WorkflowRun: __type(name: \"WorkflowRun\") { fields(includeDeprecated: true) { name } } }",
            json!({}),
        );
        assert_eq!(
            classify_graphql(&workflow_run_fields),
            Ok(GithubCliGraphqlOperation::WorkflowRunFeatureDetection)
        );
    }

    #[test]
    fn classifies_only_the_bounded_gh_pr_checks_node_query() {
        let status_checks = request(
            "query PullRequestStatusChecks($id: ID!, $endCursor: String) { \
             node(id: $id) { ... on PullRequest { \
             statusCheckRollup: commits(last: 1) { nodes { commit { statusCheckRollup { \
             contexts(first: 100, after: $endCursor) { nodes { __typename \
             ... on StatusContext { context state targetUrl createdAt description isRequired(pullRequestId: $id) } \
             ... on CheckRun { name checkSuite { workflowRun { workflow { name } } } status conclusion \
             startedAt completedAt detailsUrl isRequired(pullRequestId: $id) } } \
             pageInfo { hasNextPage endCursor } } } } } } } } }",
            json!({"id": "PR_kwDOExample", "endCursor": "cursor"}),
        );
        assert_eq!(
            classify_graphql(&status_checks),
            Ok(GithubCliGraphqlOperation::StatusChecks)
        );

        let arbitrary_node = request(
            "query PullRequestStatusChecks($id: ID!) { \
             node(id: $id) { ... on User { login email } } }",
            json!({"id": "U_kwDOExample"}),
        );
        assert_eq!(
            classify_graphql(&arbitrary_node),
            Err(GraphqlRequestError::InvalidStatusCheckQuery)
        );
    }

    #[test]
    fn classifies_bounded_pr_authoring_mutations() {
        let cases = [
            (
                "mutation PullRequestUpdate($input: UpdatePullRequestInput!) { \
                 updatePullRequest(input: $input) { pullRequest { id } } }",
                json!({"input": {
                    "pullRequestId": "PR_kwDOExample",
                    "title": "Updated title",
                    "body": "Updated body"
                }}),
                GithubCliGraphqlOperation::UpdatePullRequest,
            ),
            (
                "mutation PullRequestReadyForReview($input: MarkPullRequestReadyForReviewInput!) { \
                 markPullRequestReadyForReview(input: $input) { pullRequest { id } } }",
                json!({"input": {"pullRequestId": "PR_kwDOExample"}}),
                GithubCliGraphqlOperation::MarkPullRequestReady,
            ),
            (
                "mutation CommentCreate($input: AddCommentInput!) { \
                 addComment(input: $input) { commentEdge { node { url } } } }",
                json!({"input": {
                    "subjectId": "PR_kwDOExample",
                    "body": "Review follow-up"
                }}),
                GithubCliGraphqlOperation::CreateComment,
            ),
        ];

        for (query, variables, operation) in cases {
            assert_eq!(classify_graphql(&request(query, variables)), Ok(operation));
        }
    }

    #[test]
    fn rejects_governance_and_destructive_mutations() {
        for (field, input_type, input) in [
            (
                "closePullRequest",
                "ClosePullRequestInput",
                json!({"pullRequestId": "PR_kwDOExample"}),
            ),
            (
                "mergePullRequest",
                "MergePullRequestInput",
                json!({"pullRequestId": "PR_kwDOExample", "mergeMethod": "SQUASH"}),
            ),
            (
                "disablePullRequestAutoMerge",
                "DisablePullRequestAutoMergeInput",
                json!({"pullRequestId": "PR_kwDOExample"}),
            ),
            (
                "unresolveReviewThread",
                "UnresolveReviewThreadInput",
                json!({"threadId": "PRRT_kwDOExample"}),
            ),
            (
                "addPullRequestReview",
                "AddPullRequestReviewInput",
                json!({"pullRequestId": "PR_kwDOExample", "event": "APPROVE"}),
            ),
            (
                "deleteIssueComment",
                "DeleteIssueCommentInput",
                json!({"id": "IC_kwDOExample"}),
            ),
        ] {
            let query = format!(
                "mutation Blocked($input: {input_type}!) {{ \
                 {field}(input: $input) {{ clientMutationId }} }}"
            );
            assert_eq!(
                classify_graphql(&request(&query, json!({"input": input}))),
                Err(GraphqlRequestError::UnsupportedOperation),
                "{field}"
            );
        }

        let base_change = request(
            "mutation PullRequestUpdate($input: UpdatePullRequestInput!) { \
             updatePullRequest(input: $input) { pullRequest { id } } }",
            json!({"input": {
                "pullRequestId": "PR_kwDOExample",
                "baseRefName": "release"
            }}),
        );
        assert_eq!(
            classify_graphql(&base_change),
            Err(GraphqlRequestError::InvalidPullRequestUpdate)
        );
    }

    #[test]
    fn rejects_unbounded_pull_request_mutations() {
        let missing_repository_id = request(
            "mutation PullRequestCreate($input: CreatePullRequestInput!) { \
             createPullRequest(input: $input) { pullRequest { id } } }",
            json!({"input": {"title": "missing repo"}}),
        );
        assert_eq!(
            classify_graphql(&missing_repository_id),
            Err(GraphqlRequestError::InvalidPullRequestCreate)
        );

        let extra_root_field = request(
            "mutation PullRequestCreate($input: CreatePullRequestInput!, $id: ID!) { \
             createPullRequest(input: $input) { pullRequest { id } } \
             closeIssue(input: {issueId: $id}) { issue { id } } }",
            json!({"input": {"repositoryId": "R_kgDOExample"}, "id": "I_kgDOExample"}),
        );
        assert_eq!(
            classify_graphql(&extra_root_field),
            Err(GraphqlRequestError::UnsupportedOperation)
        );
    }

    #[test]
    fn rewrites_only_well_formed_enterprise_prefix() {
        assert_eq!(rest_upstream_path("/api/v3/repos/o/r"), Some("/repos/o/r"));
        assert_eq!(rest_upstream_path("/api/v3"), Some("/"));
        assert_eq!(rest_upstream_path("/api/v30/repos/o/r"), None);
    }

    #[test]
    fn classifies_only_bounded_repository_rest_writes() {
        for (method, path, operation) in [
            (
                "POST",
                "/api/v3/repos/example-org/example-repo/labels",
                GithubCliRestOperation::CreateLabel,
            ),
            (
                "POST",
                "/repos/example-org/example-repo/labels",
                GithubCliRestOperation::CreateLabel,
            ),
            (
                "PATCH",
                "/api/v3/repos/example-org/example-repo/labels/auto-merge-allowed",
                GithubCliRestOperation::UpdateLabel,
            ),
            (
                "PATCH",
                "/repos/example-org/example-repo/labels/area%2Fplatform",
                GithubCliRestOperation::UpdateLabel,
            ),
            (
                "POST",
                "/api/v3/repos/example-org/example-repo/issues/42/comments",
                GithubCliRestOperation::CreateIssueComment,
            ),
            (
                "POST",
                "/api/v3/repos/example-org/example-repo/pulls/42/comments/99/replies",
                GithubCliRestOperation::ReplyReviewComment,
            ),
        ] {
            assert_eq!(classify_rest_request(method, path), Ok(operation));
        }

        for (method, path) in [
            ("PUT", "/api/v3/repos/example-org/example-repo/labels/name"),
            (
                "DELETE",
                "/api/v3/repos/example-org/example-repo/labels/name",
            ),
            ("PATCH", "/api/v3/repos/example-org/example-repo/labels"),
            ("POST", "/api/v3/repos/example-org/example-repo/labels/name"),
            ("POST", "/api/v3/repos/example-org/example-repo/issues"),
            ("POST", "/api/v3/repos/example-org/example-repo/labels/"),
            (
                "POST",
                "/api/v3/repos/example-org/example-repo/issues/0/comments",
            ),
            (
                "POST",
                "/api/v3/repos/example-org/example-repo/pulls/42/comments/99",
            ),
            (
                "POST",
                "/api/v3/repos/example-org/example-repo/actions/workflows/ci.yml/dispatches",
            ),
        ] {
            assert_eq!(
                classify_rest_request(method, path),
                Err(RestRequestError::Unsupported),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn validates_bounded_rest_write_bodies() {
        for (operation, body) in [
            (
                GithubCliRestOperation::CreateLabel,
                json!({"name": "ready", "color": "1f883d", "description": "Ready"}),
            ),
            (
                GithubCliRestOperation::UpdateLabel,
                json!({"color": "1F883D", "description": "Updated"}),
            ),
            (
                GithubCliRestOperation::CreateIssueComment,
                json!({"body": "Top-level response"}),
            ),
            (
                GithubCliRestOperation::ReplyReviewComment,
                json!({"body": "Fixed in abc123"}),
            ),
        ] {
            assert_eq!(
                validate_rest_body(operation, &serde_json::to_vec(&body).unwrap()),
                Ok(())
            );
        }

        for (operation, body) in [
            (
                GithubCliRestOperation::UpdateLabel,
                json!({"new_name": "renamed"}),
            ),
            (
                GithubCliRestOperation::CreateIssueComment,
                json!({"body": "comment", "extra": true}),
            ),
            (
                GithubCliRestOperation::ReplyReviewComment,
                json!({"body": ""}),
            ),
        ] {
            assert_eq!(
                validate_rest_body(operation, &serde_json::to_vec(&body).unwrap()),
                Err(RestRequestError::InvalidBody)
            );
        }
    }
    const HEAD_OID: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn classifies_review_draft_and_merge_mutations() {
        let cases = [
            (
                "mutation ResolveReviewThread($input: ResolveReviewThreadInput!) { \
                 resolveReviewThread(input: $input) { thread { id isResolved } } }",
                json!({"input": {"threadId": "PRRT_kwDOExample"}}),
                GithubCliGraphqlOperation::ResolveReviewThread,
            ),
            (
                "mutation ConvertToDraft($input: ConvertPullRequestToDraftInput!) { \
                 convertPullRequestToDraft(input: $input) { pullRequest { id } } }",
                json!({"input": {"pullRequestId": "PR_kwDOExample"}}),
                GithubCliGraphqlOperation::ConvertPullRequestToDraft,
            ),
            // `gh pr merge --auto --match-head-commit` on a merge-queue branch
            // omits the merge method.
            (
                "mutation PullRequestAutoMerge($input: EnablePullRequestAutoMergeInput!) { \
                 enablePullRequestAutoMerge(input: $input) { clientMutationId } }",
                json!({"input": {"pullRequestId": "PR_kwDOExample", "expectedHeadOid": HEAD_OID}}),
                GithubCliGraphqlOperation::EnableAutoMerge,
            ),
            (
                "mutation PullRequestAutoMerge($input: EnablePullRequestAutoMergeInput!) { \
                 enablePullRequestAutoMerge(input: $input) { clientMutationId } }",
                json!({"input": {
                    "pullRequestId": "PR_kwDOExample",
                    "expectedHeadOid": HEAD_OID,
                    "mergeMethod": "SQUASH",
                    "commitHeadline": "Land it",
                    "commitBody": ""
                }}),
                GithubCliGraphqlOperation::EnableAutoMerge,
            ),
            (
                "mutation Enqueue($input: EnqueuePullRequestInput!) { \
                 enqueuePullRequest(input: $input) { mergeQueueEntry { id } } }",
                json!({"input": {"pullRequestId": "PR_kwDOExample", "expectedHeadOid": HEAD_OID}}),
                GithubCliGraphqlOperation::EnqueuePullRequest,
            ),
        ];
        for (query, variables, operation) in cases {
            assert_eq!(classify_graphql(&request(query, variables)), Ok(operation));
        }
    }

    #[test]
    fn rejects_unpinned_or_widened_merge_mutations() {
        let auto_merge = "mutation PullRequestAutoMerge($input: EnablePullRequestAutoMergeInput!) { \
                          enablePullRequestAutoMerge(input: $input) { clientMutationId } }";
        let enqueue = "mutation Enqueue($input: EnqueuePullRequestInput!) { \
                       enqueuePullRequest(input: $input) { mergeQueueEntry { id } } }";
        for (query, input) in [
            (
                auto_merge,
                json!({"pullRequestId": "PR_kwDOExample", "mergeMethod": "SQUASH"}),
            ),
            (
                auto_merge,
                json!({"pullRequestId": "PR_kwDOExample", "expectedHeadOid": "abc123"}),
            ),
            (
                auto_merge,
                json!({
                    "pullRequestId": "PR_kwDOExample",
                    "expectedHeadOid": HEAD_OID,
                    "mergeMethod": "FAST_FORWARD"
                }),
            ),
            (
                auto_merge,
                json!({
                    "pullRequestId": "PR_kwDOExample",
                    "expectedHeadOid": HEAD_OID,
                    "authorEmail": "someone@example.com"
                }),
            ),
            (enqueue, json!({"pullRequestId": "PR_kwDOExample"})),
            (
                enqueue,
                json!({"pullRequestId": "PR_kwDOExample", "expectedHeadOid": HEAD_OID, "jump": true}),
            ),
        ] {
            assert_eq!(
                classify_graphql(&request(query, json!({"input": input}))),
                Err(GraphqlRequestError::InvalidMergeMutation),
                "{input}"
            );
        }

        let thread_extra = request(
            "mutation ResolveReviewThread($input: ResolveReviewThreadInput!) { \
             resolveReviewThread(input: $input) { thread { id } } }",
            json!({"input": {"threadId": "PRRT_kwDOExample", "clientMutationId": "x"}}),
        );
        assert_eq!(
            classify_graphql(&thread_extra),
            Err(GraphqlRequestError::InvalidReviewThreadMutation)
        );
    }

    #[test]
    fn accepts_gh_pr_create_label_metadata_update() {
        let query = "mutation PullRequestCreateMetadata($input: UpdatePullRequestInput!) { \
                     updatePullRequest(input: $input) { clientMutationId } }";
        assert_eq!(
            classify_graphql(&request(
                query,
                json!({"input": {"pullRequestId": "PR_kwDOExample", "labelIds": ["LA_kwDOOne"]}}),
            )),
            Ok(GithubCliGraphqlOperation::UpdatePullRequest)
        );
        for input in [
            json!({"pullRequestId": "PR_kwDOExample", "labelIds": []}),
            json!({"pullRequestId": "PR_kwDOExample", "labelIds": ["LA_kwDOOne"], "assigneeIds": ["U_x"]}),
            json!({"pullRequestId": "PR_kwDOExample"}),
        ] {
            assert_eq!(
                classify_graphql(&request(query, json!({"input": input}))),
                Err(GraphqlRequestError::InvalidPullRequestUpdate),
                "{input}"
            );
        }
    }

    #[test]
    fn classifies_only_the_bare_viewer_login_query() {
        for query in [
            "query UserCurrent { viewer { login } }",
            "query { viewer { login } }",
            "{ viewer { login } }",
        ] {
            assert_eq!(
                classify_graphql(&request(query, json!({}))),
                Ok(GithubCliGraphqlOperation::Viewer),
                "{query}"
            );
        }
        for query in [
            "query UserCurrent { viewer { login email } }",
            "query UserCurrent { me: viewer { login } }",
            "query UserCurrent { viewer { login: email } }",
            "{ viewer { repositories(first: 10) { nodes { name } } } }",
        ] {
            assert_ne!(
                classify_graphql(&request(query, json!({}))),
                Ok(GithubCliGraphqlOperation::Viewer),
                "{query}"
            );
        }
    }

    #[test]
    fn binds_search_to_a_single_repo_qualifier() {
        let resource = Resource {
            owner: "example-org".into(),
            repo: "example-repo".into(),
        };
        for q in [
            "repo:example-org/example-repo is:pr is:open",
            "is:pr label:\"needs review\" REPO:example-org/example-repo author:pitsandbox[bot]",
            "fix flaky \"org:other\" repo:example-org/example-repo",
        ] {
            assert_eq!(search_query_repository(q), Some(resource.clone()), "{q}");
        }
        for q in [
            "is:pr is:open",
            "repo:example-org/example-repo repo:example-org/other",
            "repo:example-org/example-repo OR repo:example-org/other",
            "repo:example-org/example-repo org:other",
            "-repo:example-org/example-repo",
            "repo:example-org/example-repo user:someone",
            "(repo:example-org/example-repo) is:pr",
            "repo:example-org",
            "repo:example-org/example-repo \"unterminated",
        ] {
            assert_eq!(search_query_repository(q), None, "{q}");
        }
    }

    #[test]
    fn classifies_gh_pr_list_search_query() {
        let query = "fragment pr on PullRequest{number title} \
                     query PullRequestSearch($q: String!, $type: SearchType!, $limit: Int!, $endCursor: String) { \
                     search(query: $q, type: $type, first: $limit, after: $endCursor) { \
                     issueCount nodes { ...pr } pageInfo { hasNextPage endCursor } } }";
        assert_eq!(
            classify_graphql(&request(
                query,
                json!({
                    "q": "is:pr label:ready repo:example-org/example-repo",
                    "type": "ISSUE",
                    "limit": 30,
                    "endCursor": null
                }),
            )),
            Ok(GithubCliGraphqlOperation::Search(Resource {
                owner: "example-org".into(),
                repo: "example-repo".into()
            }))
        );
        for variables in [
            json!({"q": "is:pr label:ready", "type": "ISSUE", "limit": 30}),
            json!({"q": "repo:example-org/example-repo", "type": "REPOSITORY", "limit": 30}),
        ] {
            assert_eq!(
                classify_graphql(&request(query, variables)),
                Err(GraphqlRequestError::InvalidSearch)
            );
        }
    }

    #[test]
    fn binds_rest_issue_search() {
        assert_eq!(
            rest_search_repository(
                "/api/v3/search/issues",
                Some("q=repo%3Aexample-org%2Fexample-repo+is%3Apr&per_page=100"),
            ),
            Some(Ok(Resource {
                owner: "example-org".into(),
                repo: "example-repo".into()
            }))
        );
        assert_eq!(
            rest_search_repository("/api/v3/search/issues", Some("q=is%3Apr")),
            Some(Err(GraphqlRequestError::InvalidSearch))
        );
        assert_eq!(
            rest_search_repository(
                "/api/v3/search/issues",
                Some("q=repo%3Aexample-org%2Fexample-repo&q=org%3Aother"),
            ),
            Some(Err(GraphqlRequestError::InvalidSearch))
        );
        assert_eq!(
            rest_search_repository("/api/v3/repos/o/r/pulls", None),
            None
        );
    }

    #[test]
    fn classifies_bounded_issue_label_rest_writes() {
        assert_eq!(
            classify_rest_request(
                "POST",
                "/api/v3/repos/example-org/example-repo/issues/42/labels"
            ),
            Ok(GithubCliRestOperation::AddIssueLabels)
        );
        assert_eq!(
            classify_rest_request(
                "DELETE",
                "/api/v3/repos/example-org/example-repo/issues/42/labels/preview%3Aweb"
            ),
            Ok(GithubCliRestOperation::RemoveIssueLabel)
        );
        assert!(!GithubCliRestOperation::RemoveIssueLabel.requires_body());
        for (method, path) in [
            (
                "PUT",
                "/api/v3/repos/example-org/example-repo/issues/42/labels",
            ),
            (
                "DELETE",
                "/api/v3/repos/example-org/example-repo/issues/42/labels",
            ),
            (
                "DELETE",
                "/api/v3/repos/example-org/example-repo/labels/name",
            ),
        ] {
            assert_eq!(
                classify_rest_request(method, path),
                Err(RestRequestError::Unsupported),
                "{method} {path}"
            );
        }
        let valid = serde_json::to_vec(&json!({"labels": ["review:claude"]})).unwrap();
        assert_eq!(
            validate_rest_body(GithubCliRestOperation::AddIssueLabels, &valid),
            Ok(())
        );
        for body in [
            json!(["review:claude"]),
            json!({"labels": []}),
            json!({"labels": [""]}),
            json!({"labels": ["x"], "extra": 1}),
        ] {
            assert_eq!(
                validate_rest_body(
                    GithubCliRestOperation::AddIssueLabels,
                    &serde_json::to_vec(&body).unwrap()
                ),
                Err(RestRequestError::InvalidBody),
                "{body}"
            );
        }
    }

    #[test]
    fn rewrites_pagination_links_to_the_trust_host() {
        let link = "<https://api.github.com/repositories/1300192/issues/42/comments?per_page=100&page=2>; rel=\"next\", \
                    <https://api.github.com/repositories/1300192/issues/42/comments?per_page=100&page=5>; rel=\"last\"";
        assert_eq!(
            rewrite_link_header(
                link,
                "https://api.github.com",
                "https://github-cli.proxy.internal",
                "/api/v3/repos/example-org/example-repo/issues/42/comments",
                "/repos/example-org/example-repo/issues/42/comments",
            ),
            "<https://github-cli.proxy.internal/api/v3/repos/example-org/example-repo/issues/42/comments?per_page=100&page=2>; rel=\"next\", \
             <https://github-cli.proxy.internal/api/v3/repos/example-org/example-repo/issues/42/comments?per_page=100&page=5>; rel=\"last\""
        );

        assert_eq!(
            rewrite_link_header(
                "<https://api.github.com/search/issues?q=repo%3Ao%2Fr&page=2>; rel=\"next\"",
                "https://api.github.com",
                "http://gh.test:8080",
                "/search/issues",
                "/search/issues",
            ),
            "<http://gh.test:8080/search/issues?q=repo%3Ao%2Fr&page=2>; rel=\"next\""
        );

        // Different tails and foreign hosts are not mapped to the request repo.
        assert_eq!(
            rewrite_link_header(
                "<https://api.github.com/repositories/1/pulls?page=2>; rel=\"next\", <https://evil.example/x>; rel=\"x\"",
                "https://api.github.com",
                "https://trust",
                "/api/v3/repos/o/r/issues",
                "/repos/o/r/issues",
            ),
            "<https://trust/api/v3/repositories/1/pulls?page=2>; rel=\"next\", <https://evil.example/x>; rel=\"x\""
        );
        // `https://api.github.com.evil` must not match the origin prefix.
        assert_eq!(
            rewrite_link_header(
                "<https://api.github.com.evil/x>; rel=\"next\"",
                "https://api.github.com",
                "https://trust",
                "/api/v3/x",
                "/x",
            ),
            "<https://api.github.com.evil/x>; rel=\"next\""
        );
    }

    #[test]
    fn labels_graphql_operations_without_variables() {
        assert_eq!(
            graphql_operation_label(&request(
                "mutation ResolveReviewThread($input: ResolveReviewThreadInput!) { \
                 resolveReviewThread(input: $input) { thread { id } } }",
                json!({"input": {"threadId": "secret-ish"}}),
            ))
            .as_deref(),
            Some("mutation ResolveReviewThread/resolveReviewThread")
        );
        assert_eq!(
            graphql_operation_label(&request("{ viewer { login } }", json!({}))).as_deref(),
            Some("query <anonymous>/viewer")
        );
        assert_eq!(graphql_operation_label(b"not json"), None);
    }
}
