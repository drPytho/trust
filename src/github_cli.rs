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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubCliRestOperation {
    Read,
    CreateLabel,
    UpdateLabel,
    CreateIssueComment,
    ReplyReviewComment,
}

impl GithubCliRestOperation {
    pub fn requires_body(self) -> bool {
        self != Self::Read
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
        _ => Err(RestRequestError::Unsupported),
    }
}

pub fn validate_rest_body(
    operation: GithubCliRestOperation,
    body: &[u8],
) -> Result<(), RestRequestError> {
    if operation == GithubCliRestOperation::Read {
        return Ok(());
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| RestRequestError::InvalidJson)?;
    let input = value.as_object().ok_or(RestRequestError::InvalidBody)?;

    match operation {
        GithubCliRestOperation::Read => Ok(()),
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
    }
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
                _ => Err(GraphqlRequestError::UnsupportedOperation),
            }
        }
        _ => Err(GraphqlRequestError::UnsupportedOperation),
    }
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
        | GithubCliGraphqlOperation::UpdateLabels => Err(GraphqlRequestError::UnsupportedOperation),
    }
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
    if input.len() < 2
        || !has_only_keys(input, &["pullRequestId", "title", "body"])
        || !input.get("pullRequestId").is_some_and(valid_node_id)
        || !input.contains_key("title") && !input.contains_key("body")
        || input.get("title").is_some_and(|value| !value.is_string())
        || input.get("body").is_some_and(|value| !value.is_string())
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
            "query Viewer { viewer { login } }",
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
                "convertPullRequestToDraft",
                "ConvertPullRequestToDraftInput",
                json!({"pullRequestId": "PR_kwDOExample"}),
            ),
            (
                "enablePullRequestAutoMerge",
                "EnablePullRequestAutoMergeInput",
                json!({"pullRequestId": "PR_kwDOExample", "mergeMethod": "SQUASH"}),
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
}
