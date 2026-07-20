use graphql_parser::query::{
    Definition, Mutation, OperationDefinition, Query, Selection, Value, parse_query,
};
use serde::Deserialize;

use crate::resource::safe_component;
use crate::scope::Resource;

// Pingora's built-in retry buffer is 64 KiB. We enable it before inspecting a
// GraphQL body so the normal proxy pipeline can replay the exact bytes.
pub const MAX_GRAPHQL_BODY_BYTES: usize = 64 * 1024;

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
}

/// A GitHub CLI GraphQL operation whose repository authority Trust can bind
/// before it exchanges the caller JWT for an installation token.
#[derive(Debug, PartialEq, Eq)]
pub enum GithubCliGraphqlOperation {
    RepositoryQuery(Resource),
    IssueFeatureDetection,
    CreatePullRequest,
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

pub fn is_graphql_path(path: &str) -> bool {
    matches!(path, "/api/graphql" | "/graphql")
}

fn variable_string<'a>(
    variables: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a str> {
    variables.get(name)?.as_str()
}

/// Classify a GitHub CLI GraphQL request. Repository-rooted queries are bound
/// from their variables. `createPullRequest` is the sole allowed mutation: its
/// opaque `repositoryId` is subsequently bound to one exact JWT scope before
/// Trust exchanges the caller JWT for a repository-restricted installation
/// token.
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
            } else {
                repository_from_query(query, &request.variables)
                    .map(GithubCliGraphqlOperation::RepositoryQuery)
            }
        }
        OperationDefinition::Mutation(mutation) => {
            validate_create_pull_request(mutation, &request.variables)?;
            Ok(GithubCliGraphqlOperation::CreatePullRequest)
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
        | GithubCliGraphqlOperation::CreatePullRequest => {
            Err(GraphqlRequestError::UnsupportedOperation)
        }
    }
}

/// GitHub CLI treats a custom `GH_HOST` as GitHub Enterprise and asks this
/// static schema question before `gh pr create`. It is safe to answer locally:
/// the response contains no account or repository data, and its empty field
/// list disables optional issue metadata features rather than enabling writes.
fn is_issue_feature_detection(query: &Query<'_, String>) -> bool {
    if query.name.as_deref() != Some("Issue_fields") || query.selection_set.items.len() != 1 {
        return false;
    }
    let [Selection::Field(type_field)] = query.selection_set.items.as_slice() else {
        return false;
    };
    if type_field.alias.as_deref() != Some("Issue")
        || type_field.name != "__type"
        || type_field.arguments.len() != 1
        || !type_field.directives.is_empty()
    {
        return false;
    }
    matches!(
        type_field.arguments.as_slice(),
        [(name, Value::String(type_name))] if name == "name" && type_name == "Issue"
    )
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
}
