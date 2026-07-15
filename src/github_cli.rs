use graphql_parser::query::{Definition, OperationDefinition, Selection, Value, parse_query};
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
    #[error("exactly one named query operation is required")]
    UnsupportedOperation,
    #[error("GraphQL query must be rooted exclusively at one repository")]
    UnscopedQuery,
    #[error("GraphQL variables do not identify one safe repository")]
    InvalidRepository,
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

/// Extract and validate the sole repository selected by a GitHub CLI GraphQL
/// request. Only query operations whose root fields are all `repository(...)`
/// are accepted. Mutations, global queries, node lookups, search, and root
/// fragment indirection fail closed.
pub fn repository_from_graphql(body: &[u8]) -> Result<Resource, GraphqlRequestError> {
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
    let [OperationDefinition::Query(query)] = operations.as_slice() else {
        return Err(GraphqlRequestError::UnsupportedOperation);
    };
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

        let owner = variable_string(&request.variables, owner_variable)
            .ok_or(GraphqlRequestError::InvalidRepository)?;
        let repo = variable_string(&request.variables, repo_variable)
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
            json!({"owner": "pitorg", "name": "pit-ts"}),
        );
        assert_eq!(
            repository_from_graphql(&body).unwrap(),
            Resource {
                owner: "pitorg".into(),
                repo: "pit-ts".into()
            }
        );
    }

    #[test]
    fn extracts_gh_pr_and_issue_shape_using_repo_variable() {
        let body = request(
            "query PullRequestList($owner: String!, $repo: String!) { \
             repository(owner: $owner, name: $repo) { pullRequests(first: 10) { totalCount } } }",
            json!({"owner": "pitorg", "repo": "pit-ts"}),
        );
        assert_eq!(repository_from_graphql(&body).unwrap().repo, "pit-ts");
    }

    #[test]
    fn rejects_global_or_ambiguous_queries() {
        let global = request(
            "query Viewer { viewer { login } }",
            json!({"owner": "pitorg", "repo": "pit-ts"}),
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
            json!({"owner": "pitorg", "name": "pit-ts"}),
        );
        assert_eq!(
            repository_from_graphql(&multiple),
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
