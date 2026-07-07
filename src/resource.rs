use serde::Deserialize;

use crate::scope::Resource;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    GithubRepo,
}

pub fn extract(kind: ResourceKind, path: &str) -> Option<Resource> {
    match kind {
        ResourceKind::GithubRepo => {
            // .../repos/{owner}/{repo}/...
            let mut segs = path.split('/').filter(|s| !s.is_empty());
            loop {
                match segs.next() {
                    Some("repos") => break,
                    Some(_) => continue,
                    None => return None,
                }
            }
            let owner = segs.next()?;
            let repo = segs.next()?;
            let repo = repo.strip_suffix(".git").unwrap_or(repo);
            if owner.is_empty() || repo.is_empty() {
                return None;
            }
            Some(Resource { owner: owner.to_string(), repo: repo.to_string() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_repo_from_repos_path() {
        let r = extract(ResourceKind::GithubRepo, "/repos/pitorg/pit-ts/issues").unwrap();
        assert_eq!(r.owner, "pitorg");
        assert_eq!(r.repo, "pit-ts");
    }

    #[test]
    fn github_repo_trims_dot_git() {
        let r = extract(ResourceKind::GithubRepo, "/repos/pitorg/pit-ts.git").unwrap();
        assert_eq!(r.repo, "pit-ts");
    }

    #[test]
    fn non_repo_paths_are_none() {
        assert!(extract(ResourceKind::GithubRepo, "/user").is_none());
        assert!(extract(ResourceKind::GithubRepo, "/repos/pitorg").is_none());
        assert!(extract(ResourceKind::GithubRepo, "/").is_none());
    }
}
