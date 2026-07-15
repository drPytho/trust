use serde::Deserialize;

use crate::scope::Resource;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    GithubRepo,
    GithubCliRepo,
    GitRepo,
    ArtifactRegistryRepo,
}

/// Returns `true` if `s` is a safe path component: non-empty, not `.` or `..`,
/// and contains no `/`, `\`, control characters, or DEL.
///
/// Used by `extract(GitRepo, …)` and will be reused by `MirrorStore` (Task 5).
pub(crate) fn safe_component(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    // Reject `/`, `\`, and any control character (< 0x20) or DEL (0x7F)
    !s.bytes()
        .any(|b| b == b'/' || b == b'\\' || b < 0x20 || b == 0x7F)
}

/// Git smart-HTTP suffixes we recognise.
const GIT_SUFFIXES: &[&str] = &["/info/refs", "/git-upload-pack", "/git-receive-pack"];

pub fn extract(kind: ResourceKind, path: &str) -> Option<Resource> {
    match kind {
        ResourceKind::GithubRepo | ResourceKind::GithubCliRepo => {
            // /repos/{owner}/{repo}/...
            // GitHub CLI treats a custom GH_HOST as GitHub Enterprise and
            // prefixes REST requests with /api/v3. The explicit CLI resource
            // kind accepts both that shape and GitHub.com's native shape.
            let path = if kind == ResourceKind::GithubCliRepo {
                path.strip_prefix("/api/v3").unwrap_or(path)
            } else {
                path
            };
            let mut segs = path.split('/').filter(|s| !s.is_empty());
            if segs.next()? != "repos" {
                return None;
            }
            let owner = segs.next()?;
            let repo = segs.next()?;
            let repo = repo.strip_suffix(".git").unwrap_or(repo);
            if !safe_component(owner) || !safe_component(repo) {
                return None;
            }
            Some(Resource {
                owner: owner.to_string(),
                repo: repo.to_string(),
            })
        }

        ResourceKind::GitRepo => {
            // /{owner}/{repo}[.git]/{info/refs,git-upload-pack,git-receive-pack}
            //
            // Strip the recognised git suffix first, then take the first two
            // non-empty segments from what remains as owner/repo.
            let stripped = GIT_SUFFIXES
                .iter()
                .find_map(|suffix| path.strip_suffix(suffix))?;

            let mut segs = stripped.split('/').filter(|s| !s.is_empty());

            let owner = segs.next()?;
            let repo_raw = segs.next()?;

            // Strip optional trailing `.git` from the repo segment.
            let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);

            // Validate both components against path-traversal.
            if !safe_component(owner) || !safe_component(repo) {
                return None;
            }

            Some(Resource {
                owner: owner.to_string(),
                repo: repo.to_string(),
            })
        }

        ResourceKind::ArtifactRegistryRepo => {
            // Artifact Registry npm endpoints are rooted at /PROJECT/REPOSITORY/.
            let mut segs = path.split('/').filter(|s| !s.is_empty());
            let project = segs.next()?;
            let repository = segs.next()?;
            if !safe_component(project) || !safe_component(repository) {
                return None;
            }
            Some(Resource {
                owner: project.to_string(),
                repo: repository.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GithubRepo (existing) ────────────────────────────────────────────────

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
    fn github_cli_repo_accepts_enterprise_rest_prefix() {
        let r = extract(
            ResourceKind::GithubCliRepo,
            "/api/v3/repos/pitorg/pit-ts/pulls",
        )
        .unwrap();
        assert_eq!(r.owner, "pitorg");
        assert_eq!(r.repo, "pit-ts");
    }

    #[test]
    fn artifact_registry_repo_from_path() {
        let r = extract(
            ResourceKind::ArtifactRegistryRepo,
            "/my-project/npm-private/@scope%2fpkg",
        )
        .unwrap();
        assert_eq!(r.owner, "my-project");
        assert_eq!(r.repo, "npm-private");
    }

    #[test]
    fn non_repo_paths_are_none() {
        assert!(extract(ResourceKind::GithubRepo, "/user").is_none());
        assert!(extract(ResourceKind::GithubRepo, "/repos/pitorg").is_none());
        assert!(extract(ResourceKind::GithubRepo, "/").is_none());
    }

    // ── safe_component ───────────────────────────────────────────────────────

    #[test]
    fn safe_component_accepts_normal_names() {
        assert!(safe_component("abc"));
        assert!(safe_component("pit-ts"));
        assert!(safe_component("my.repo"));
        assert!(safe_component("owner123"));
    }

    #[test]
    fn safe_component_rejects_bad_inputs() {
        assert!(!safe_component("")); // empty
        assert!(!safe_component(".")); // current-dir
        assert!(!safe_component("..")); // parent-dir
        assert!(!safe_component("a/b")); // embedded slash
        assert!(!safe_component("a\\b")); // embedded backslash
        assert!(!safe_component("a\0b")); // NUL byte
    }

    #[test]
    fn safe_component_rejects_control_chars() {
        // Reject BEL (0x07)
        assert!(!safe_component("a\u{0007}b"));
        // Reject DEL (0x7F)
        assert!(!safe_component("a\u{007f}b"));
        // Still accept normal names
        assert!(safe_component("a-b.c"));
    }

    // ── GitRepo extraction ───────────────────────────────────────────────────

    #[test]
    fn git_repo_info_refs_with_dot_git() {
        // /pitorg/pit-ts.git/info/refs → owner=pitorg, repo=pit-ts
        let r = extract(ResourceKind::GitRepo, "/pitorg/pit-ts.git/info/refs").unwrap();
        assert_eq!(r.owner, "pitorg");
        assert_eq!(r.repo, "pit-ts");
    }

    #[test]
    fn git_repo_upload_pack_without_dot_git() {
        // /pitorg/pit-ts/git-upload-pack → owner=pitorg, repo=pit-ts
        let r = extract(ResourceKind::GitRepo, "/pitorg/pit-ts/git-upload-pack").unwrap();
        assert_eq!(r.owner, "pitorg");
        assert_eq!(r.repo, "pit-ts");
    }

    #[test]
    fn git_repo_receive_pack_with_dot_git() {
        // /o/r.git/git-receive-pack → owner=o, repo=r
        let r = extract(ResourceKind::GitRepo, "/o/r.git/git-receive-pack").unwrap();
        assert_eq!(r.owner, "o");
        assert_eq!(r.repo, "r");
    }

    #[test]
    fn git_repo_api_style_path_is_none() {
        // /repos/x/y has no git suffix → None
        assert!(extract(ResourceKind::GitRepo, "/repos/x/y").is_none());
    }

    #[test]
    fn git_repo_traversal_dotdot_is_none() {
        // /../etc/info/refs — the ".." segment must be rejected
        assert!(extract(ResourceKind::GitRepo, "/../etc/info/refs").is_none());
    }

    #[test]
    fn git_repo_missing_repo_segment_is_none() {
        // /pitorg/info/refs — only one segment before the suffix → None
        assert!(extract(ResourceKind::GitRepo, "/pitorg/info/refs").is_none());
    }

    #[test]
    fn git_repo_dot_git_stripping_yields_empty_repo() {
        // /o/.git/info/refs — after stripping .git, the repo segment becomes empty → None
        assert!(extract(ResourceKind::GitRepo, "/o/.git/info/refs").is_none());
    }
}
