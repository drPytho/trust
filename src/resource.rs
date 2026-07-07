use serde::Deserialize;

use crate::scope::Resource;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    GithubRepo,
    GitRepo,
}

/// Returns `true` if `s` is a safe path component: non-empty, not `.` or `..`,
/// and contains no `/`, `\`, or NUL bytes.
///
/// Used by `extract(GitRepo, …)` and will be reused by `MirrorStore` (Task 5).
pub(crate) fn safe_component(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    !s.bytes().any(|b| b == b'/' || b == b'\\' || b == 0)
}

/// Git smart-HTTP suffixes we recognise.
const GIT_SUFFIXES: &[&str] = &["/info/refs", "/git-upload-pack", "/git-receive-pack"];

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
        assert!(!safe_component(""));      // empty
        assert!(!safe_component("."));     // current-dir
        assert!(!safe_component(".."));    // parent-dir
        assert!(!safe_component("a/b"));   // embedded slash
        assert!(!safe_component("a\\b")); // embedded backslash
        assert!(!safe_component("a\0b")); // NUL byte
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
}
