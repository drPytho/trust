use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;
use tokio::sync::Mutex as TokioMutex;

use crate::resource::safe_component;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from mirror operations.
///
/// SECURITY: `auth_header` must never appear in any variant — not in messages,
/// not in the `source` chain.  Variants may carry the clone URL (no secret) or
/// the filesystem path, but not the credential.
#[derive(Debug, Error)]
pub enum GitError {
    /// Failed to spawn the `git` subprocess.
    #[error("failed to spawn git for path {path}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `git clone --mirror` exited with a non-zero status.
    #[error("git clone --mirror failed for {clone_url} → {path} (exit: {exit_code:?})")]
    Clone {
        clone_url: String,
        path: PathBuf,
        exit_code: Option<i32>,
    },

    /// Failed to check whether the mirror path exists.
    #[error("could not stat mirror path {path}: {source}")]
    Stat {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `git fetch --prune origin` exited with a non-zero status.
    ///
    /// SECURITY: `auth_header` must never appear here — only the key and path.
    #[error("git fetch failed for {key} at {path} (exit: {exit_code:?})")]
    Fetch {
        key: String,
        path: PathBuf,
        exit_code: Option<i32>,
    },
}

// ---------------------------------------------------------------------------
// MirrorStore
// ---------------------------------------------------------------------------

/// A per-path async lock entry used to prevent concurrent double-clones of the
/// same mirror directory.  The outer `HashMap` is keyed by the canonical mirror
/// path.
///
/// Holds the bare git mirrors for all repos served by a git-cache upstream.
///
/// Layout on disk: `<root>/<upstream>/<owner>/<repo>.git`
pub struct MirrorStore {
    root: PathBuf,
    /// Per-path locks to serialise concurrent first-clones of the same mirror.
    ///
    // TODO: entries in this HashMap are never evicted — unbounded small growth
    // for a long-running proxy mirroring many distinct repos. Future cleanup:
    // evict entries whose Arc has a strong_count of 1 (no waiters) after the
    // clone succeeds, or replace with a bounded LRU.
    locks: Mutex<HashMap<PathBuf, Arc<TokioMutex<()>>>>,
}

impl MirrorStore {
    /// Create a new `MirrorStore` rooted at `root`.  The directory is created
    /// lazily (on first `ensure` call).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Return the on-disk path for a mirror.
    ///
    /// Returns `None` if **any** of the three components fails the
    /// `safe_component` check (path-traversal guard).  The caller must not
    /// pass a component that has not been validated here before using it in a
    /// filesystem operation.
    ///
    /// Path layout: `<root>/<upstream>/<owner>/<repo>.git`
    pub fn path_for(&self, upstream: &str, owner: &str, repo: &str) -> Option<PathBuf> {
        if !safe_component(upstream) || !safe_component(owner) || !safe_component(repo) {
            return None;
        }
        let mut p = self.root.clone();
        p.push(upstream);
        p.push(owner);
        p.push(format!("{repo}.git"));
        Some(p)
    }

    /// Ensure the mirror at `path` exists.
    ///
    /// * If `path` already exists on disk — no-op, returns `Ok(())`.
    /// * If `path` does not exist — runs
    ///   `git -c http.extraHeader=Authorization: <auth_header> clone --mirror <clone_url> <path>`
    ///   via `tokio::process::Command` (fixed argv, no shell).
    ///
    /// Concurrent callers for the **same path** are serialised by a per-path
    /// async mutex so that only one `git clone` ever runs for a given mirror
    /// directory.  Subsequent callers after the first succeeds find the path
    /// present and return immediately.
    ///
    /// SECURITY: `auth_header` is never written to logs or included in any
    /// error message or `Debug` output of `GitError`.
    pub async fn ensure(
        &self,
        path: &Path,
        clone_url: &str,
        auth_header: &str,
    ) -> Result<(), GitError> {
        // Initial check: does the path already exist?
        match tokio::fs::metadata(path).await {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Proceed to acquire lock and attempt clone.
            }
            Err(e) => {
                return Err(GitError::Stat {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        }

        // Grab (or create) the per-path lock.
        let lock_arc = {
            let mut map = self.locks.lock().await;
            map.entry(path.to_path_buf())
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };

        // Serialise concurrent first-clones for this exact path.
        let _guard = lock_arc.lock().await;

        // Re-check after acquiring the lock — a prior waiter may have cloned.
        match tokio::fs::metadata(path).await {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Proceed to clone.
            }
            Err(e) => {
                return Err(GitError::Stat {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        }

        // Run: git -c http.extraHeader=Authorization: <auth_header> clone --mirror <url> <path>
        // Fixed argv only; no shell expansion.
        let header_arg = format!("http.extraHeader=Authorization: {auth_header}");
        let status = tokio::process::Command::new("git")
            .args(["-c", &header_arg, "clone", "--mirror", clone_url])
            .arg(path)
            .status()
            .await
            .map_err(|source| GitError::Spawn {
                path: path.to_path_buf(),
                source,
            })?;

        if !status.success() {
            return Err(GitError::Clone {
                clone_url: clone_url.to_owned(),
                path: path.to_path_buf(),
                exit_code: status.code(),
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> MirrorStore {
        MirrorStore::new("/var/lib/trust/mirrors")
    }

    // ── path_for: happy path ─────────────────────────────────────────────────

    #[test]
    fn path_for_builds_correct_path() {
        let s = store();
        let p = s.path_for("github.com", "pitorg", "pit-ts").unwrap();
        assert_eq!(
            p,
            PathBuf::from("/var/lib/trust/mirrors/github.com/pitorg/pit-ts.git")
        );
    }

    #[test]
    fn path_for_appends_dot_git() {
        let s = store();
        let p = s.path_for("gitlab.com", "owner", "myrepo").unwrap();
        assert!(p.to_string_lossy().ends_with(".git"));
    }

    // ── path_for: unsafe upstream ────────────────────────────────────────────

    #[test]
    fn path_for_rejects_dotdot_upstream() {
        let s = store();
        assert!(s.path_for("..", "owner", "repo").is_none());
    }

    #[test]
    fn path_for_rejects_empty_upstream() {
        let s = store();
        assert!(s.path_for("", "owner", "repo").is_none());
    }

    #[test]
    fn path_for_rejects_slash_in_upstream() {
        let s = store();
        assert!(s.path_for("github.com/evil", "owner", "repo").is_none());
    }

    // ── path_for: unsafe owner ───────────────────────────────────────────────

    #[test]
    fn path_for_rejects_dotdot_owner() {
        let s = store();
        assert!(s.path_for("github.com", "..", "repo").is_none());
    }

    #[test]
    fn path_for_rejects_empty_owner() {
        let s = store();
        assert!(s.path_for("github.com", "", "repo").is_none());
    }

    #[test]
    fn path_for_rejects_slash_in_owner() {
        let s = store();
        assert!(s.path_for("github.com", "a/b", "repo").is_none());
    }

    // ── path_for: unsafe repo ────────────────────────────────────────────────

    #[test]
    fn path_for_rejects_dotdot_repo() {
        let s = store();
        assert!(s.path_for("github.com", "owner", "..").is_none());
    }

    #[test]
    fn path_for_rejects_empty_repo() {
        let s = store();
        assert!(s.path_for("github.com", "owner", "").is_none());
    }

    #[test]
    fn path_for_rejects_slash_in_repo() {
        let s = store();
        assert!(s.path_for("github.com", "owner", "a/b").is_none());
    }

    #[test]
    fn path_for_rejects_control_char_in_repo() {
        let s = store();
        assert!(s.path_for("github.com", "owner", "re\x07po").is_none());
    }

    // ── GitError: auth_header must not leak into Display/Debug ───────────────

    #[test]
    fn git_error_display_does_not_contain_auth_header() {
        let err = GitError::Clone {
            clone_url: "https://github.com/pitorg/pit-ts.git".to_owned(),
            path: PathBuf::from("/mirrors/github.com/pitorg/pit-ts.git"),
            exit_code: Some(128),
        };
        let sample_secret = "ghp_supersecrettoken";
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(!display.contains(sample_secret));
        assert!(!debug.contains(sample_secret));
    }

    #[test]
    fn git_error_spawn_display_does_not_contain_auth_header() {
        let err = GitError::Spawn {
            path: PathBuf::from("/mirrors/github.com/pitorg/pit-ts.git"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "git not found"),
        };
        let sample_secret = "ghp_supersecrettoken";
        let display = format!("{err}");
        assert!(!display.contains(sample_secret));
    }
}
