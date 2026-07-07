use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::Mutex as AsyncMutex;

use super::mirror::GitError;

// ---------------------------------------------------------------------------
// Fetch function type alias
// ---------------------------------------------------------------------------

/// A boxed async function that performs the actual git fetch.
///
/// SECURITY: The `auth_header` passed to this function must never appear in
/// logs or error messages. The function is responsible for that invariant.
type FetchFn = Arc<
    dyn Fn(
            String,  // key (for error context only, not auth)
            PathBuf, // git_dir
            String,  // auth_header — MUST NOT be logged
        ) -> Pin<Box<dyn Future<Output = Result<(), GitError>> + Send>>
        + Send
        + Sync,
>;

// ---------------------------------------------------------------------------
// In-flight entry
// ---------------------------------------------------------------------------

/// Shared state for a single in-flight fetch.
///
/// - `lock`: async mutex held by the leader for the duration of the fetch;
///   waiters block on acquiring it.
/// - `outcome`: written by the leader (before releasing `lock`) to convey
///   success or failure to waiters.  `None` while the fetch is still running.
struct InFlight {
    lock: AsyncMutex<()>,
    /// Stores `Some(Ok(()))` or `Some(Err(<display string>))` after the leader
    /// finishes.  Protected by std Mutex so it can be set without an `.await`.
    outcome: Mutex<Option<Result<(), String>>>,
}

impl InFlight {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            lock: AsyncMutex::new(()),
            outcome: Mutex::new(None),
        })
    }
}

// ---------------------------------------------------------------------------
// SyncManager
// ---------------------------------------------------------------------------

/// Manages incremental `git fetch` syncs for bare mirror repositories.
///
/// **Single-flight by key:** concurrent callers with the same key share one
/// in-flight fetch.  Once one fetch is running for a key, all other callers
/// for that key wait for it to finish and then propagate the leader's result.
/// Different keys run concurrently.
///
/// SECURITY: `auth_header` is never written to logs or included in any error
/// variant.  All error variants carry only the key or path, never credentials.
pub struct SyncManager {
    /// Per-key in-flight entries.  An entry is present while a fetch is
    /// in-flight.  Using `Weak` allows entries to be garbage-collected after
    /// the fetch completes and all waiters have finished.
    in_flight: Mutex<HashMap<String, Weak<InFlight>>>,

    /// The actual fetch implementation.  Swappable in tests.
    fetch_fn: FetchFn,
}

impl SyncManager {
    /// Create a `SyncManager` that runs real `git fetch --prune origin`.
    pub fn new() -> Self {
        Self::with_fetch_fn(real_git_fetch)
    }

    /// Create a `SyncManager` with a custom fetch function.  Used in tests to
    /// inject a counter or stub without invoking real git.
    pub fn with_fetch_fn<F, Fut>(f: F) -> Self
    where
        F: Fn(String, PathBuf, String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), GitError>> + Send + 'static,
    {
        Self {
            in_flight: Mutex::new(HashMap::new()),
            fetch_fn: Arc::new(move |key, dir, auth| Box::pin(f(key, dir, auth))),
        }
    }

    /// Sync the bare mirror at `git_dir` by running an incremental fetch from
    /// `origin`.
    ///
    /// Concurrent callers for the same `key` share a single in-flight fetch.
    /// Waiters receive the leader's result: `Ok(())` if the leader succeeded,
    /// `Err(GitError::Fetch { .. })` if it failed.
    ///
    /// SECURITY: `auth_header` is passed only to `fetch_fn`; it never appears
    /// in error messages returned from this method.
    pub async fn sync(&self, key: &str, git_dir: &Path, auth_header: &str) -> Result<(), GitError> {
        // Attempt to find an existing in-flight arc, or create a new one.
        // The std::sync::Mutex guard is dropped before any .await point.
        enum Outcome {
            Leader(Arc<InFlight>),
            Waiter(Arc<InFlight>),
        }

        let outcome: Outcome = {
            let mut map = self.in_flight.lock().map_err(|_| GitError::Spawn {
                path: git_dir.to_path_buf(),
                source: std::io::Error::other("sync manager lock poisoned"),
            })?;

            if let Some(weak) = map.get(key) {
                if let Some(arc) = weak.upgrade() {
                    // In-flight fetch exists — become a waiter.
                    Outcome::Waiter(arc)
                } else {
                    // Stale entry — become the new leader.
                    let arc = InFlight::new();
                    map.insert(key.to_owned(), Arc::downgrade(&arc));
                    Outcome::Leader(arc)
                }
            } else {
                // No entry — become the leader.
                let arc = InFlight::new();
                map.insert(key.to_owned(), Arc::downgrade(&arc));
                Outcome::Leader(arc)
            }
            // MutexGuard drops here, before any .await.
        };

        match outcome {
            Outcome::Waiter(entry) => {
                // Wait for the leader's fetch to complete (leader holds the lock
                // for the duration of its fetch).
                let _guard = entry.lock.lock().await;

                // Read the outcome the leader stored before releasing the lock.
                let shared = entry
                    .outcome
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();

                match shared {
                    Some(Ok(())) => Ok(()),
                    Some(Err(msg)) => {
                        // Leader's fetch failed.  Surface as a Spawn error so
                        // the reason string (which never contains auth_header,
                        // since it comes from GitError::Display) is visible to
                        // the caller.
                        Err(GitError::Spawn {
                            path: git_dir.to_path_buf(),
                            source: std::io::Error::other(msg),
                        })
                    }
                    None => {
                        // Should not happen: leader always writes before releasing
                        // the lock.  Treat as a fetch failure to never silently Ok.
                        Err(GitError::Fetch {
                            key: key.to_owned(),
                            path: git_dir.to_path_buf(),
                            exit_code: None,
                        })
                    }
                }
            }

            Outcome::Leader(entry) => {
                // Acquire the per-key async lock so waiters block on it.
                let _guard = entry.lock.lock().await;

                // Run the actual fetch.
                let result = (self.fetch_fn)(
                    key.to_owned(),
                    git_dir.to_path_buf(),
                    auth_header.to_owned(),
                )
                .await;

                // Store the outcome for waiters BEFORE releasing the lock.
                {
                    let shared_outcome = match &result {
                        Ok(()) => Ok(()),
                        Err(e) => Err(e.to_string()),
                    };
                    // Unwrap: std Mutex poison here means a bug elsewhere; we
                    // must store before releasing or waiters get None.
                    if let Ok(mut cell) = entry.outcome.lock() {
                        *cell = Some(shared_outcome);
                    }
                }

                // Remove the in-flight entry so the Weak goes stale.
                // New callers after this point will start a fresh fetch.
                {
                    if let Ok(mut map) = self.in_flight.lock() {
                        map.remove(key);
                    }
                }

                result
            }
        }
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Real git fetch implementation
// ---------------------------------------------------------------------------

/// Run `git -c http.extraHeader=Authorization: <auth_header> --git-dir <git_dir>
/// fetch --prune origin`.
///
/// SECURITY: `auth_header` is passed as a process argument value (not
/// shell-expanded).  It never appears in any error variant returned here.
async fn real_git_fetch(
    key: String,
    git_dir: PathBuf,
    auth_header: String,
) -> Result<(), GitError> {
    // Build the header arg.  The value contains the auth secret; it is passed
    // as a process argument, never logged.
    let header_arg = format!("http.extraHeader=Authorization: {auth_header}");

    let status = tokio::process::Command::new("git")
        .args(["-c", &header_arg, "--git-dir"])
        .arg(&git_dir)
        .args(["fetch", "--prune", "origin"])
        .status()
        .await
        .map_err(|source| GitError::Spawn {
            path: git_dir.clone(),
            source,
        })?;

    if !status.success() {
        return Err(GitError::Fetch {
            key,
            path: git_dir,
            exit_code: status.code(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ── Single-flight dedup: concurrent burst ────────────────────────────────

    /// Fire N concurrent syncs for the same key.  Assert the underlying fetch
    /// ran at most 2 times (strongly deduplicated), not N independent fetches.
    /// With `yield_now` inside the fetch, the first task runs while others
    /// wait on the in-flight lock — producing 1 fetch invocation for the
    /// whole burst.
    #[tokio::test]
    async fn single_flight_deduplicates_concurrent_syncs() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let manager = Arc::new(SyncManager::with_fetch_fn(move |_key, _dir, _auth| {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                // Yield to allow other tasks to arrive while "fetch" is in
                // progress, making the single-flight guarantee observable.
                tokio::task::yield_now().await;
                Ok(())
            }
        }));

        let path = PathBuf::from("/tmp/test-mirror.git");

        const N: usize = 8;
        let mut handles = Vec::with_capacity(N);

        for _ in 0..N {
            let m = manager.clone();
            let p = path.clone();
            handles.push(tokio::spawn(async move {
                m.sync("repo-key", &p, "Bearer secret").await
            }));
        }

        for h in handles {
            let result = h.await.expect("task panicked");
            assert!(result.is_ok(), "sync returned error: {result:?}");
        }

        let invocations = counter.load(Ordering::SeqCst);
        // With single-flight: at most 2 invocations (one wave completes, then
        // late-arriving tasks may start a second).  Never 8 independent ones.
        assert!(
            invocations <= 2,
            "expected single-flight dedup (≤2 invocations), got {invocations}"
        );
    }

    // ── Single-flight dedup: deterministic two-task proof ───────────────────

    /// Deterministic test: two tasks for the same key — only one fetch.
    ///
    /// Uses a semaphore to hold the first fetch until both tasks have started,
    /// ensuring the race condition is exercised reproducibly.
    #[tokio::test]
    async fn single_flight_two_tasks_same_key_one_fetch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        // Gate: keeps the first fetch running until we open it.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let gate_clone = gate.clone();

        let manager = Arc::new(SyncManager::with_fetch_fn(move |_key, _dir, _auth| {
            let c = counter_clone.clone();
            let g = gate_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                // Block until the test opens the gate.
                let _permit = g.acquire().await.expect("semaphore closed");
                Ok(())
            }
        }));

        let path = PathBuf::from("/tmp/test-mirror.git");

        let m1 = manager.clone();
        let p1 = path.clone();
        let t1 = tokio::spawn(async move { m1.sync("same-key", &p1, "tok").await });

        // Let t1 start and register itself as the leader.
        tokio::task::yield_now().await;

        let m2 = manager.clone();
        let p2 = path.clone();
        let t2 = tokio::spawn(async move { m2.sync("same-key", &p2, "tok").await });

        // Let t2 arrive and block on the in-flight lock.
        tokio::task::yield_now().await;

        // Open the gate — t1's fetch completes, _guard drops, t2 unblocks.
        gate.add_permits(1);

        t1.await.expect("t1 panicked").expect("t1 errored");
        t2.await.expect("t2 panicked").expect("t2 errored");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "two concurrent tasks with same key must trigger exactly one fetch"
        );
    }

    // ── Different keys both execute ──────────────────────────────────────────

    /// Two tasks with different keys must each run their own fetch (no false
    /// dedup across distinct repos).
    #[tokio::test]
    async fn different_keys_both_execute() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let manager = Arc::new(SyncManager::with_fetch_fn(move |_key, _dir, _auth| {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));

        let path = PathBuf::from("/tmp/test-mirror.git");

        let m1 = manager.clone();
        let p1 = path.clone();
        let t1 = tokio::spawn(async move { m1.sync("key-A", &p1, "tok").await });

        let m2 = manager.clone();
        let p2 = path.clone();
        let t2 = tokio::spawn(async move { m2.sync("key-B", &p2, "tok").await });

        t1.await.expect("t1 panicked").expect("t1 errored");
        t2.await.expect("t2 panicked").expect("t2 errored");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "two tasks with different keys must each run their own fetch"
        );
    }

    // ── Security: auth_header must not leak into errors ──────────────────────

    #[test]
    fn fetch_error_display_does_not_contain_auth_header() {
        let err = GitError::Fetch {
            key: "github.com/owner/repo".to_owned(),
            path: PathBuf::from("/mirrors/github.com/owner/repo.git"),
            exit_code: Some(1),
        };
        let secret = "ghp_supersecrettoken";
        assert!(!format!("{err}").contains(secret));
        assert!(!format!("{err:?}").contains(secret));
    }

    // ── Default impl ─────────────────────────────────────────────────────────

    #[test]
    fn default_creates_sync_manager() {
        let _m: SyncManager = SyncManager::default();
    }

    // ── Waiter observes leader failure ───────────────────────────────────────

    /// A waiter coalesced onto a failing leader must receive `Err(...)`, not
    /// `Ok(())`.  This guards against the silent-masking bug where a waiter
    /// returns success regardless of whether the leader's fetch succeeded.
    #[tokio::test]
    async fn waiter_observes_leader_failure() {
        // Gate: holds the leader's fetch open until the waiter has joined.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let gate_clone = gate.clone();

        let manager = Arc::new(SyncManager::with_fetch_fn(move |key, dir, _auth| {
            let g = gate_clone.clone();
            async move {
                // Block until the test opens the gate — this gives the waiter
                // time to register against the in-flight entry.
                let _permit = g.acquire().await.expect("semaphore closed");
                // Leader always fails.
                Err(GitError::Fetch {
                    key,
                    path: dir,
                    exit_code: Some(128),
                })
            }
        }));

        let path = PathBuf::from("/tmp/test-mirror-fail.git");

        // Task 1: the leader — will fail.
        let m1 = manager.clone();
        let p1 = path.clone();
        let t1 = tokio::spawn(async move { m1.sync("fail-key", &p1, "tok").await });

        // Let t1 start and register as leader (acquire the async lock inside sync).
        tokio::task::yield_now().await;

        // Task 2: waiter — should join the in-flight entry.
        let m2 = manager.clone();
        let p2 = path.clone();
        let t2 = tokio::spawn(async move { m2.sync("fail-key", &p2, "tok").await });

        // Let t2 register as a waiter.
        tokio::task::yield_now().await;

        // Open the gate: leader's fetch fails, outcome is stored, lock released.
        gate.add_permits(1);

        let r1 = t1.await.expect("t1 panicked");
        let r2 = t2.await.expect("t2 panicked");

        assert!(r1.is_err(), "leader must return Err when fetch fails");
        assert!(
            r2.is_err(),
            "waiter must observe leader failure and return Err, got: {r2:?}"
        );
    }

    // ── Waiter observes leader success ───────────────────────────────────────

    /// A waiter coalesced onto a successful leader must receive `Ok(())`.
    #[tokio::test]
    async fn waiter_observes_leader_success() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let gate_clone = gate.clone();

        let manager = Arc::new(SyncManager::with_fetch_fn(move |_key, _dir, _auth| {
            let g = gate_clone.clone();
            async move {
                let _permit = g.acquire().await.expect("semaphore closed");
                Ok(())
            }
        }));

        let path = PathBuf::from("/tmp/test-mirror-ok.git");

        let m1 = manager.clone();
        let p1 = path.clone();
        let t1 = tokio::spawn(async move { m1.sync("ok-key", &p1, "tok").await });

        tokio::task::yield_now().await;

        let m2 = manager.clone();
        let p2 = path.clone();
        let t2 = tokio::spawn(async move { m2.sync("ok-key", &p2, "tok").await });

        tokio::task::yield_now().await;

        gate.add_permits(1);

        t1.await.expect("t1 panicked").expect("leader must Ok");
        t2.await
            .expect("t2 panicked")
            .expect("waiter must Ok when leader succeeds");
    }
}
