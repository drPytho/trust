# GitHub: gh CLI and git-cache

Trust supports repository-scoped GitHub access two ways: an API upstream with
`github-cli-repo` resource extraction (for `gh` and REST/GraphQL calls), and a
`git-cache` upstream (for `git clone`/`fetch`/`push`). Both use dynamic GitHub
App installation tokens minted per-repository — no PAT ever reaches a client.

## GitHub CLI without CONNECT

Configure the API upstream with `resource = { kind = "github-cli-repo" }`,
then point `gh` at its reverse-proxy hostname. Because `gh` treats a custom
host as GitHub Enterprise, trust rewrites `/api/v3/...` to GitHub.com's REST
paths and `/api/graphql` to `/graphql`. `GH_ENTERPRISE_TOKEN` carries the
trust JWT, not a GitHub token:

```bash
export GH_HOST=github-cli.proxy.internal
export GH_ENTERPRISE_TOKEN="$JWT"
export GH_REPO=github-cli.proxy.internal/example-org/example-repo
export SSL_CERT_FILE=/var/run/trust/server/ca.crt   # or install the CA system-wide

gh repo view "$GH_REPO"
gh api repos/example-org/example-repo/pulls
gh pr create --repo "$GH_REPO" --base main --head agent-branch --title "Scoped PR"
```

The GitHub App installation token must request at least `contents: read`,
`pull_requests: write`, `issues: write`, `actions: read`, `checks: read`, and
`statuses: read` for the full capability set below. Auto-merge and the merge
queue also need `contents: write`. Trust can only narrow the permissions
already granted to the installed App.

The CLI sends `Authorization: token <JWT>`; that scheme is accepted only by
`github-cli-repo` mode. Trust validates the JWT, derives the exact repository,
mints/caches an installation token restricted to that repository, replaces the
client header, and forwards.

What is allowed, and what fails closed:

- **REST reads**: repository paths use `GET`/`HEAD`, including Actions run,
  job, and log inspection used by `gh run list`, `gh run view`, and related CI
  diagnostics. GitHub normally redirects a log download to a public signed
  URL; a network-restricted sandbox must also route that follow-up request
  through Trust's forward proxy using an explicitly allowed destination or
  the temporary `outbound-audit` discovery scope.
- **Pagination**: Trust rewrites each upstream URL in a REST `Link` header to
  the Trust host the client used, so `gh api --paginate` and other clients
  follow page 2 and later through Trust. GitHub's `/repositories/{id}/...`
  link form is mapped back to the request's `/repos/{owner}/{repo}/...` path
  so the next page binds to the same repository.
- **REST writes**: only label creation/update, adding labels to or removing
  one label from an issue or pull request, top-level issue or pull-request
  comments, and replies to inline pull-request review comments are accepted.
  JSON bodies have operation-specific key and value validation. Label updates
  may change only color and description; renaming or deleting labels is not
  allowed.
- **Search**: `GET /search/issues` (`gh search prs/issues`) and the GraphQL
  `search(type: ISSUE)` query used by `gh pr list --search/--label/--author`.
  The query string must contain exactly one `repo:owner/name` qualifier, which
  binds the request to that repository's scope. `org:`, `user:`, `owner:`,
  negated `repo:`, `OR`, and parentheses are rejected because they could widen
  results beyond the repository.
- **Identity**: `GET /api/v3/user` and `viewer { login }` are answered
  locally from `github_app.bot` (see
  [CONFIGURATION.md](CONFIGURATION.md#github-app-credentials)), because GitHub
  refuses them to installation tokens. They require a `github-cli` grant and
  are refused when no bot is configured.
- **GraphQL reads**: named queries whose root fields all select the same
  repository through variables, plus the exact status-check query used by
  `gh pr checks`.
- **GraphQL writes**: `createPullRequest`, adding/removing labels, updating
  a pull request's title, body, or labels, marking a draft ready for review,
  converting a pull request back to draft, adding a discussion comment, and
  resolving a review thread. These operations carry opaque node IDs, so
  trust requires exactly one exact `github-cli:owner/repo` scope and uses it
  to obtain a repository-restricted installation token; GitHub rejects node
  IDs from any other repository.
- **Auto-merge and merge queue**: `enablePullRequestAutoMerge` and
  `enqueuePullRequest`, with the same single-repository binding. Both must pin
  `expectedHeadOid` to a full commit SHA, so GitHub only merges the exact
  commit the agent checked (`gh pr merge --auto --match-head-commit <sha>`).
  Commit author overrides and queue jumping are rejected. A direct
  `mergePullRequest` is still denied. On a branch without a merge queue, `gh
  pr merge --auto` sends a direct merge when the pull request is already
  mergeable, so that case fails.
- **Enterprise probes**: `gh` runs feature detection against a custom host;
  trust answers only the exact static `/api/v3/meta`, `Issue_fields`,
  `PullRequest_fields`, and `PullRequest_fields2` probes locally, after the
  same exact-scope check. `PullRequest_fields` advertises `isInMergeQueue` so
  `gh pr merge` uses its merge-queue path.
- **Everything else**: direct merge, disabling auto-merge, approvals,
  closing/reopening, unresolving review threads, changing a pull request's
  base branch, workflow dispatch/rerun/cancel, comment or label deletion,
  branch/repository administration, other mutations or REST writes, global
  queries, generic node lookups, unbound search, multiple operations, and
  bodies over 64 KiB are denied. Rejection logs include the method, path,
  deny reason, and the GraphQL operation name and root field (never
  variables).

This supports the routine sandbox workflow: inspect repository and CI state,
create or update a pull request, mark it ready or move it back to draft,
create and apply labels, post and resolve review follow-ups, and land a
pinned commit through auto-merge or the merge queue. Other repository
governance stays outside the sandbox.

## Routing gh's git subprocess

`gh repo clone` and `gh pr checkout` invoke `git` after their API query.
Route the child process to the git-cache hostname and give the JWT both the
`github-cli:owner/repo` and `github-git:owner/repo` scopes:

```bash
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=url.https://git.proxy.internal/.insteadOf
export GIT_CONFIG_VALUE_0=https://github-cli.proxy.internal/
export GIT_CONFIG_KEY_1=http.https://git.proxy.internal/.extraHeader
export GIT_CONFIG_VALUE_1="Authorization: Bearer $JWT"
export GIT_SSL_CAINFO=/var/run/trust/server/ca.crt

gh repo clone example-org/example-repo
```

## git-cache behaviour

```bash
# clone/fetch: served from a local bare mirror, refs always fresh
git -c http.extraHeader="Authorization: Bearer $JWT" \
  clone https://git.proxy.internal/example-org/example-repo.git

# push: passed through to the origin
git -c http.extraHeader="Authorization: Bearer $JWT" \
  push https://git.proxy.internal/example-org/example-repo.git HEAD:main
```

- **Clone / fetch:** trust serves objects from a local bare mirror. Every read
  triggers an incremental `git fetch` from the origin (no TTL — refs are
  always current); concurrent reads of the same repo share a single in-flight
  fetch. Objects already mirrored are served without hitting the origin.
- **Push:** passthrough — trust injects the upstream credential and forwards
  to the real origin. The mirror re-syncs in the background after a
  successful push.
- **Auth:** same JWT flow as `api` upstreams, with `git-repo` resource
  extraction; the client's `Authorization` is stripped and the upstream
  credential injected.
- **Requirement:** `git` must be installed where trust runs
  (`git http-backend` serves reads; `git fetch` syncs the mirror). The child
  processes run with a cleared environment and fixed argument vectors, so
  credentials never pass through a shell or the process environment.
- **Storage:** mirrors live under `git.storage_path` and are disposable (refs
  are re-fetched on every read), but a cold cache re-clones each repo on first
  use. On Kubernetes, back the path with a PersistentVolumeClaim — see
  [examples/kubernetes/README.md](../examples/kubernetes/README.md#persistent-storage-for-the-git-cache)
  for the PVC, the `strategy: Recreate` requirement with ReadWriteOnce, and
  why replicas must not share one volume.
