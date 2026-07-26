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

The CLI sends `Authorization: token <JWT>`; that scheme is accepted only by
`github-cli-repo` mode. Trust validates the JWT, derives the exact repository,
mints/caches an installation token restricted to that repository, replaces the
client header, and forwards.

What is allowed, and what fails closed:

- **REST**: `/repos/{owner}/{repo}/...` paths only, limited to `GET`/`HEAD`.
- **GraphQL**: named query operations whose root fields all select the same
  repository through variables, plus the single `createPullRequest` mutation
  used by basic `gh pr create`. That mutation carries an opaque repository
  node ID, so trust requires exactly one exact `github-cli:owner/repo` scope
  and uses it to obtain a repository-restricted installation token; GitHub
  rejects node IDs from any other repository.
- **Enterprise probes**: `gh` runs feature detection against a custom host;
  trust answers only the static `/api/v3/meta` and `Issue_fields` probes
  locally, after the same exact-scope check.
- **Everything else** — other mutations, REST writes, global queries, node
  lookups, search, multiple operations, bodies over 64 KiB — is denied.

This supports repository-scoped reads and basic non-interactive PR creation.
Follow-up mutations (assigning reviewers, labels, closing issues) remain
denied.

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
