# trust Phase 2 — JWT auth, mTLS token issuance, scoped authz (design)

Date: 2026-07-06
Status: Approved (design), pending implementation planning
Depends on: Phase 1 (API egress proxy) — this replaces Phase 1's static token map.

## 1. Overview

trust becomes its own **token authority**. An mTLS-gated OAuth2 `client_credentials`
endpoint mints short-lived (~7-day) asymmetric JWTs whose scopes are capped by the caller's
SPIFFE identity. The proxy path verifies those JWTs with trust's own public key and
authorizes each request by scope — including **repo-level** authorization for GitHub (git
today via the GitHub API upstream, and the Phase-3 git-cache upstream later). Signing keys
live in GCP Secret Manager with rotation; public keys are published as JWKS.

This **replaces** Phase 1's static `[[tokens]]` map with JWT-only auth. The existing api
upstreams (anthropic, mistral) plus a resource-scoped `github` API upstream prove it
end-to-end. The `git-cache` upstream kind is **out of scope** here (separate Phase-3 spec);
its authorization will reuse the scope model defined below.

### Decisions locked in

- Asymmetric JWTs (**ES256**), issued and verified by trust itself.
- Issuance API: **OAuth2 `client_credentials`** token endpoint.
- Issuance authn: **mTLS**; client identity = **SPIFFE SAN URI**; a config policy maps
  identity → maximum grantable scopes.
- Signing key in **GCP Secret Manager**, with rotation; JWKS publishes current + previous
  public keys.
- Scope wildcard: **one segment** (`owner/*`).
- Repo-scoped authz applies to **both** the GitHub API upstream and (later) git-cache.
- Git clients carry the JWT via `http.extraHeader: Authorization: Bearer <jwt>`.

## 2. Scope model

The OAuth `scope` claim is a space-delimited list of scope tokens:

- `<upstream>` (bare, e.g. `anthropic`, `mistral`) — full access to an unscoped upstream.
- `<upstream>:<owner>/<repo>` (e.g. `github:example-org/example-repo`) — one exact repo on a
  resource-scoped upstream.
- `<upstream>:<owner>/*` (e.g. `github:customer-org/*`) — one wildcard segment: any repo
  directly under `owner`.

Example claim: `scope: "anthropic mistral github:example-org/example-repo github:customer-org/*"`.

Grammar (one wildcard, no `**`, no nested globs):

```
scope-token := upstream                      ; bare
             | upstream ":" owner "/" repo   ; exact resource
             | upstream ":" owner "/*"       ; wildcard resource
upstream, owner, repo := [A-Za-z0-9._-]+
```

Two operations:

- **`covers(allowed, requested) -> bool`** — issuance check. True when a granted-to-caller
  scope `allowed` is broad enough to grant `requested`:
  - `allowed == requested`
  - `allowed` is bare `<u>` and `requested` is `<u>` or `<u>:<anything>` (bare grants all
    resources under the upstream)
  - `allowed` is `<u>:<owner>/*` and `requested` is `<u>:<owner>/<repo>` or `<u>:<owner>/*`
  - exact `<u>:<owner>/<repo>` covers only itself

  A requested scope is grantable iff **some** allowed scope covers it. This lets a caller
  entitled to `github:example-org/*` mint `github:example-org/example-repo`.

- **`permits(scopeset, upstream, resource) -> bool`** — authorization check for a proxied
  request:
  - unscoped upstream: bare `<upstream>` ∈ scopeset
  - resource-scoped upstream, request maps to `owner/repo`: bare `<upstream>` ∈ scopeset,
    **or** some `<upstream>:<glob>` in scopeset matches `owner/repo`
  - resource-scoped upstream, request maps to no repo: allowed only if bare `<upstream>` ∈
    scopeset (otherwise denied)

## 3. Components

New and changed units (each independently testable):

| Component | Responsibility | Notes |
|---|---|---|
| `scope` | Parse scope strings into typed tokens; implement `covers` (issuance) and `permits` (authz) with one-segment wildcard matching. | Pure, fully unit-tested. |
| `keystore` | Load the private signing key from GCP Secret Manager; derive the public JWK; assemble JWKS from current + previous public keys; background refresh so rotation takes effect without restart. | Uses the Phase-1 `SecretProvider`. |
| `jwt::Issuer` | Mint a signed JWT: header `{alg: ES256, kid}`, claims `{iss, aud, sub, iat, exp = iat + ttl, scope}`. | ttl from config (default 7d). |
| `jwt::Verifier` | Verify an incoming Bearer JWT against the keystore's current+previous public keys; validate `exp`, `iss`, `aud`; return a parsed `ScopeSet`. | Rejects on bad signature / expiry / issuer / audience. |
| `mtls` | Extract the SPIFFE SAN URI from the verified client certificate on the issuance listener. | Identity string, e.g. `spiffe://example/ci/example-repo`. |
| `ClientPolicy` | Config table mapping SPIFFE identity (exact or trailing `*` prefix) → maximum grantable scopes. | Deny if no entry matches. |
| token endpoint | Handle `POST /token` (OAuth2 client_credentials): mTLS identity → policy → validate requested ⊆ allowed via `covers` → mint → OAuth token response. | On its own mTLS listener. |
| JWKS endpoint | Serve `/.well-known/jwks.json` (current + previous public keys). | Public listener. |
| upstream `resource` | Optional per-upstream resource extractor. `github-repo` extracts `owner/repo` from `/repos/{owner}/{repo}/…`. Absent ⇒ unscoped upstream. | Extend with more kinds later. |
| `decision` (changed) | Replace the Phase-1 token-map lookup with: verify JWT → `permits(scopeset, upstream, resource)`. Same 404/401/403/forward result shape. | `TokenMap` removed. |
| `config` (changed) | Remove `[[tokens]]`; add `[auth]`, `[auth.signing]`, `[issuance]`, `[issuance.clients]`, and optional per-upstream `resource`. | Validated at startup. |

## 4. Configuration

```toml
[listen]
tcp = "0.0.0.0:6191"

[auth]
mode = "jwt"
issuer = "https://trust.example.internal/"
audience = "trust-proxy"

[auth.signing]
algorithm = "ES256"
token_ttl = "7d"
key_secret_ref = "projects/my-proj/secrets/trust-signing-key/versions/latest"
# Optional: verify-only previous key so live tokens survive rotation.
previous_key_secret_ref = "projects/my-proj/secrets/trust-signing-key/versions/2"

[issuance]
mtls_addr = "0.0.0.0:8443"
client_ca_path = "/etc/trust/client-ca.pem"     # CA that signs client certs

[issuance.jwks]
addr = "0.0.0.0:8080"                            # serves /.well-known/jwks.json

[[issuance.clients]]
spiffe = "spiffe://example/ci/example-repo"                # exact identity
allowed_scopes = ["github:example-org/example-repo"]

[[issuance.clients]]
spiffe = "spiffe://example/team/platform/*"          # trailing-* prefix match
allowed_scopes = ["anthropic", "mistral", "github:example-org/*", "github:customer-org/*"]

# --- Unscoped API upstream ---
[[upstreams]]
name = "anthropic"
kind = "api"
listen_host = "anthropic.proxy.internal"
origin = "https://api.anthropic.com"
secret_ref = "projects/my-proj/secrets/anthropic-key/versions/latest"
injection = { header = "x-api-key", scheme = "raw" }

# --- Unscoped API upstream ---
[[upstreams]]
name = "mistral"
kind = "api"
listen_host = "mistral.proxy.internal"
origin = "https://api.mistral.ai"
secret_ref = "projects/my-proj/secrets/mistral-key/versions/latest"
injection = { header = "authorization", scheme = "bearer" }

# --- Resource-scoped API upstream ---
[[upstreams]]
name = "github"
kind = "api"
listen_host = "github-api.proxy.internal"
origin = "https://api.github.com"
secret_ref = "projects/my-proj/secrets/github-token/versions/latest"
injection = { header = "authorization", scheme = "bearer" }
resource = { kind = "github-repo" }              # extract owner/repo → repo-scoped authz
```

Validation additions: `[auth] mode = "jwt"` required; each `issuance.clients` entry's
`allowed_scopes` must parse; a `resource.kind` must be a known extractor; upstream `name`s
used in scopes need no pre-declaration (scopes are opaque strings, matched at request time).

## 5. Data flow

### Issuance (`POST /token`, mTLS listener)

1. TLS handshake requires a client cert chained to `client_ca_path`. Extract the SPIFFE SAN
   URI (**401** if absent/invalid).
2. Match the identity against `issuance.clients` (exact, then trailing-`*` prefix). No match
   ⇒ **403**.
3. Parse the OAuth2 request: `grant_type=client_credentials` (**400** otherwise) and an
   optional space-delimited `scope`. Omitted `scope` ⇒ grant the caller's full
   `allowed_scopes`.
4. For each requested scope, require some `allowed` scope to `cover` it; any uncovered scope
   ⇒ **400 `invalid_scope`**.
5. Mint the JWT (`exp = now + token_ttl`, `sub` = identity, `scope` = granted) signed with
   the current key (`kid` in header).
6. Respond `200 {access_token, token_type: "Bearer", expires_in, scope}`.

### Proxy (updated `request_filter`)

1. Route by `Host` → upstream (**404** if none).
2. Extract Bearer JWT from `Authorization`; verify signature against keystore public keys and
   validate `exp`/`iss`/`aud` (**401** on any failure).
3. Parse the `scope` claim → `ScopeSet`.
4. Determine the request's resource: if the upstream has a `resource` extractor, apply it to
   the path → `Option<owner/repo>`. Authorize via `permits(scopeset, upstream, resource)`
   (**403** if not permitted).
5. Fetch the upstream secret (cached) (**502** on error).
6. Strip the client `Authorization`, inject the upstream secret per its scheme, rewrite
   `Host` to the origin. (Unchanged from Phase 1.)

Git clients send the JWT via `git -c http.extraHeader="Authorization: Bearer <jwt>"`; trust
strips it and injects the real upstream credential.

### Key rotation

- New tokens are always signed with the **current** key.
- The verifier and JWKS include **current + previous** public keys, so 7-day tokens signed
  before a rotation keep validating until they expire.
- The keystore refreshes from GCP Secret Manager on an interval, so rotating the secret (add
  a new version, shift `previous_key_secret_ref`) takes effect without a restart.

## 6. Error handling

- All issuance failures map to OAuth-style responses: `401` (bad/absent client cert),
  `403` (identity not in policy), `400 invalid_scope` / `unsupported_grant_type`.
- Proxy failures reuse Phase-1 conventions: `404` unknown host, `401` invalid token, `403`
  not permitted, `502` secret/backing failure. Reject responses short-circuit; only
  authorized, credential-injected requests reach an upstream.
- Secrets and private keys are never logged (redacted `Debug`, no `Display`). The signing
  private key is treated like any other secret.
- Typed errors (`thiserror`) at every boundary; no panics in the request or issuance path.

## 7. Testing

- **Unit:** scope parsing; `covers` (issuance subset with wildcard subsumption) and
  `permits` (authz) matrices; JWT issue↔verify round-trip; rejection on bad signature,
  expiry, wrong `iss`/`aud`; keystore load from a fake `SecretProvider` and JWKS
  current+previous assembly; SPIFFE SAN extraction from a test cert; `github-repo` resource
  extraction from representative paths (`/repos/o/r/...`, non-repo paths).
- **Integration:** generate a test signing keypair + a client CA and client cert; call the
  mTLS `/token` endpoint to obtain a JWT; use that JWT against the proxy and assert:
  anthropic (unscoped) allowed; `github` repo in scope allowed; `github` repo out of scope
  → 403; expired/tampered token → 401; and that the upstream received the injected secret
  with the client JWT stripped.

## 8. Scope of this spec vs later

- **In scope:** the full auth + issuance system above, proven on `api` upstreams (including
  the resource-scoped `github` API upstream).
- **Out of scope (Phase 3):** the `git-cache` upstream kind (local mirror serving, push
  passthrough). It will reuse `scope`/`permits` and the `github-repo` resource extractor
  unchanged.
