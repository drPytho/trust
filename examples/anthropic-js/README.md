# Example: Anthropic query with on-the-fly secret injection

A minimal Node.js script that calls the Anthropic API **through trust**. The
client authenticates to trust with a short-lived JWT and **never holds an
Anthropic API key** — trust injects the real key at the edge.

```
 query.mjs (@anthropic-ai/sdk)                 trust (localhost:6191)          api.anthropic.com
 baseURL = http://localhost:6191   ─────────▶  verify JWT (scope: anthropic)
 Authorization: Bearer <JWT>                    strip Authorization
 (no x-api-key)                                 inject x-api-key: <real key>  ──▶  /v1/messages
                                                rewrite Host → api.anthropic.com
```

The SDK's `authToken` option sends the JWT as `Authorization: Bearer …` and
omits `x-api-key` entirely; trust adds the real key from GCP Secret Manager.
This is intentionally a reverse-proxy example. HTTP CONNECT cannot be used for
credential injection because the end-to-end TLS stream is opaque to trust.

## Prerequisites

Run everything from the **repo root** so the config's `certs/` paths resolve.

1. **Dev certs** (server cert + client CA + client cert with a SPIFFE SAN):
   ```bash
   ./scripts/dev-certs.sh certs         # SPIFFE defaults to spiffe://example/dev/local
   ```
2. **Signing key** in GCP Secret Manager:
   ```bash
   ./scripts/gen-signing-key.sh signing-key.pem
   gcloud secrets create trust-signing-key --data-file=signing-key.pem --project=$PROJECT
   ```
3. **Anthropic API key** in GCP Secret Manager:
   ```bash
   printf '%s' "sk-ant-…" | gcloud secrets create anthropic-key --data-file=- --project=$PROJECT
   ```
4. Edit `examples/anthropic-js/config.toml` — replace `YOUR_PROJECT` in the two
   `secret_ref`s with your GCP project. Ensure Application Default Credentials
   are available (`gcloud auth application-default login`).

## Run

```bash
# 1. Start trust with the example config (from the repo root)
TRUST_CONFIG=examples/anthropic-js/config.toml RUST_LOG=info cargo run --release &

# 2. Install the SDK
cd examples/anthropic-js && npm install && cd -

# 3. Mint a scoped JWT (mTLS to the /token endpoint) and run the query
TRUST_JWT="$(./scripts/mint-jwt.sh anthropic)" node examples/anthropic-js/query.mjs
```

Expected: a one-sentence reply from Claude. The script sent only the JWT; the
Anthropic key was injected by trust and never touched the client.

## Try the authorization boundary

Mint a token scoped to a *different* upstream and watch trust reject it (403):

```bash
# (requires a client identity allowed to mint another scope; otherwise the mint
#  itself returns 400 invalid_scope — which is the issuance boundary doing its job)
TRUST_JWT="$(./scripts/mint-jwt.sh mistral)" node examples/anthropic-js/query.mjs
```

## Notes

- Uses trust's plain `tcp` listener (`http://localhost:6191`) so the Node client
  needs no TLS trust config. In production, front the proxy with TLS (`[tls]`)
  and point `TRUST_URL` at `https://…`.
- The example does not enable `[forward_proxy]`. Use that CONNECT-only listener
  for explicitly allowlisted passthrough destinations, not for Anthropic key
  injection.
- `listen_host = "localhost"` in the config is what makes the SDK's default
  `Host: localhost` route to the `anthropic` upstream.
- The scripts referenced here (`dev-certs.sh`, `gen-signing-key.sh`,
  `mint-jwt.sh`) live in the repo-root `scripts/` directory.
