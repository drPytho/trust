# Example: Linear query with on-the-fly secret injection

A minimal Node.js script that calls Linear's GraphQL API **through trust**. The
client authenticates to trust with a short-lived JWT and **never holds a Linear
API key** — trust injects the real key at the edge.

```
 query.mjs (@linear/sdk)                    trust (localhost:6191)             api.linear.app
 apiUrl = http://localhost:6191/graphql ─▶  verify JWT (scope: linear)
 Authorization: Bearer <JWT>                strip Authorization
                                              inject Authorization: <real key> ──▶ /graphql
                                              rewrite Host → api.linear.app
```

Linear personal API keys deliberately use `Authorization: <key>` without a
`Bearer` prefix. The SDK's `accessToken` option makes the client-facing
credential `Authorization: Bearer <trust JWT>`; trust strips it and writes the
stored Linear key verbatim before forwarding.

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

3. **Linear personal API key** in GCP Secret Manager:

   ```bash
   printf '%s' "lin_api_…" | gcloud secrets create linear-key --data-file=- --project=$PROJECT
   ```

4. Edit `examples/linear-js/config.toml` — replace `YOUR_PROJECT` in the two
   `secret_ref`s with your GCP project. Ensure Application Default Credentials
   are available (`gcloud auth application-default login`).

## Run

```bash
# 1. Start trust with the example config (from the repo root)
TRUST_CONFIG=examples/linear-js/config.toml RUST_LOG=info cargo run --release &

# 2. Install the SDK
cd examples/linear-js && npm install && cd -

# 3. Mint a scoped JWT (mTLS to the /token endpoint) and query the current viewer
TRUST_JWT="$(./scripts/mint-jwt.sh linear)" node examples/linear-js/query.mjs
```

Expected: JSON containing the authenticated Linear viewer. The script sends
only the trust JWT; the Linear key is injected by trust and never reaches the
client.

## Notes

- `TRUST_URL` must be the complete GraphQL endpoint, for example
  `https://linear.proxy.internal/graphql` in production.
- Use `accessToken`, not `apiKey`, for the trust JWT. `apiKey` sends a raw
  `Authorization` value, whereas trust accepts client JWTs as Bearer tokens.
- This example stores a personal API key and therefore uses `scheme = "raw"`.
  If the stored secret is a Linear OAuth access token, use
  `scheme = "bearer"` instead.
- The example permits only `POST`, which is the method used by the Linear
  GraphQL API and SDK. Add methods intentionally if your integration needs
  another endpoint.
- Uses trust's plain `tcp` listener (`http://localhost:6191`) for local
  development. In production, front the proxy with TLS and point `TRUST_URL`
  at the TLS reverse-proxy hostname.
