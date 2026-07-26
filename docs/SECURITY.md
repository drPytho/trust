# Security model

## Invariants

- **Clients never hold upstream credentials.** Real keys live in a secret
  manager, are fetched server-side, held only in memory with a TTL, and never
  logged (`Secret` has a redacted `Debug` and no `Display`).
- **The client JWT never leaks upstream.** `Proxy-Authorization` is always
  removed before forwarding. In inject mode the client's `Authorization` is
  also removed before the upstream secret is injected. In passthrough mode the
  caller's `Authorization` is preserved and the trust JWT is accepted only
  from `Proxy-Authorization`.
- **No request reaches an upstream without a valid, authorized JWT** —
  verified ES256 signature, `iss`, `aud`, `exp`, and scope coverage.
- **Deny by default.** Unknown `Host` headers are 404. CONNECT destinations
  are denied unless their exact origin `host:port` has `allow_connect`
  (opaque) or `intercept_connect` (selective interception). The optional
  `audit_unmatched` fallback is the only policy admitting unmatched public
  destinations, and it is always opaque.
- **Scopes are capped at issuance.** The mTLS-only `/token` endpoint
  intersects requested scopes with the per-identity policy; clients cannot
  self-escalate. Unauthenticated clients cannot reach `/token` at all.
- **The config file contains no plaintext secrets** — only secret-manager
  references. Keep local `config.toml` out of version control (it is
  `.gitignore`d).

## Key handling

- JWT signing keys (ES256/P-256) are loaded from GCP Secret Manager and
  refreshed every 10 minutes without a restart. Rotation keeps current +
  previous keys verify-capable and both published via JWKS, so live tokens
  survive a rotation.
- TLS interception uses a **dedicated CA hierarchy**: offline root, scoped
  online intermediate mounted in trust. It must not share material with the
  reverse-proxy cert, workload mTLS CA, or the signing key. Removing the root
  from a tenant's trust bundle is the immediate rollback.

## Egress hardening

- DNS is resolved server-side; non-global special-use ranges (loopback,
  link-local, private, multicast, documentation, reserved) are rejected unless
  `allow_private_ips = true` for exact configured routes. The audit fallback
  is always public-only.
- For intercepted routes, approved addresses are **resolved and frozen at
  CONNECT time**; the decrypted upstream connection uses only that set — no
  second lookup, no DNS-rebinding window.
- Intercepted tunnels require exact agreement between CONNECT authority, TLS
  SNI, and decrypted `Host`, accept HTTP/1.1 only, and keep upstream
  certificate/hostname verification enabled.
- Tunnels terminate at JWT expiry, idle timeout, or `max_tunnel_duration`.

## Subprocess hygiene (git-cache)

- `git` and `git http-backend` children run with a **cleared environment** and
  fixed argument vectors — credentials never pass through a shell or inherited
  env, and auth headers never appear in logs or error types.
- Mirror paths are built from validated components (`safe_component` rejects
  `.`, `..`, separators, and control characters), preventing path traversal
  into or out of the mirror root.

## Logging and metrics

- Rejections are logged at `WARN` with bounded reason labels and safe request
  metadata; credentials and authorization headers are never logged.
- High-cardinality values (audit destination hostnames) go to logs, not
  Prometheus labels.

## Known limitations

- Intercepted CONNECT paths are HTTP/1.1 only; certificate-pinned or
  HTTP/2-/HTTP/3-only clients need an opaque or reverse-proxy route.
- The `outbound-audit` fallback is an audit boundary, not a
  credential-isolation boundary: it cannot inspect or modify tunneled TLS.
- Plaintext listeners (`[listen].tcp`, `forward_proxy.tls = false`) expose the
  JWT on that hop; restrict them to private networks with NetworkPolicy.
- Token revocation latency equals `token_ttl`; shorten it where tighter
  revocation is needed.
