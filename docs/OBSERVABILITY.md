# Observability

The management listener (`[issuance].jwks_addr`, default `:8080`) exposes:

| Path | Purpose |
|---|---|
| `/healthz` | liveness — always OK while the process runs |
| `/readyz` | readiness — requires the proxy lifecycle started and a signing key loaded |
| `/metrics` | Prometheus text format |
| `/.well-known/jwks.json` | public signing keys for external JWT verification |

JWKS is safe to expose to verifiers; `/metrics` may reveal operational
metadata — restrict it (the Kubernetes example does so with NetworkPolicy).

## Metrics

Reverse proxy:

- `trust_proxy_requests_total{upstream,status}`
- `trust_proxy_rejections_total{upstream,reason,status}`
- `trust_proxy_request_duration_seconds{upstream}`
- `trust_proxy_in_flight_requests`

Credential resolution:

- `trust_credential_resolutions_total{upstream,provider,result}`
- `trust_credential_resolution_duration_seconds{provider}`

Forward proxy / CONNECT:

- `trust_connect_attempts_total{upstream,result}`
- `trust_connect_active_tunnels{upstream}`
- `trust_connect_duration_seconds{upstream}`
- `trust_connect_bytes_total{upstream,direction}`
- `trust_forward_proxy_requests_total{upstream,result}`

TLS interception:

- `trust_mitm_handshakes_total{upstream,result}`
- `trust_mitm_certificate_cache_total{result}`
- `trust_mitm_active_connections{upstream}`
- `trust_mitm_connection_duration_seconds{upstream}`

Audit-fallback traffic is recorded under `upstream="audit-unmatched"`.
Destination hostnames stay in logs rather than labels to bound cardinality.

## Logging

Rejected reverse-proxy and forward-proxy calls are logged at `WARN` with
bounded reason labels and safe request metadata. CONNECT rejections
distinguish invalid authorities, unknown destinations, missing or invalid
tokens, forbidden scopes, private destinations, connection failures, and
tunnel-capacity exhaustion. Credentials and authorization headers are never
logged.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| container exits at startup | GCP creds/IAM, missing `[tls]` cert/key, or bad `client_ca_path` |
| `/token` → 401 | client cert missing/not signed by `client_ca_path`, or no SPIFFE SAN |
| `/token` → 403 | SPIFFE identity has no `[[issuance.clients]]` entry |
| `/token` → 400 invalid_scope | requested scope beyond the identity's `allowed_scopes` |
| proxy → 401 | missing/expired/invalid JWT |
| proxy → 403 | JWT scope doesn't cover this upstream/repo |
| proxy → 404 | `Host` header matches no upstream `listen_host` |
| proxy → 502 | upstream secret fetch failed (GCP) or upstream unreachable |
| CONNECT → 407 | missing, expired, or invalid `Proxy-Authorization` JWT |
| CONNECT → 403 | destination not allowlisted or JWT scope doesn't cover it |
| forward proxy → 400 | request was not absolute-form HTTP and not HTTPS CONNECT |
| CONNECT → 502 | DNS resolution, private-address policy, or target connection failed |
| CONNECT → 503 | signing keys unavailable or tunnel capacity exhausted |
| interception handshake fails | check `trust_mitm_handshakes_total` result label: `sni_mismatch`, `certificate_unavailable`, `alpn_mismatch` (client tried HTTP/2+) |
