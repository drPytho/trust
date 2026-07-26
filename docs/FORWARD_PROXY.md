# HTTP(S) forward proxy

The optional `[forward_proxy]` listener accepts absolute-form `http://`
requests and HTTPS CONNECT tunnels. It reuses the same upstream configuration,
JWT verifier, signing keys, scopes, and metrics as the reverse proxy.

## Routing model

| CONNECT destination                      | Required scope       | TLS handling                                   | Credential injection |
|------------------------------------------|----------------------|------------------------------------------------|----------------------|
| Unknown public host with `audit_unmatched` | `outbound-audit`     | opaque TCP tunnel                              | never                |
| `allow_connect = true` upstream          | that upstream's name | opaque TCP tunnel                              | never                |
| `intercept_connect = true` upstream      | that upstream's name | per-host TLS termination + verified upstream TLS | configured inject mode |

An exact configured route always takes precedence over the audit fallback: an
`outbound-audit` token cannot select a configured intercepted host — it gets
`403` before the TLS upgrade begins. Opaque paths remain compatible with
HTTP/2, gRPC, and other TLS protocols; the intercepted path accepts **HTTP/1.1
only** (ALPN is restricted during the handshake).

## Client authentication

Clients that can set proxy headers should use Bearer authentication:

```bash
curl --proxy https://trust.example.internal:6180 \
  --proxy-cacert server-ca.pem \
  --proxy-header "Proxy-Authorization: Bearer $JWT" \
  https://api.example.com/resource
```

For tools that only understand proxy-URL credentials, trust also accepts HTTP
Basic with the fixed username `jwt` and the JWT as password:

```bash
export HTTPS_PROXY="https://jwt:${JWT}@trust.example.internal:6180"
export NO_PROXY="trust.example.internal,.proxy.internal"
```

The `https://` proxy scheme encrypts the client→trust hop; client support
varies. `tls = false` with `http://` is more widely compatible but exposes the
JWT to that network hop — acceptable only for a private, NetworkPolicy-restricted
cluster-internal listener:

```bash
export HTTP_PROXY="http://jwt:${JWT}@trust.example.internal:6180"
export HTTPS_PROXY="$HTTP_PROXY"
```

## DNS and private addresses

Trust resolves DNS server-side and rejects non-global special-use addresses
(loopback, link-local, private, multicast, documentation, benchmarking,
reserved) by default. For intercepted routes, the approved addresses are
resolved and **frozen at CONNECT time** before trust returns `200`; the
decrypted upstream connection tries only that set, preventing DNS rebinding.
Set `allow_private_ips = true` only when explicitly configured internal
upstreams are required; the audit fallback always remains public-only.

Tunnels end at JWT expiry, the idle timeout, or `max_tunnel_duration`,
whichever comes first.

## Selective TLS interception

TLS interception is an explicit per-provider opt-in, not a generic egress
feature. It uses a dedicated CA hierarchy: an offline root and a scoped online
intermediate. Do not reuse the reverse-proxy certificate, workload mTLS CA, or
JWT signing key.

```bash
./scripts/dev-egress-mitm-ca.sh dev-egress-mitm-ca
# Trust mount: dev-egress-mitm-ca/intermediate/{intermediate-chain.pem,intermediate.key}
# Opt-in workload trust anchor: dev-egress-mitm-ca/egress-root-ca.pem
# Keep dev-egress-mitm-ca/root/egress-root-ca.key offline.
```

Mount only the intermediate chain/key read-only in the trust Pod. Add only the
public root to a **combined** CA bundle in opted-in sandboxes — the bundle must
retain the workload's regular public roots (and the trust server CA when
needed); replacing it with the egress root alone breaks ordinary TLS.

Operational properties:

- Trust synchronously prewarms a bounded in-memory leaf cache at startup and
  refreshes it in the background; TLS handshakes never call Secret Manager or
  KMS.
- Each leaf has one exact DNS SAN; the response chain omits the root; upstream
  certificate/hostname verification stays enabled.
- The CONNECT authority, TLS SNI, and decrypted HTTP/1 `Host` must all match
  the canonical configured host and port. A mismatch, missing SNI,
  absent/duplicate `Host`, expired CONNECT JWT, cache miss, or unsupported
  ALPN fails before any upstream request.
- The outer `Proxy-Authorization` and client `Authorization` are stripped; the
  stored provider credential is the only credential injected upstream.

A client whose combined CA bundle trusts the egress root makes a normal
provider request without changing its destination hostname:

```bash
curl --proxy http://trust.example.internal:6180 \
  --proxy-header "Proxy-Authorization: Bearer $ANTHROPIC_JWT" \
  --cacert dev-egress-mitm-ca/egress-root-ca.pem \
  https://api.anthropic.com/v1/messages
```

Certificate pinning and clients that require HTTP/2/HTTP/3 are not compatible
with interception; keep those on an opaque or reverse-proxy route. Block
direct UDP/443 for egress-enforced sandboxes so QUIC cannot bypass the proxy.

## Auditing unmatched destinations

During migration, the forward proxy can allow otherwise-unmatched public
destinations while inventorying them. This is opt-in and still requires a
valid JWT with a dedicated bare scope:

```toml
[forward_proxy]
addr = "0.0.0.0:6180"
tls = true
allow_private_ips = false
audit_unmatched = { scope = "outbound-audit" }

[[issuance.clients]]
spiffe = "spiffe://example/sandboxes/*"
allowed_scopes = ["outbound-audit"]
```

For an unknown CONNECT authority or absolute-form HTTP request, trust logs the
requested hostname and port at `WARN`, verifies the JWT and `outbound-audit`
scope, and applies the normal DNS/private-IP checks. Results are recorded under
`trust_connect_attempts_total{upstream="audit-unmatched",...}` and
`trust_forward_proxy_requests_total{upstream="audit-unmatched",...}`.
Destination names stay in logs, not Prometheus labels, to bound metric
cardinality.

The audit fallback never enters interception, cannot remove or inject
destination TLS credentials, and does not apply to reverse-proxy hosts or
private destinations. It is an egress **audit** boundary, not a
credential-isolation boundary. Workflow: grant a sandbox its named scopes plus
`outbound-audit` during discovery, convert observed destinations into explicit
upstreams, then remove the audit scope and setting to return to
deny-by-default.
