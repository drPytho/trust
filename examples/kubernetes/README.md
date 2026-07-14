# Kubernetes example

This example deploys `trust` using the image published by CI to
`ghcr.io/drpytho/trust`. The configuration is mounted from a ConfigMap, while
TLS private material is kept in a Kubernetes Secret.

Before applying the manifest, replace `PROJECT_ID`, the issuer, SPIFFE policy,
and upstream settings in `deployment.yaml`. Grant the `trust` ServiceAccount
access to the referenced GCP Secret Manager secrets through your cluster's
workload identity integration.

Create the TLS Secret from your server certificate, server key, and client CA:

```bash
kubectl apply -f examples/kubernetes/namespaces.yaml
kubectl -n trust-system create secret generic trust-tls \
  --from-file=server.crt=/path/to/server.crt \
  --from-file=server.key=/path/to/server.key \
  --from-file=client-ca.pem=/path/to/client-ca.pem
```

Apply the example:

```bash
kubectl apply -f examples/kubernetes/deployment.yaml
```

The Service exposes these listeners inside the cluster:

| Service port | Listener | Client authentication |
|---|---|---|
| `6443` | TLS reverse proxy | Bearer JWT; passthrough uses `Proxy-Authorization` |
| `6180` | TLS CONNECT proxy | `Proxy-Authorization` Bearer or Basic `jwt:<JWT>` |
| `8443` | mTLS token endpoint | client certificate with authorized SPIFFE URI |
| `8080` | management | restricted by NetworkPolicy in this example |

The example leaves the plain reverse listener disabled so JWTs are not sent
over an unencrypted hop. For a private GHCR package, also configure an
`imagePullSecret`. For production, pin the image to the immutable `sha-...`
tag published by CI instead of `latest`.

The Deployment probes `/healthz` for liveness and `/readyz` for readiness on
the management port. Prometheus metrics are available at `/metrics` on the same
port.

For dynamic credentials, configure the proxy's Kubernetes ServiceAccount with
Workload Identity. It needs Secret Manager access to the GitHub App private key
and `roles/artifactregistry.reader` on the specific npm repository. Workers do
not need either permission.

GitHub App installations are mapped explicitly by organization:

```toml
[github_app]
app_id = 123456
private_key_secret_ref = "projects/PROJECT_ID/secrets/github-app-key/versions/latest"

[[github_app.installations]]
owner = "ORG_ONE"
installation_id = 111111

[[github_app.installations]]
owner = "ORG_TWO"
installation_id = 222222
```

Artifact Registry npm workers use a non-secret `.npmrc` pointing at the proxy
and place their short-lived trust JWT in `TRUST_TOKEN`; they do not run
`gcloud` or `google-artifactregistry-auth`. See the main README for the full
upstream and `.npmrc` examples.

## Granting a workload access

The token endpoint authenticates a workload by the SPIFFE URI SAN in its mTLS
client certificate. A Kubernetes ServiceAccount does not become a `trust`
identity automatically: the workload needs a client certificate signed by the
CA configured as `issuance.client_ca_path`.

The general setup is:

1. Create a private client CA, or use a managed CA or SPIRE. Configure a
   cert-manager `Issuer` or `ClusterIssuer` that can issue client certificates.
   A public ACME issuer such as Let's Encrypt is not suitable for internal mTLS
   client certificates.
2. Mount the public client CA certificate into the `trust` Pod as
   `client-ca.pem`.
3. Give the workload an exact SPIFFE identity and authorize only the scopes it
   needs in the `trust` configuration:

   ```toml
   [[issuance.clients]]
   spiffe = "spiffe://example/workloads/my-service"
   allowed_scopes = [
     "anthropic",
     "github:ORG/REPOSITORY",
     "npm-artifacts:PROJECT_ID/NPM_REPOSITORY",
   ]
   ```

4. Issue the workload a certificate containing that URI SAN. For example, with
   cert-manager and a preconfigured `trust-client-ca` issuer:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata:
     name: my-service-trust-client
     namespace: WORKLOAD_NAMESPACE
   spec:
     secretName: my-service-trust-client
     duration: 24h
     renewBefore: 8h
     uris:
       - spiffe://example/workloads/my-service
     usages:
       - client auth
     privateKey:
       algorithm: ECDSA
       size: 256
       rotationPolicy: Always
     issuerRef:
       name: trust-client-ca
       kind: ClusterIssuer
   ```

5. Mount the generated `tls.crt` and `tls.key` Secret into the workload. Also
   mount the CA certificate that signed the `trust` server certificate so the
   client can verify the server. The server certificate must contain the
   Kubernetes Service DNS name, for example `trust.TRUST_NAMESPACE.svc`.
6. Mint a token by posting an explicit, minimal scope to the mTLS port:

   ```bash
   curl --fail --silent --show-error \
     --cert /var/run/trust/client/tls.crt \
     --key /var/run/trust/client/tls.key \
     --cacert /var/run/trust/server/ca.crt \
     https://trust.TRUST_NAMESPACE.svc:8443/token \
     --data-urlencode 'grant_type=client_credentials' \
     --data-urlencode 'scope=github:ORG/REPOSITORY'
   ```

The response contains `access_token`, `expires_in`, and the granted `scope`.
Keep the JWT in process memory, send it to the proxy as
`Authorization: Bearer <token>`, and refresh it shortly before it expires. Do
not store minted JWTs in Kubernetes Secrets.

For an upstream configured with `mode = "passthrough"`, send the trust JWT in
`Proxy-Authorization` instead. `trust` removes that header and forwards the
caller's regular `Authorization` header unchanged. Passthrough hosts are still
explicitly allowlisted, JWT-authenticated, and scope-authorized; unknown hosts
remain denied.

## Using trust as the sandbox egress proxy

The example enables a TLS HTTP CONNECT listener on port `6180`. A destination
is available through that listener only when its upstream is configured as
passthrough and explicitly opts in:

```toml
[forward_proxy]
addr = "0.0.0.0:6180"
tls = true
connect_timeout = "10s"
idle_timeout = "5m"
max_tunnel_duration = "1h"
max_concurrent_tunnels = 1024
allow_private_ips = false

[[upstreams]]
name = "public-api"
kind = "api"
mode = "passthrough"
listen_host = "public.proxy.internal"
origin = "https://api.example.com"
allow_connect = true
```

The CONNECT authority must exactly match `api.example.com:443`, and the JWT
must contain the `public-api` scope. Unknown hosts and ports fail closed. The
listener uses the same verifier, scopes, upstream configuration, signing keys,
rejection logs, and metrics as the reverse proxy. It does not create a second
trust domain.

CONNECT carries an opaque TLS stream, so it cannot inject credentials or
enforce HTTP paths or methods. Keep credential-injected endpoints on the
reverse proxy (`https://anthropic.proxy.internal/...`, for example), and use
CONNECT for explicitly allowlisted straight-through destinations. Configure
cluster DNS for each `*.proxy.internal` reverse-proxy name to resolve to the
`trust` Service, or use equivalent stable internal DNS names in `listen_host`.

An orchestrator can mint a narrowly scoped JWT over mTLS, pass the short-lived
token and proxy URL into the sandbox, and configure clients in either of these
ways:

```bash
# Preferred when the client supports explicit proxy headers.
curl --proxy https://trust.trust-system.svc:6180 \
  --proxy-cacert /var/run/trust/server/ca.crt \
  --proxy-header "Proxy-Authorization: Bearer $TRUST_TOKEN" \
  https://api.example.com/resource

# Compatibility mode for clients that only support credentials in HTTPS_PROXY.
# trust accepts Basic username `jwt` with the JWT as its password.
export HTTPS_PROXY="https://jwt:${TRUST_TOKEN}@trust.trust-system.svc:6180"
export NO_PROXY="metadata.google.internal,169.254.169.254,169.254.169.252,trust.trust-system.svc,.proxy.internal"
```

The server certificate must include `trust.trust-system.svc` as a DNS SAN, and
the client must trust its issuing CA. Support for TLS-to-proxy (`https://` in
`HTTPS_PROXY`) varies by client. A plaintext `http://` listener is more broadly
compatible but exposes the JWT on the Pod-to-proxy network path and should be
used only with compensating network controls.

Apply `sandbox-egress-network-policy.yaml` to select sandbox Pods labeled
`trust.example.com/restricted-egress: "true"`. It allows egress only to the
trust token/reverse/CONNECT ports, cluster DNS, and the GKE metadata server.
The metadata exception in the example is for GKE Dataplane V2
(`169.254.169.254/32` on TCP ports `80` and `8080`). For older or
non-Dataplane-V2 clusters, replace it with `169.254.169.252/32` on TCP ports
`987` and `988`. The separate ingress policy allows only the corresponding
labeled clients to enter the trust ports. Together, these make direct egress
fail closed for traffic covered by the cluster's NetworkPolicy implementation.

When the sandbox uses Workload Identity, keep the metadata host and addresses
out of the proxy path:

```bash
export NO_PROXY="metadata.google.internal,169.254.169.254,169.254.169.252,trust.trust-system.svc,.proxy.internal"
```

The sandbox's Google client obtains a short-lived access token from the GKE
metadata server. It then sends that token inside the TLS stream carried by the
CONNECT tunnel. The trust JWT authorizes the destination; Google IAM authorizes
the operation and resource. Grant `roles/pubsub.publisher` on only the required
topic and `roles/storage.objectCreator` on only the required bucket. Use a more
permissive Storage role only when overwrite, read, or delete is required.

### Testing Workload Identity egress

`cargo test --all --locked` includes integration tests that verify:

- the CONNECT listener consumes the trust JWT without forwarding it;
- a separate Google OAuth bearer token is preserved inside the tunnel;
- all Kubernetes examples parse as YAML and the embedded trust TOML is valid;
- the example allowlists only the exact Pub/Sub and Storage CONNECT endpoints;
- the restricted sandbox policy has the Dataplane V2 metadata exception but no
  direct HTTPS egress; and
- `NO_PROXY` covers the metadata server without bypassing `*.googleapis.com`.

Only a Pod on a real GKE node can test metadata interception and the deployed
IAM policies. `gcp-wif-smoke-test.yaml` is an opt-in Job for that final check.
It publishes one message and creates one uniquely named object, so do not apply
it against production resources unintentionally. Replace `PROJECT_ID`,
`TOPIC_ID`, and `BUCKET_NAME`, then run:

```bash
kubectl apply -f examples/kubernetes/gcp-wif-smoke-test.yaml
kubectl -n workloads logs -f job/trust-gcp-wif-smoke-test
```

The Job reuses the `my-service` Kubernetes ServiceAccount, mTLS client Secret,
server CA ConfigMap, trust scopes, and restricted-egress labels from the other
examples. A successful run proves metadata token acquisition, proxy
authentication, Pub/Sub publish, and Cloud Storage upload end to end.

NetworkPolicy enforcement and service-DNAT ordering vary by CNI. Validate the
policy in your cluster, adapt the DNS Pod selector if it is not `k8s-app:
kube-dns`, and separately prevent bypass through host networking, privileged
Pods, node-local proxies, or other CNI-specific paths. The trust Pod itself
still needs DNS and outbound access to its configured origins.

In production, restrict ingress to the token port with NetworkPolicy, prefer
short JWT lifetimes, and tightly control who may request certificates or choose
URI SANs from the client issuer. Deleting a client certificate does not revoke
JWTs already minted from it; those remain valid until their configured expiry.

The example is split into reusable manifests:

- [`namespaces.yaml`](namespaces.yaml) creates the `trust-system` and
  `workloads` namespaces used by the other examples.
- [`client-ca-issuer.yaml`](client-ca-issuer.yaml) configures cert-manager to
  issue client certificates from a CA Secret.
- [`client-certificate.yaml`](client-certificate.yaml) requests one rotating
  workload certificate with an exact SPIFFE URI.
- [`client-workload.yaml`](client-workload.yaml) shows how to mount the client
  key pair and server CA in an application Pod.
- [`token-network-policy.yaml`](token-network-policy.yaml) restricts the mTLS
  port and proxy ports to their respective labeled clients.
- [`sandbox-egress-network-policy.yaml`](sandbox-egress-network-policy.yaml)
  denies direct egress from selected sandboxes while retaining trust, DNS, and
  the GKE metadata server.
- [`gcp-wif-smoke-test.yaml`](gcp-wif-smoke-test.yaml) optionally verifies a
  real Workload Identity token through trust against Pub/Sub and Cloud Storage.

Replace the example namespaces, DNS names, SPIFFE trust domain, image, and CA
certificate before applying the files. The management port is intentionally
not exposed by the ingress NetworkPolicy; add a narrowly scoped monitoring
rule if Prometheus or an operator must reach it.

A representative application order is:

```bash
kubectl apply -f examples/kubernetes/namespaces.yaml
kubectl apply -f examples/kubernetes/deployment.yaml
kubectl apply -f examples/kubernetes/client-ca-issuer.yaml
kubectl apply -f examples/kubernetes/client-certificate.yaml
kubectl apply -f examples/kubernetes/client-workload.yaml
kubectl apply -f examples/kubernetes/token-network-policy.yaml
kubectl apply -f examples/kubernetes/sandbox-egress-network-policy.yaml
```

Create the `trust-tls`, client-CA, and server-CA material before applying the
resources that reference it. Apply NetworkPolicies last, after confirming DNS,
token issuance, reverse proxying, CONNECT, and your CNI's policy behavior.
