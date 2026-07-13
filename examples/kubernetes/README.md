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
kubectl create secret generic trust-tls \
  --from-file=server.crt=/path/to/server.crt \
  --from-file=server.key=/path/to/server.key \
  --from-file=client-ca.pem=/path/to/client-ca.pem
```

Apply the example:

```bash
kubectl apply -f examples/kubernetes/deployment.yaml
```

The Service exposes the plain proxy, TLS proxy, mTLS token, and JWKS ports
inside the cluster. For a private GHCR package, also configure an
`imagePullSecret`. For production, pin the image to the immutable `sha-...` tag
published by CI instead of `latest`.

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

In production, restrict ingress to the token port with NetworkPolicy, prefer
short JWT lifetimes, and tightly control who may request certificates or choose
URI SANs from the client issuer. Deleting a client certificate does not revoke
JWTs already minted from it; those remain valid until their configured expiry.

The example is split into reusable manifests:

- [`client-ca-issuer.yaml`](client-ca-issuer.yaml) configures cert-manager to
  issue client certificates from a CA Secret.
- [`client-certificate.yaml`](client-certificate.yaml) requests one rotating
  workload certificate with an exact SPIFFE URI.
- [`client-workload.yaml`](client-workload.yaml) shows how to mount the client
  key pair and server CA in an application Pod.
- [`token-network-policy.yaml`](token-network-policy.yaml) restricts the mTLS
  port to labeled token clients in the example workload namespace.

Replace the example namespaces, DNS names, SPIFFE trust domain, image, and CA
certificate before applying the files. The NetworkPolicy intentionally permits
only port `8443`; add the ingress rules needed for the proxy and management
ports before applying it to a shared `trust` Deployment.
