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
