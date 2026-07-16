// Query Linear's GraphQL API *through trust*, which injects the real personal
// API key. The client authenticates only to trust with a short-lived JWT.
//
// Run: TRUST_JWT="$(../../scripts/mint-jwt.sh linear)" node query.mjs
import { LinearClient } from "@linear/sdk";

const jwt = process.env.TRUST_JWT;
if (!jwt) {
  console.error("Set TRUST_JWT (e.g. TRUST_JWT=$(../../scripts/mint-jwt.sh linear))");
  process.exit(1);
}

const client = new LinearClient({
  // `apiUrl` is the complete GraphQL endpoint. Its Host header routes this
  // request to the `linear` upstream in the example trust configuration.
  apiUrl: process.env.TRUST_URL ?? "http://localhost:6191/graphql",
  // Use `accessToken`, rather than `apiKey`, so the SDK sends the trust JWT as
  // `Authorization: Bearer <jwt>`. trust replaces it with the raw Linear
  // personal API key before forwarding to api.linear.app.
  accessToken: jwt,
});

const viewer = await client.viewer;
console.log(
  JSON.stringify(
    { id: viewer.id, name: viewer.name, email: viewer.email },
    null,
    2,
  ),
);
