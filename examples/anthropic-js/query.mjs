// Query Anthropic *through the trust proxy*, which injects the real API key.
//
// The client authenticates to trust with its own short-lived JWT (via the SDK's
// `authToken` option → `Authorization: Bearer <jwt>`). It never holds an
// Anthropic API key. trust verifies the JWT, strips it, injects the real
// `x-api-key` from GCP Secret Manager, and forwards to api.anthropic.com.
//
// Run:  TRUST_JWT="$(../../scripts/mint-jwt.sh anthropic)" node query.mjs
import Anthropic from "@anthropic-ai/sdk";

const jwt = process.env.TRUST_JWT;
if (!jwt) {
  console.error("Set TRUST_JWT (e.g. TRUST_JWT=$(../../scripts/mint-jwt.sh anthropic))");
  process.exit(1);
}

const client = new Anthropic({
  // Point at trust's plain listener. The SDK appends /v1/messages; trust routes
  // by the Host header (here "localhost" → the `anthropic` upstream).
  baseURL: process.env.TRUST_URL ?? "http://localhost:6191",
  // The proxy JWT, NOT an Anthropic key. `authToken` sends it as
  // `Authorization: Bearer <jwt>` and omits `x-api-key` entirely — trust adds
  // the real key on the way out.
  authToken: jwt,
});

const message = await client.messages.create({
  model: "claude-opus-4-8",
  max_tokens: 256,
  messages: [{ role: "user", content: "Say hello from behind a credential-injecting proxy, in one sentence." }],
});

for (const block of message.content) {
  if (block.type === "text") console.log(block.text);
}
