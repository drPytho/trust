# syntax=docker/dockerfile:1

# ---- Builder ------------------------------------------------------------
# aws-lc-rs (JWT/rustls) needs cmake + a C toolchain + clang(libclang) for
# bindgen; pingora's `openssl` feature needs libssl-dev + pkg-config.
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        clang \
        libclang-dev \
        pkg-config \
        libssl-dev \
        perl \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies: copy manifests first, build a stub, then the real source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked || true \
    && rm -rf src

COPY . .
# Touch so cargo rebuilds with the real sources (stub build cached the deps).
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- Runtime ------------------------------------------------------------
# debian-slim provides libssl3 (pingora links system OpenSSL), ca-certificates
# (outbound TLS to GCP/upstreams), and `git` — required by the git-cache
# upstream, which shells out to `git http-backend` (serve) and `git fetch` (sync).
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/trust /usr/local/bin/trust

# Config path (mount your config.toml here); override with -e TRUST_CONFIG=...
ENV TRUST_CONFIG=/etc/trust/config.toml
ENV RUST_LOG=info

# proxy TCP / proxy TLS / mTLS token endpoint / JWKS
EXPOSE 6191 6443 8443 8080

ENTRYPOINT ["/usr/local/bin/trust"]
