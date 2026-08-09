# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS build
WORKDIR /src

# libsqlite3-sys compiles a bundled SQLite, so a C toolchain is required. The
# rust:*-slim images already carry gcc and libc6-dev.
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./

# Build the dependency graph against a stub main so it lands in its own cached
# layer; a source-only change then rebuilds just this crate rather than all of
# axum/sqlx/tokio, which is the bulk of a cold build.
#
# `--mount=type=cache` would be the tidier way to do this, but it hard-fails on
# the legacy builder with "the --mount option requires BuildKit". This form
# works on both, at the cost of one throwaway compile of the stub.
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src

COPY src/ src/

# cargo decides what is stale by mtime, and the stub's artifacts carry this
# crate's name; drop them or the real sources are silently not compiled.
RUN rm -f target/release/gesh-server target/release/deps/gesh_server* \
 && cargo build --release --locked

FROM debian:bookworm-slim AS runtime

# No ca-certificates: the relay makes no outbound TLS connections.
RUN useradd --system --uid 10001 --shell /usr/sbin/nologin gesh

COPY --from=build /src/target/release/gesh-server /usr/local/bin/gesh-server

# Unprivileged. Whatever is mounted at /data must be writable by this uid.
USER 10001
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/gesh-server"]
