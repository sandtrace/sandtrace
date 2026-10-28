FROM rust:1.87-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY rules ./rules

RUN cargo build --release --bin sandtrace

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source=https://github.com/sandtrace/sandtrace

# git: audit uses `git check-ignore` to skip gitignored env files.
# safe.directory: bind-mounted repos are owned by another uid, which git refuses.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*' \
    && useradd --create-home sandtrace

COPY --from=builder /app/target/release/sandtrace /usr/local/bin/sandtrace

USER sandtrace
WORKDIR /src

ENTRYPOINT ["sandtrace"]
