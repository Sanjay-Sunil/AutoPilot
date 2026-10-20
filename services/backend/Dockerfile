# syntax=docker/dockerfile:1.7
# Build from the repo root:  docker build -f services/backend/Dockerfile .
# Produces a static musl binary in a distroless image (~10 MB).

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
ENV CARGO_TARGET_DIR=/target
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    cargo build --release -p backend --features db \
 && cp /target/release/backend /backend

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /backend /backend
ENV BIND=0.0.0.0:8080 RUST_LOG=info
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/backend"]
