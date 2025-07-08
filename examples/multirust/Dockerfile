FROM rust:1.88-bookworm AS build-daemon

WORKDIR /app/

COPY crates/aranya-daemon/ crates/aranya-daemon
COPY crates/aranya-daemon-api/ crates/aranya-daemon-api
COPY crates/aranya-keygen/ crates/aranya-keygen
COPY crates/aranya-util/ crates/aranya-util
COPY Cargo.toml .
COPY Cargo.lock .

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=daemon-target,sharing=locked,target=/app/target \
    cargo build --release -p aranya-daemon --bin aranya-daemon \
    && mkdir bin \
    && cp target/release/aranya-daemon bin/


FROM rust:1.88-bookworm AS build-example

WORKDIR /app/

COPY crates/aranya-client/ crates/aranya-client
COPY crates/aranya-daemon-api/ crates/aranya-daemon-api
COPY crates/aranya-util/ crates/aranya-util
COPY Cargo.toml .
COPY Cargo.lock .
COPY examples/multirust/src/ examples/multirust/src
COPY examples/multirust/Cargo.toml examples/multirust/
COPY examples/multirust/Cargo.lock examples/multirust/

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=example-target,sharing=locked,target=/app/examples/multirust/target \
    cd examples/multirust \
    && cargo build --release --bin aranya-example \
    && mkdir /app/bin \
    && cp target/release/aranya-example /app/bin/



FROM debian:bookworm

WORKDIR /app/

COPY --link --from=build-daemon /app/bin/aranya-daemon bin/aranya-daemon
COPY --link --from=build-example /app/bin/aranya-example bin/aranya-example

ENTRYPOINT ["/app/bin/aranya-example", "/app/bin/aranya-daemon"]
