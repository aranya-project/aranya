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


FROM rust:1.88-bookworm AS build-provision

WORKDIR /app/

COPY crates/aranya-client/ crates/aranya-client
COPY crates/aranya-daemon-api/ crates/aranya-daemon-api
COPY crates/aranya-util/ crates/aranya-util
COPY Cargo.toml .
COPY Cargo.lock .
COPY examples/multirust/src/bin/aranya-provision.rs examples/multirust/src/bin/aranya-provision.rs
COPY examples/multirust/Cargo.toml examples/multirust/
COPY examples/multirust/Cargo.lock examples/multirust/

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=provision-target,sharing=locked,target=/app/examples/multirust/target \
    cd examples/multirust \
    && cargo build --release --bin aranya-provision \
    && mkdir /app/bin \
    && cp target/release/aranya-provision /app/bin/



FROM debian:bookworm AS provision

WORKDIR /app/

COPY --link --from=build-daemon /app/bin/aranya-daemon bin/aranya-daemon
COPY --link --from=build-provision /app/bin/aranya-provision bin/aranya-provision

RUN /app/bin/aranya-provision /app/bin/aranya-daemon


FROM rust:1.88-bookworm AS build-user

WORKDIR /app/

COPY crates/aranya-client/ crates/aranya-client
COPY crates/aranya-daemon-api/ crates/aranya-daemon-api
COPY crates/aranya-util/ crates/aranya-util
COPY Cargo.toml .
COPY Cargo.lock .
COPY examples/multirust/src/bin/aranya-user.rs examples/multirust/src/bin/aranya-user.rs
COPY examples/multirust/Cargo.toml examples/multirust/
COPY examples/multirust/Cargo.lock examples/multirust/

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=example-target,sharing=locked,target=/app/examples/multirust/target \
    cd examples/multirust \
    && cargo build --release --bin aranya-user \
    && mkdir /app/bin \
    && cp target/release/aranya-user /app/bin/


FROM debian:bookworm AS operator

WORKDIR /app/

COPY --link --from=build-daemon /app/bin/aranya-daemon bin/daemon
COPY --link --from=build-user /app/bin/aranya-user bin/operator
COPY --link --from=provision /app/daemons/operator/state/ state

ENTRYPOINT [ "/app/bin/operator", "/app/bin/daemon" ]


FROM debian:bookworm AS member-a

WORKDIR /app/

COPY --link --from=build-daemon /app/bin/aranya-daemon bin/daemon
COPY --link --from=build-user /app/bin/aranya-user bin/member-a
COPY --link --from=provision /app/daemons/member-a/state/ state

ENTRYPOINT [ "/app/bin/member-a", "/app/bin/daemon" ]


FROM debian:bookworm AS member-b

WORKDIR /app/

COPY --link --from=build-daemon /app/bin/aranya-daemon bin/daemon
COPY --link --from=build-user /app/bin/aranya-user bin/member-b
COPY --link --from=provision /app/daemons/member-b/state/ state

ENTRYPOINT [ "/app/bin/member-b", "/app/bin/daemon" ]
