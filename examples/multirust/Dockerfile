FROM ubuntu:22.04 AS base


FROM base AS build

# Update and install base dependencies
RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install build-essential curl

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs >rustup.sh && sh rustup.sh -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Common Aranya build setup
WORKDIR /app/

COPY crates/aranya-daemon-api/ crates/aranya-daemon-api
COPY crates/aranya-util/ crates/aranya-util
COPY Cargo.toml .
COPY Cargo.lock .

# Remove examples from workspace so we don't have to copy them in.
RUN sed -ie '\|"examples/rust/\*",|d' Cargo.toml


FROM build AS build-daemon

COPY crates/aranya-daemon/ crates/aranya-daemon
COPY crates/aranya-keygen/ crates/aranya-keygen

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=daemon-target,sharing=locked,target=/app/target \
    cargo build --release -p aranya-daemon --bin aranya-daemon \
    && mkdir /app/bin \
    && cp target/${CARGO_BUILD_TARGET}/release/aranya-daemon bin/


FROM build AS build-provision

COPY crates/aranya-client/ crates/aranya-client
COPY examples/multirust/src/bin/aranya-provision.rs examples/multirust/src/bin/aranya-provision.rs
COPY examples/multirust/Cargo.toml examples/multirust/
COPY examples/multirust/Cargo.lock examples/multirust/

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=provision-target,sharing=locked,target=/app/examples/multirust/target \
    cd examples/multirust \
    && cargo build --release --bin aranya-provision \
    && mkdir /app/bin \
    && cp target/${CARGO_BUILD_TARGET}/release/aranya-provision /app/bin/


FROM build AS build-user

COPY crates/aranya-client/ crates/aranya-client
COPY examples/multirust/src/bin/aranya-user.rs examples/multirust/src/bin/aranya-user.rs
COPY examples/multirust/Cargo.toml examples/multirust/
COPY examples/multirust/Cargo.lock examples/multirust/

RUN --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=user-target,sharing=locked,target=/app/examples/multirust/target \
    cd examples/multirust \
    && cargo build --release --bin aranya-user \
    && mkdir /app/bin \
    && cp target/${CARGO_BUILD_TARGET}/release/aranya-user /app/bin/


FROM base AS runner

WORKDIR /app/

COPY --link --from=build-daemon /app/bin/aranya-daemon bin/daemon


FROM runner AS provision

COPY --link --from=build-provision /app/bin/aranya-provision bin/provision

RUN ["/app/bin/provision", "/app/bin/daemon"]


FROM runner AS operator

COPY --link --from=build-user /app/bin/aranya-user bin/operator
COPY --link --from=provision /app/daemons/operator/state/ state

ENTRYPOINT [ "/app/bin/operator", "/app/bin/daemon" ]


FROM runner AS member-a

COPY --link --from=build-user /app/bin/aranya-user bin/member-a
COPY --link --from=provision /app/daemons/member-a/state/ state

ENTRYPOINT [ "/app/bin/member-a", "/app/bin/daemon" ]


FROM runner AS member-b

COPY --link --from=build-user /app/bin/aranya-user bin/member-b
COPY --link --from=provision /app/daemons/member-b/state/ state

ENTRYPOINT [ "/app/bin/member-b", "/app/bin/daemon" ]
