#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

set -xeuo pipefail

script_dir=
script_dir="$(dirname "$0")"

# Back to root of the repo.
pushd "${script_dir}"
pushd ../../

current_dir="$(pwd)"

cargo build \
    --release \
    --manifest-path "examples/rust/Cargo.toml" \
    --locked

cargo build \
    --release \
    --manifest-path Cargo.toml \
    --bin aranya-daemon
daemon="${current_dir}/target/release/aranya-daemon"

"examples/rust/target/release/aranya-example" "${daemon}"
