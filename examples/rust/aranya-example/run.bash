#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

set -xeuo pipefail

script_dir="$(dirname "$0")"

# Back to root of the repo.
pushd "${script_dir}"
pushd ../../../

current_dir="$(pwd)"

echo "Building aranya-example..."
cargo build \
    --release \
    --manifest-path Cargo.toml \
    --bin aranya-example \
    --locked

echo "Building aranya-daemon..."
cargo build \
    --release \
    --manifest-path Cargo.toml \
    --bin aranya-daemon

daemon="${current_dir}/target/release/aranya-daemon"
example="${current_dir}/target/release/aranya-example"

echo "Running aranya-example with daemon: ${daemon}"
"${example}" "${daemon}"
