#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

set -xeuo pipefail

if command -v shellcheck; then
    shellcheck "${0}"
fi

cleanup() {
    jobs -p | xargs -I{} kill {} || true
}
trap 'cleanup' EXIT
trap 'trap - SIGTERM && cleanup && kill -- -$$ || true' SIGINT SIGTERM EXIT

script_dir="$(dirname "$0")"

# Back to root of the repo.
pushd "${script_dir}"
pushd ../../../

current_dir="$(pwd)"

echo "Building binaries..."
cargo build \
    --release \
    --package aranya-example-multi-node \
    --package aranya-daemon \
    --features afc,preview \
    --locked

workspace="${current_dir}/examples/rust/aranya-example-multi-node"
release="${current_dir}/target/release"
example="${current_dir}/target/release/aranya-example-multi-node"

echo "Running aranya-example-multi-node..."
"${example}" "${release}" "${workspace}"
