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

devices=("owner" "admin" "operator" "membera" "memberb")

for device in "${devices[@]}"; do
    echo "Building aranya-example-multi-node-${device}..."
    cargo build \
        --release \
        --manifest-path Cargo.toml \
        --bin aranya-example-multi-node-"${device}" \
        --features aqc \
        --locked
done

echo "Building aranya-daemon..."
cargo build \
    --release \
    --manifest-path Cargo.toml \
    --bin aranya-daemon \
    --features experimental,aqc,preview,afc

echo "Building aranya-example-multi-node..."
ARANYA_EXAMPLE=info cargo run \
    --release \
    --manifest-path Cargo.toml \
    --bin aranya-example-multi-node \
    --locked
