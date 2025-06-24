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

# Run example with randomly generated QUIC syncer PSK seed
./example.bash

# Run example with raw QUIC syncer PSK seed IKM
./example.bash raw_seed_ikm
