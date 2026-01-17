#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

# Run the Aranya C examples.

set -xeuo pipefail

if command -v shellcheck; then
    shellcheck "${0}"
fi

cleanup() {
    jobs -p | xargs -I{} kill {} || true
}
trap 'cleanup' EXIT
trap 'trap - SIGTERM && cleanup && kill -- -$$ || true' SIGINT SIGTERM EXIT

# Run example
./example.bash
