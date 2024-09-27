#!/usr/bin/env bash

set -aeuo pipefail

if command -v shellcheck; then
	shellcheck "${0}"
fi

cleanup() {
	jobs -p | xargs -I{} kill {}
}
trap 'cleanup' EXIT
trap 'trap - SIGTERM && kill -- -$$ || true' SIGINT SIGTERM EXIT

# flag to select debug or release builds
export release=${RELEASE:-1}
# flag to skip building executables
export skip_build=${SKIP_BUILD:-0}

proj=
proj="$(cargo locate-project --workspace --message-format plain)"
proj="$(dirname "${proj}")"

out_dir="${proj}/scripts/daemon/out"
mkdir -p "${out_dir}"

target_dir="${proj}/target/debug"
export release_flag=
if [ "${release}" == "1" ]; then
	target_dir="${proj}/target/release"
	release_flag="--release"
fi

if [ "${skip_build}" != "1" ]; then
    cargo build --locked ${release_flag}
fi

rm -rf "${out_dir}" && mkdir -p "${out_dir}"

# copy daemon config into out dir.
cp ./config.json "${out_dir}"/config.json

# start daemon
ARANYA_DAEMON="debug" "${target_dir}"/daemon "${out_dir}"/config.json
