#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

set -xeuo pipefail

if command -v shellcheck; then
    shellcheck "${0}"
fi

# TODO(eric): It is silly to require patchelf on non-ELF systems.
if ! command -v patchelf &>/dev/null; then
    echo "please install patchelf"
    exit 1
fi

if ! command -v cargo &>/dev/null; then
    echo "please install Rust"
    exit 1
fi

if ! command -v cmake &>/dev/null; then
    echo "please install cmake"
    exit 1
fi

declare -a devices=("owner" "admin" "operator" "membera" "memberb")

proj="$(cargo locate-project --workspace --message-format plain)"
proj="$(dirname "${proj}")"
release="${proj}/target/release"
capi="${proj}/crates/aranya-client-capi"
example="${proj}/examples/c"
out="${example}/out"

cleanup() {
    jobs -p | xargs -I{} kill {} || true
}
trap 'cleanup' EXIT
trap 'trap - SIGTERM && cleanup && kill -- -$$ || true' SIGINT SIGTERM EXIT

rm -rf "${out}"

# build the daemon.
cargo build --bin aranya-daemon --release

# copy the aranya-client.h header file
mkdir -p "${example}/include"
cp "${capi}/output/aranya-client.h" "${example}/include/aranya-client.h"

# copy the shared library
mkdir -p "${example}/lib"
cp "${release}/libaranya_client_capi.dylib" "${example}/lib/libaranya_client.dylib" ||
    cp "${release}/libaranya_client_capi.so" "${example}/lib/libaranya_client.so"
patchelf --set-soname libaranya_client.so "${example}/lib/libaranya_client.so" || true
ls "${example}/lib"

# build the example app.
Aranya_DIR=. CMAKE_LIBRARY_PATH=. CMAKE_INCLUDE_PATH=. cmake -S "${example}" -B "${example}/build"
cmake --build build

# start the daemons
for device in "${devices[@]}"; do
    mkdir -p "${out}/${device}"
    # TODO: autogenerate these config files
    # Note: set ARANYA_DAEMON=debug to debug daemons.
    cfg_path="${example}/configs/${device}-config.json"
    api_pk="${out}/${device}/api_pk"
    rm -I "${api_pk}" || true

    ARANYA_DAEMON=trace \
        "${release}/aranya-daemon" \
        --config "${cfg_path}" \
        --print-api-pk | tee "${api_pk}"

    ARANYA_DAEMON="aranya_daemon::aqc=trace,aranya_daemon::api=debug" \
        "${release}/aranya-daemon" \
        --config "${cfg_path}" &
done
# give the daemons time to startup
sleep 1

# start the example app.
# TODO: rm ASAN_OPTIONS when memory leaks are resolved.
ASAN_OPTIONS=detect_leaks=0:exitcode=0 \
    ARANYA_CAPI="aranya=debug,aranya_capi_core=info" \
    ./build/example
