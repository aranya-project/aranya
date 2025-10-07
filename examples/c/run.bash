#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.
#
# Aranya C API Example Runner
#
# Usage:
#   ./run.bash [FEATURES] [MODE]
#
# FEATURES:
#   default      - Build with default features
#   preview      - Build with preview features
#   experimental - Build with experimental features
#   full         - Build with all features (default)
#
# MODE:
#   single       - Run example once with random QUIC PSK seed
#   dual         - Run example twice (random + raw seed) (default)
#   raw_seed_ikm - Run example with raw QUIC PSK seed

set -xeuo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WORKSPACE_ROOT="$(cargo locate-project --workspace --message-format plain | xargs dirname)"
readonly RELEASE_DIR="${WORKSPACE_ROOT}/target/release"
readonly CAPI_DIR="${WORKSPACE_ROOT}/crates/aranya-client-capi"
readonly EXAMPLE_DIR="${WORKSPACE_ROOT}/examples/c"
readonly OUT_DIR="${EXAMPLE_DIR}/out"

# Default values
FEATURES="${1:-full}"
MODE="${2:-dual}"

# Device configuration
readonly DEVICES=("owner" "admin" "operator" "membera" "memberb")
readonly BASE_PORT=10001

cleanup() {
    local pids

    # Get list of background job PIDs, ignore if none exist
    if pids=$(jobs -p 2>/dev/null) && [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true

        # Give tasks a moment to terminate gracefully
        sleep 0.5

        # Force kill any stragglers
        if pids=$(jobs -p 2>/dev/null) && [[ -n "$pids" ]]; then
            echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
        fi
    fi
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

log_info() {
    echo "INFO: $*" >&2
}

log_error() {
    echo "ERROR: $*" >&2
}

die() {
    log_error "$*"
    exit 1
}

check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    command -v patchelf >/dev/null || missing_deps+=("patchelf")
    command -v cargo >/dev/null || missing_deps+=("cargo")
    command -v cmake >/dev/null | missing_deps+=("cmake")

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        die "Missing required dependencies: ${missing_deps[*]}"
    fi
}

get_make_task_suffix() {
    case "${FEATURES}" in
        "default")      echo "-default" ;;
        "preview")      echo "-preview" ;;
        "experimental") echo "-experimental" ;;
        "full")         echo "" ;;
        *)              die "Unknown features: ${FEATURES}." ;;
    esac
}

generate_device_config() {
    local device="$1"
    local port="$2"
    local config_file="${EXAMPLE_DIR}/configs/${device}-config.toml"

    mkdir -p "$(dirname "${config_file}")"

    cat > "${config_file}" <<EOF
name = "${device}"
runtime_dir = "${OUT_DIR}/${device}/run"
state_dir = "${OUT_DIR}/${device}/state"
cache_dir = "${OUT_DIR}/${device}/cache"
logs_dir = "${OUT_DIR}/${device}/log"
config_dir = "${OUT_DIR}/${device}/config"

aqc.enable = true

[afc]
enable = true
shm_path = "/shm_${device}"
max_chans = 100

[sync.quic]
enable = true
addr = "127.0.0.1:${port}"
EOF
}

setup_device_configs() {
    log_info "Setting up device configurations..."

    local port="${BASE_PORT}"
    for device in "${DEVICES[@]}"; do
        generate_device_config "${device}" "${port}"
        ((port++))
    done
}

build_components() {
    log_info "Building components with features: ${FEATURES}..."

    local task_suffix="$(get_make_task_suffix)"

    log_info "Building daemon..."
    cargo make build${task_suffix}

    log_info "Building C API header..."
    cargo make capi-header

    log_info "Building C API library..."
    cargo make capi-lib${task_suffix}
}

setup_example_environment() {
    log_info "Setting up example environment..."

    # Clean and create any directories
    rm -rf "${OUT_DIR}"
    mkdir -p "${EXAMPLE_DIR}/include" "${EXAMPLE_DIR}/lib"

    cp "${CAPI_DIR}/output/aranya-client.h" "${EXAMPLE_DIR}/include/"

    # Copy platform-specific library
    if [[ "$OSTYPE" == "darwin"* ]]; then
        cp "${RELEASE_DIR}/libaranya_client_capi.dylib" "${EXAMPLE_DIR}/lib/libaranya_client.dylib"
    else
        cp "${RELEASE_DIR}/libaranya_client_capi.so" "${EXAMPLE_DIR}/lib/libaranya_client.so"
        patchelf --set-soname libaranya_client.so "${EXAMPLE_DIR}/lib/libaranya_client.so" 2>/dev/null || true
    fi

    log_info "Library files:"
    ls -la "${EXAMPLE_DIR}/lib/"
}

get_compile_flags() {
    local cmake_flags=""

    case "${FEATURES}" in
        "default")
            cmake_flags=""
            ;;
        "preview")
            cmake_flags="-DENABLE_ARANYA_PREVIEW -DENABLE_ARANYA_AFC"
            ;;
        "experimental")
            cmake_flags="-DENABLE_ARANYA_PREVIEW -DENABLE_ARANYA_AFC -DENABLE_ARANYA_EXPERIMENTAL -DENABLE_ARANYA_AQC"
            ;;
        "full")
            cmake_flags="-DENABLE_ARANYA_PREVIEW -DENABLE_ARANYA_AFC -DENABLE_ARANYA_EXPERIMENTAL -DENABLE_ARANYA_AQC"
            ;;
        *)
            die "Unknown features: ${FEATURES}"
    esac

    # Return the appropriate CMake flags
    echo "${cmake_flags}"
}

build_example_app() {
    log_info "Building example application..."

    # TODO(nikki): separate funcs for compile flags and feature toggles?
    local cmake_flags="$(get_compile_flags)"

    cd "${EXAMPLE_DIR}"
    log_info "CMake flags for ${FEATURES} features: ${cmake_flags:-<none>}"
    Aranya_DIR=. CMAKE_LIBRARY_PATH=. CMAKE_INCLUDE_PATH=. \
        cmake -S . -B build -DCMAKE_C_FLAGS="${cmake_flags}"
    cmake --build build
}

start_daemons() {
    log_info "Starting daemon instances..."

    for device in "${DEVICES[@]}"; do
        # Create device directories
        for dir in run state cache log config; do
            mkdir -p "${OUT_DIR}/${device}/${dir}"
        done

        # Start daemon
        local config_file="${EXAMPLE_DIR}/configs/${device}-config.toml"

        ARANYA_DAEMON="aranya_daemon::aqc=trace,aranya_daemon::api=debug" \
            "${RELEASE_DIR}/aranya-daemon" \
            --config "${config_file}" &

        log_info "Started daemon for ${device} (PID: $!)"
    done

    log_info "Waiting for daemons to initialize..."
    sleep 2
}

run_example() {
    local args=("$@")

    log_info "Running example application with args: ${args[*]:-<none>}"

    cd "${EXAMPLE_DIR}"
    ASAN_OPTIONS=detect_leaks=0 \
        ARANYA_CAPI=aranya=debug \
        ./build/example "${args[@]+"${args[@]}"}"
}

main() {
    log_info "Starting C API example (features: ${FEATURES}, mode: ${MODE})"

    cd "${WORKSPACE_ROOT}"
    check_dependencies
    setup_device_configs
    build_components
    setup_example_environment
    build_example_app
    start_daemons

    case "${MODE}" in
        "single")
            run_example
            ;;
        "dual")
            log_info "Running dual mode - random seed then raw seed"
            run_example
            sleep 1
            run_example "raw_seed_ikm"
            ;;
        "raw_seed_ikm")
            run_example "raw_seed_ikm"
            ;;
        *)
            die "Unknown mode: ${MODE}."
            ;;
    esac

    log_info "Example completed successfully!"
}

# Show usage if requested
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    head -n 20 "${0}" | grep "^#" | grep -v "^#!/" | sed 's/^# *//'
    exit 0
fi

main "$@"