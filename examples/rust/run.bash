#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.
#
# Aranya Rust Example Runner
#
# Usage:
#   ./run.bash

set -euo pipefail

# Configuration
readonly EXAMPLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WORKSPACE_ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
readonly RELEASE_DIR="${WORKSPACE_ROOT}/target/release"

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

    command -v cargo >/dev/null || missing_deps+=("cargo")

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        die "Missing required dependencies: ${missing_deps[*]}"
    fi
}

build_components() {
    cd "${WORKSPACE_ROOT}"

    log_info "Building daemon with full features..."
    cargo make build

    log_info "Building Rust example..."
    cargo make build-example-rust

    cd "${EXAMPLE_ROOT}"
}

run_example() {
    local daemon="${RELEASE_DIR}/aranya-daemon"
    local example="${WORKSPACE_ROOT}/examples/rust/target/release/aranya-example"

    # Verify binaries exist
    [[ -f "${daemon}" ]] || die "Daemon binary not found: ${daemon}"
    [[ -f "${example}" ]] || die "Daemon binary not found: ${example}"

    log_info "Running Rust example with daemon: ${daemon}"

    "${example}" "${daemon}"
}

main() {
    log_info "Starting Rust example"

    check_dependencies
    build_components
    run_example

    log_info "Example completed successfully!"
}

# Show usage if requested
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    head -n 8 "${0}" | grep "^#" | grep -v "^#!/" | sed 's/^# *//'
    exit 0
fi

main "$@"