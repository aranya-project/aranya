#!/usr/bin/env bash

# `cargo-fmt` wrapper to set unstable config options via command line.

set -eu

base=$(dirname -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")")

cargo_args=()
while [[ $# -gt 0 ]]; do
    arg="$1"
    shift
    if [[ "$arg" = "--" ]]; then
        break;
    fi
    cargo_args+=("$arg")
done

rustfmt_args=("$@")
while IFS=' =' read -r key value; do
    rustfmt_args+=(--config "$key=${value//\"/}")
done < "$base/rustfmt.toml"

exec cargo fmt ${cargo_args[@]+"${cargo_args[@]}"} -- ${rustfmt_args[@]+"${rustfmt_args[@]}"}
