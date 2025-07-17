#!/bin/bash

# Parse command line arguments
TEST_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --test)
            TEST_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--test]"
            exit 1
            ;;
    esac
done

if ! aranya --help >/dev/null 2>&1; then
  cargo install --path "$(dirname "$0")/../../crates/aranya-cli"
fi

# Build both the example and daemon in release mode (following run.bash pattern)
current_dir="$(pwd)"

cargo build \
    --release \
    --manifest-path "$(dirname "$0")/../Cargo.toml" \
    --locked

cargo build \
    --release \
    --manifest-path "$(dirname "$0")/../../../Cargo.toml" \
    --bin aranya-daemon

daemon="$(cd "$(dirname "$0")/../../../target/release" && pwd)/aranya-daemon"

if [ "$TEST_MODE" = true ]; then
    # Run the example and capture all output, but also extract export lines for env vars
    UDS_OUTPUT=""
    while IFS= read -r line; do
        if [[ $line == export* ]]; then
            UDS_OUTPUT+="$line"$'\n'
            eval "$line"
        fi
    done < <("$(dirname "$0")/../target/release/aranya-example" "${daemon}")

    # Wait for daemons to fully initialize
    echo "⏳ Waiting for daemons to initialize..."
    sleep 3

    # Run command testing script
    "$(dirname "$0")/command-testing.sh"
else
    "$(dirname "$0")/../target/release/aranya-example" "${daemon}"
fi


