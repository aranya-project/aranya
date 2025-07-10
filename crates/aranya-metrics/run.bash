#!/usr/bin/env bash

set -e # Exit on any errors

if ! command -v pushgateway >/dev/null 2>&1; then
    echo "Error: pushgateway is not installed. Please grab the latest binary from https://prometheus.io/download/#pushgateway"
    exit 1
fi

echo "Building our binaries..."
cargo build --bin aranya-daemon --release
cargo build --bin aranya-metrics --release

echo "Starting pushgateway..."
pushgateway &
PUSHGATEWAY_PID=$!

for i in {1..24}; do
    if curl -s http://localhost:9091/metrics >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

cleanup() {
    jobs -p | xargs -I{} kill {} || true
}
trap 'cleanup' EXIT
trap 'trap - SIGTERM && cleanup && kill -- -$$ || true' SIGINT SIGTERM EXIT

cd crates/aranya-metrics

echo "Running metrics collection..."
CONFIG_PATH=example.hjson cargo run --release -- $(pwd)/../../target/release/aranya-daemon