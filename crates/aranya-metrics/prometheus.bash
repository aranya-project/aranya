#!/usr/bin/env bash

set -e # Exit on any errors

if ! command -v prometheus >/dev/null 2>&1; then
    echo "Error: Prometheus is not installed. Please install it using your favorite package manager."
    exit 1
fi

if ! command -v pushgateway >/dev/null 2>&1; then
    echo "Error: pushgateway is not installed. Please grab the latest binary from https://prometheus.io/download/#pushgateway"
    exit 1
fi

echo "Building our binaries..."
cargo build --bin aranya-daemon --release --features aqc,experimental
cargo build --bin aranya-metrics --release --features prometheus,aqc

# We assume that if they installed prometheus, it's already running in the background.
echo "Starting pushgateway..."
pushgateway &
PUSHGATEWAY_PID=$!

# Wait for `pushgateway` server endpoint
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

echo "Running metrics collection..."
CONFIG_PATH=crates/aranya-metrics/prometheus.toml $(pwd)/target/release/aranya-metrics $(pwd)/target/release/aranya-daemon
