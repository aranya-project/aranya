#!/usr/bin/env bash
# Wrapper script to run C tests and ensure daemon cleanup
# Usage: execute_test.sh <test_executable> <daemon_path> <certgen_path> <daemon_names>
#   daemon_names: comma-separated list of daemon names to spawn (e.g., "owner,member")

set -xeuo pipefail

test_exec="$1"
daemon_path="$2"
certgen_path="$3"
daemon_names="$4"
test_name=$(basename "$test_exec")

# PIDs to track spawned daemons
daemon_pids=()

# Temp directory for this test run
tmpdir=""

# Track all child processes for cleanup
# shellcheck disable=SC2329
cleanup() {
    local exit_code=$?
    echo "Cleaning up processes..."

    # First attempt: SIGTERM for clean shutdown
    # Kill tracked daemon PIDs
    for pid in "${daemon_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Also kill any orphaned test daemons by pattern
    pkill -f "aranya-daemon.*test-.*-daemon" 2>/dev/null || true

    # Wait briefly for clean shutdown
    sleep 1

    # Second attempt: SIGKILL for any remaining processes
    for pid in "${daemon_pids[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    pkill -9 -f "aranya-daemon.*test-.*-daemon" 2>/dev/null || true

    # Remove temp directory
    if [ -n "$tmpdir" ] && [ -d "$tmpdir" ]; then
        rm -rf "$tmpdir"
    fi

    exit "$exit_code"
}

# Set up cleanup trap
trap cleanup EXIT INT TERM

# Function to spawn a daemon
spawn_daemon() {
    local run_dir="$1"
    local daemon_name="$2"
    local shm_path="$3"
    local sync_port="$4"
    local root_certs_dir="$5"
    local config_dir="$6"

    # Create run directory and subdirectories
    mkdir -p "$run_dir/state" "$run_dir/cache" "$run_dir/logs" "$run_dir/config"

    # Create daemon config with mTLS settings
    cat > "$run_dir/daemon.toml" <<EOF
name = "$daemon_name"
runtime_dir = "$run_dir"
state_dir = "$run_dir/state"
cache_dir = "$run_dir/cache"
logs_dir = "$run_dir/logs"
config_dir = "$run_dir/config"

[afc]
enable = true
shm_path = "$shm_path"
max_chans = 100

[sync.quic]
enable = true
addr = "127.0.0.1:$sync_port"
root_certs_dir = "$root_certs_dir"
device_cert = "$config_dir/device.crt.pem"
device_key = "$config_dir/device.key.pem"
EOF

    # Spawn daemon
    ARANYA_DAEMON=aranya_daemon::aranya_daemon::api=debug \
        "$daemon_path" --config "$run_dir/daemon.toml" &

    local pid=$!
    daemon_pids+=("$pid")
    echo "Spawned daemon '$daemon_name' (PID: $pid) at $run_dir"
}

tmpdir=""
# Spawn daemons if daemon names are provided
if [ -n "$daemon_names" ]; then
    echo "=== Spawning daemons: $daemon_names ==="

    # Create unique temp directory
    tmpdir=$(mktemp -d)
    echo "Using temp directory: $tmpdir"

    # Create certificate directory
    root_certs_dir="$tmpdir/root_certs"
    mkdir -p "$root_certs_dir"

    # Generate CA certificate
    echo "Generating CA certificate..."
    "$certgen_path" ca --cn "Test CA" --output "$root_certs_dir/ca"

    # Parse comma-separated daemon names
    IFS=',' read -ra names <<< "$daemon_names"
    port=40001

    for name in "${names[@]}"; do
        config_dir="$tmpdir/$name/config"
        mkdir -p "$config_dir"

        # Generate device certificate signed by CA
        # Use 127.0.0.1 as CN to create IP SAN
        echo "Generating certificate for $name..."
        "$certgen_path" signed "$root_certs_dir/ca" --cn 127.0.0.1 --output "$config_dir/device"

        spawn_daemon "$tmpdir/$name" "test-daemon-$test_name-$name" "/$test_name-$name" "$port" "$root_certs_dir" "$config_dir"
        port=$((port + 1))
    done

    # Wait for daemons to initialize
    echo "Waiting 2 seconds for daemons to initialize..."
    sleep 2
    echo "Daemons should be ready"
fi

# Run the test
"$test_exec" "$tmpdir"

exit $?
