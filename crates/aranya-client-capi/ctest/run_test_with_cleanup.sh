#!/usr/bin/env bash
# Wrapper script to run C tests and ensure daemon cleanup
# Usage: run_test_with_cleanup.sh <test_executable> <daemon_path> <daemon_names>
#   daemon_names: comma-separated list of daemon names to spawn (e.g., "owner,member")

set -e

TEST_EXEC="$1"
DAEMON_PATH="$2"
DAEMON_NAMES="$3"
TEST_NAME=$(basename "$TEST_EXEC")

# PIDs to track spawned daemons
DAEMON_PIDS=()

# Temp directory for this test run
TMPDIR=""

# Track all child processes for cleanup
cleanup() {
    local exit_code=$?
    echo "Cleaning up processes..."
    
    # First attempt: SIGTERM for clean shutdown
    # Kill tracked daemon PIDs
    for pid in "${DAEMON_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Also kill any orphaned test daemons by pattern
    pkill -f "aranya-daemon.*test-.*-daemon" 2>/dev/null || true
    
    # Wait briefly for clean shutdown
    sleep 1
    
    # Second attempt: SIGKILL for any remaining processes
    for pid in "${DAEMON_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    pkill -9 -f "aranya-daemon.*test-.*-daemon" 2>/dev/null || true
    
    # Remove temp directory
    if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
        rm -rf "$TMPDIR"
    fi
    
    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT INT TERM

# Function to spawn a daemon
spawn_daemon() {
    local run_dir="$1"
    local daemon_name="$2"
    local shm_path="$3"
    local sync_port="$4"
    
    # Create run directory and subdirectories
    mkdir -p "$run_dir/state" "$run_dir/cache" "$run_dir/logs" "$run_dir/config"
    
    # Create daemon config
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
EOF
    
    # Spawn daemon
    ARANYA_DAEMON=aranya_daemon::aranya_daemon::api=debug \
        "$DAEMON_PATH" --config "$run_dir/daemon.toml" &
    
    local pid=$!
    DAEMON_PIDS+=($pid)
    echo "Spawned daemon '$daemon_name' (PID: $pid) at $run_dir"
}

# Spawn daemons if daemon names are provided
if [ -n "$DAEMON_NAMES" ]; then
    echo "=== Spawning daemons: $DAEMON_NAMES ==="
    
    # Create unique temp directory
    TMPDIR=$(mktemp -d)
    echo "Using temp directory: $TMPDIR"
    
    # Parse comma-separated daemon names
    IFS=',' read -ra NAMES <<< "$DAEMON_NAMES"
    PORT=40001
    
    for name in "${NAMES[@]}"; do
        spawn_daemon "$TMPDIR/$name" "test-daemon-$TEST_NAME-$name" "/$TEST_NAME-$name" "$PORT"
        PORT=$((PORT + 1))
    done
    
    # Wait for daemons to initialize
    echo "Waiting 2 seconds for daemons to initialize..."
    sleep 2
    echo "Daemons should be ready"
fi

# Run the test
if [ -n "$TMPDIR" ]; then
    "$TEST_EXEC" "$TMPDIR"
else
    "$TEST_EXEC"
fi

# Capture the exit code
TEST_EXIT_CODE=$?

# Exit with the test's exit code
exit $TEST_EXIT_CODE
