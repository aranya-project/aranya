#!/usr/bin/env bash
# Wrapper script to run C tests and ensure daemon cleanup
# Usage: run_test_with_cleanup.sh <test_executable> [daemon_path]

set -e

TEST_EXEC="$1"
DAEMON_PATH="$2"

# Track all child processes for cleanup
cleanup() {
    local exit_code=$?
    echo "Cleaning up processes..."
    
    # Kill all child processes of this script
    pkill -P $$ 2>/dev/null || true
    
    # Kill any aranya-daemon processes that might be orphaned
    pkill -f "aranya-daemon.*test-.*-daemon" 2>/dev/null || true
    
    # Give processes time to exit cleanly
    sleep 1
    
    # Force kill any remaining processes
    pkill -9 -P $$ 2>/dev/null || true
    pkill -9 -f "aranya-daemon.*test-.*-daemon" 2>/dev/null || true
    
    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT INT TERM

# Run the test
if [ -n "$DAEMON_PATH" ]; then
    "$TEST_EXEC" "$DAEMON_PATH"
else
    "$TEST_EXEC"
fi

# Capture the exit code
TEST_EXIT_CODE=$?

# Exit with the test's exit code (cleanup will run via trap)
exit $TEST_EXIT_CODE
