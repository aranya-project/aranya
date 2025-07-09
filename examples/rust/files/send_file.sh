#!/bin/bash

set -xeuo pipefail

# Usage: ./send_file.sh [path/to/file]
# If no file is provided, defaults to data/test.yaml

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$SCRIPT_DIR/../../../../"

DAEMON_PATH="$WORKSPACE_ROOT/target/release/aranya-daemon"
SENDER_PATH="$WORKSPACE_ROOT/examples/rust/files/sender/target/release/sender"

if [ $# -eq 1 ]; then
  FILE_PATH="$1"
else
  FILE_PATH="$SCRIPT_DIR/data/test.yaml"
fi

cd "$WORKSPACE_ROOT" || exit 1

echo "Building aranya-daemon..."
cargo build --release --bin aranya-daemon

echo "Building sender example..."
cargo build --release --manifest-path examples/rust/files/sender/Cargo.toml --bin sender

echo "DAEMON_PATH: $DAEMON_PATH"
echo "FILE_PATH: $FILE_PATH"

echo "Running sender example with daemon: $DAEMON_PATH"
"$SENDER_PATH" "$DAEMON_PATH" "$FILE_PATH"

