#!/bin/bash

# Aranya Multi-Daemon Cleanup Script
# This script removes all temporary files, keystores, and processes created by the Aranya multi-daemon setup

set -e

echo "=== Aranya Multi-Daemon Cleanup Script ==="
echo ""

# Function to check if a process is running
check_process() {
    local process_name="$1"
    if pgrep -f "$process_name" > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to kill a process safely
kill_process() {
    local process_name="$1"
    local display_name="$2"
    
    if check_process "$process_name"; then
        echo "Stopping $display_name..."
        pkill -f "$process_name" || true
        sleep 2
        
        # Force kill if still running
        if check_process "$process_name"; then
            echo "Force killing $display_name..."
            pkill -9 -f "$process_name" || true
        fi
    else
        echo "$display_name is not running"
    fi
}

# Kill Aranya processes
echo "Stopping Aranya processes..."
kill_process "aranya-daemon" "All Aranya Daemons"
kill_process "aranya" "Aranya CLI"

# Remove temporary directories
echo ""
echo "Removing temporary directories..."

# Original Aranya runtime directory
if [ -d "/tmp/aranya" ]; then
    echo "Removing /tmp/aranya..."
    rm -rf /tmp/aranya
fi

# Multi-daemon directories (aranya1-aranya5)
echo "Removing multi-daemon directories..."
for i in {1..5}; do
    if [ -d "/tmp/aranya$i" ]; then
        echo "Removing /tmp/aranya$i..."
        rm -rf /tmp/aranya$i
    fi
done

# Remove PID files from daemon directories
echo "Cleaning up PID files..."
for i in {1..5}; do
    if [ -f "/tmp/aranya$i/daemon.pid" ]; then
        echo "Removing /tmp/aranya$i/daemon.pid..."
        rm -f /tmp/aranya$i/daemon.pid
    fi
done

# Temporary keystore directories
echo "Removing temporary keystores..."
for keystore in /tmp/aranya_keys_*; do
    if [ -d "$keystore" ]; then
        echo "Removing $keystore..."
        rm -rf "$keystore"
    fi
done

# Remove generated files
echo ""
echo "Removing generated files..."

# Multi-daemon config files
echo "Removing daemon config files..."
for i in {1..5}; do
    if [ -f "config_daemon$i.json" ]; then
        echo "Removing config_daemon$i.json..."
        rm -f config_daemon$i.json
    fi
done

# CSV file with device info
if [ -f "../devices_with_keys.csv" ]; then
    echo "Removing ../devices_with_keys.csv..."
    rm -f ../devices_with_keys.csv
fi

# Team environment file
if [ -f "../team_env.sh" ]; then
    echo "Removing ../team_env.sh..."
    rm -f ../team_env.sh
fi

# Original daemon config file
if [ -f "../daemon_config.json" ]; then
    echo "Removing ../daemon_config.json..."
    rm -f ../daemon_config.json
fi

# Original config.json
if [ -f "config.json" ]; then
    echo "Removing config.json..."
    rm -f config.json
fi

# Key bundle files
if [ -f "key_bundle.cbor" ]; then
    echo "Removing key_bundle.cbor..."
    rm -f key_bundle.cbor
fi

# Build artifacts (optional)
if [ "$1" = "--clean-build" ]; then
    echo ""
    echo "Removing build artifacts..."
    if [ -d "../../target" ]; then
        echo "Removing ../../target/ directory..."
        rm -rf ../../target
    fi
    if [ -f "../../Cargo.lock" ]; then
        echo "Removing ../../Cargo.lock..."
        rm -f ../../Cargo.lock
    fi
fi

# Check for any remaining Aranya processes
echo ""
echo "Checking for remaining Aranya processes..."
if pgrep -f "aranya" > /dev/null; then
    echo "WARNING: Some Aranya processes are still running:"
    pgrep -f "aranya" | xargs ps -p
    echo ""
    echo "You may need to manually stop these processes."
else
    echo "No Aranya processes are running."
fi

# Check for remaining files
echo ""
echo "Checking for remaining Aranya files..."
if [ -d "/tmp/aranya" ] || [ -f "/tmp/aranya" ]; then
    echo "WARNING: /tmp/aranya still exists"
fi

for i in {1..5}; do
    if [ -d "/tmp/aranya$i" ] || [ -f "/tmp/aranya$i" ]; then
        echo "WARNING: /tmp/aranya$i still exists"
    fi
done

if ls /tmp/aranya_keys_* 2>/dev/null; then
    echo "WARNING: Some keystore directories still exist"
fi

echo ""
echo "=== Cleanup Complete ==="
echo ""
echo "The following have been cleaned up:"
echo "✓ All Aranya daemon and CLI processes"
echo "✓ Original temporary directory (/tmp/aranya)"
echo "✓ Multi-daemon directories (/tmp/aranya1 through /tmp/aranya5)"
echo "✓ Daemon PID files"
echo "✓ Daemon config files (config_daemon1.json through config_daemon5.json)"
echo "✓ Keystore directories (/tmp/aranya_keys_*)"
echo "✓ Generated files (CSV, env files, configs)"
echo "✓ Key bundle files"
if [ "$1" = "--clean-build" ]; then
    echo "✓ Build artifacts (target/, Cargo.lock)"
fi
echo ""
echo "To start fresh with multi-daemon setup:"
echo "1. Run: ./start-daemons.sh"
echo "2. Run: ./build-teams.sh" 