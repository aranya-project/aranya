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
            echo "  --test: Run daemons and automatically test CLI commands"
            echo "  (no args): Run daemons and source env vars for manual testing"
            exit 1
            ;;
    esac
done

echo "🚀 Aranya CLI Testing Script"
echo "============================"

# Build the daemon
echo "🔨 Building daemon..."
cargo build --release --manifest-path "$(dirname "$0")/../../../Cargo.toml" --bin aranya-daemon

# Build the example
echo "🔨 Building example..."
cargo build --release --manifest-path "$(dirname "$0")/../Cargo.toml"

# Get the absolute path to the daemon
daemon="$(cd "$(dirname "$0")/../../../target/release" && pwd)/aranya-daemon"

echo "🔄 Starting daemons and running example..."
echo "   Daemon path: $daemon"

# Run the example and capture output
if [ "$TEST_MODE" = true ]; then
    # Test mode: Do everything from manual mode PLUS run CLI tests
    echo "📋 Running example (test mode)..."
    "$(dirname "$0")/../target/release/aranya-example" "${daemon}"
    
    # Source the environment variables
    if [ -f "/tmp/aranya-env-vars.sh" ]; then
        echo "📁 Sourcing environment variables..."
        source "/tmp/aranya-env-vars.sh"
        echo "✅ Environment variables loaded!"
        
        # Wait for daemons to fully initialize
        echo "⏳ Waiting for daemons to initialize..."
        sleep 3

        # Run command testing script
        echo "🧪 Running CLI tests..."
        "$(dirname "$0")/command-testing.sh"
    else
        echo "❌ Environment file not found at /tmp/aranya-env-vars.sh"
        echo "   The example may have failed to run properly."
        exit 1
    fi
else
    # Manual mode: Run example and source env vars
    echo "📋 Running example (manual mode)..."
    "$(dirname "$0")/../target/release/aranya-example" "${daemon}"
    
    # Source the environment variables
    if [ -f "/tmp/aranya-env-vars.sh" ]; then
        echo "📁 Sourcing environment variables..."
        source "/tmp/aranya-env-vars.sh"
        echo "✅ Environment variables loaded!"
        echo ""
        echo "🎯 Ready for manual CLI testing!"
        echo "   Available commands:"
        echo "   - aranya --uds-path \$OWNER_UDS get-device-id"
        echo "   - aranya --uds-path \$OWNER_UDS query-devices-on-team \$TEAM_ID"
        echo "   - aranya --uds-path \$OWNER_UDS list-devices \$TEAM_ID"
        echo "   - aranya --uds-path \$ADMIN_UDS device-info \$TEAM_ID"
        echo ""
        echo "   Environment variables set:"
        echo "   - OWNER_UDS, ADMIN_UDS, OPERATOR_UDS, MEMBERA_UDS, MEMBERB_UDS"
        echo "   - TEAM_ID, SEED_IKM_HEX"
        echo ""
        echo "   Example: aranya --uds-path \$OWNER_UDS query-devices-on-team \$TEAM_ID"
    else
        echo "❌ Environment file not found at /tmp/aranya-env-vars.sh"
        echo "   The example may have failed to run properly."
    fi
fi

echo "✅ Script completed!"

# Print environment variables for easy copying
echo ""
echo "📋 After running this script, copy and paste the following lines into your terminal to set up your environment variables:"
echo "========================================================================"
echo "export OWNER_UDS=\"$OWNER_UDS\""
echo "export ADMIN_UDS=\"$ADMIN_UDS\""
echo "export OPERATOR_UDS=\"$OPERATOR_UDS\""
echo "export MEMBERA_UDS=\"$MEMBERA_UDS\""
echo "export MEMBERB_UDS=\"$MEMBERB_UDS\""
echo "export SEED_IKM_HEX=\"$SEED_IKM_HEX\""
echo "export TEAM_ID=\"$TEAM_ID\""
echo "export OWNER_DEVICE_ID=\"$OWNER_DEVICE_ID\""
echo "export ADMIN_DEVICE_ID=\"$ADMIN_DEVICE_ID\""
echo "export OPERATOR_DEVICE_ID=\"$OPERATOR_DEVICE_ID\""
echo "export MEMBERA_DEVICE_ID=\"$MEMBERA_DEVICE_ID\""
echo "export MEMBERB_DEVICE_ID=\"$MEMBERB_DEVICE_ID\""
echo "export OWNER_SYNC_ADDR=\"$OWNER_SYNC_ADDR\""
echo "export ADMIN_SYNC_ADDR=\"$ADMIN_SYNC_ADDR\""
echo "export OPERATOR_SYNC_ADDR=\"$OPERATOR_SYNC_ADDR\""
echo "export MEMBERA_SYNC_ADDR=\"$MEMBERA_SYNC_ADDR\""
echo "export MEMBERB_SYNC_ADDR=\"$MEMBERB_SYNC_ADDR\""
echo "export MEMBERA_AQC_NET_ID=\"$MEMBERA_AQC_NET_ID\""
echo "export MEMBERB_AQC_NET_ID=\"$MEMBERB_AQC_NET_ID\""
echo "export LABEL_ID=\"$LABEL_ID\""
echo "========================================================================"

# Print example commands for easy copying
echo ""
echo "🚀 Copy and paste these advanced commands to test the CLI:"
echo "========================================================="
echo ""
echo "# Basic device commands:"
echo ""
echo "🆔 get-device-id"
echo "aranya --uds-path \"$OWNER_UDS\" get-device-id"
echo ""
echo "🔑 get-key-bundle"
echo "aranya --uds-path \"$OWNER_UDS\" get-key-bundle"
echo ""
echo "👥 query-devices-on-team"
echo "aranya --uds-path \"$OWNER_UDS\" query-devices-on-team \"$TEAM_ID\""
echo ""
echo "📋 list-devices"
echo "aranya --uds-path \"$OWNER_UDS\" list-devices \"$TEAM_ID\""
echo ""
echo "ℹ️  device-info"
echo "aranya --uds-path \"$ADMIN_UDS\" device-info \"$TEAM_ID\""
echo ""
echo "### ------ Team management commands ------ ###"
echo ""
echo "🛡️  assign-role"
echo "aranya --uds-path \"$OPERATOR_UDS\" assign-role \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\" \"Member\""
echo ""
echo "🔍 query-device-role"
echo "aranya --uds-path \"$MEMBERA_UDS\" query-device-role \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\""
echo ""
echo "🔑 query-device-keybundle"
echo "aranya --uds-path \"$MEMBERA_UDS\" query-device-keybundle \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\""
echo ""
echo "# AQC network commands:"
echo ""
echo "🌐 assign-aqc-net-id"
echo "aranya --uds-path \"$OPERATOR_UDS\" assign-aqc-net-id \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\" \"$MEMBERA_AQC_NET_ID\""
echo ""
echo "🔍 query-aqc-net-identifier"
echo "aranya --uds-path \"$MEMBERA_UDS\" query-aqc-net-identifier \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\""
echo ""
echo "📋 list-aqc-assignments"
echo "aranya --uds-path \"$OPERATOR_UDS\" list-aqc-assignments \"$TEAM_ID\""
echo ""
echo "# Sync commands:"
echo ""
echo "🔗 add-sync-peer"
echo "aranya --uds-path \"$OWNER_UDS\" add-sync-peer \"$TEAM_ID\" \"$ADMIN_SYNC_ADDR\""
echo ""
echo "🔄 sync-now"
echo "aranya --uds-path \"$ADMIN_UDS\" sync-now \"$TEAM_ID\""
echo ""
echo "# Label and channel commands:"
echo ""
echo "🏷️  create-label"
echo "aranya --uds-path \"$OPERATOR_UDS\" create-label \"$TEAM_ID\" \"my_test_label\""
echo ""
echo "📋 list-label-assignments"
echo "aranya --uds-path \"$OPERATOR_UDS\" list-label-assignments \"$TEAM_ID\""
echo ""
echo "📺 show-channels"
echo "aranya --uds-path \"$MEMBERA_UDS\" show-channels"
echo ""
echo "📋 list-active-channels"
echo "aranya --uds-path \"$MEMBERA_UDS\" list-active-channels"
echo ""
echo "### ------ Advanced commands ------ ###"
echo ""
echo "📤 send-data"
echo "aranya --uds-path \"$MEMBERA_UDS\" send-data \"$LABEL_ID\" \"$TEAM_ID\" \"Hello from CLI!\""
echo ""
echo "📥 listen-data"
echo "aranya --uds-path \"$MEMBERB_UDS\" listen-data \"$LABEL_ID\" \"$TEAM_ID\""
echo ""
echo "🔗 create-bidi-channel"
echo "aranya --uds-path \"$MEMBERA_UDS\" create-bidi-channel \"$TEAM_ID\" \"$MEMBERB_DEVICE_ID\""
echo ""
echo "📥 receive-channel"
echo "aranya --uds-path \"$MEMBERB_UDS\" receive-channel \"$TEAM_ID\""
echo "=========================================================" 