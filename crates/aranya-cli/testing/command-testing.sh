#!/bin/bash

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
PASSED_TEST_NAMES=()
FAILED_TEST_NAMES=()
PASSED_TEST_COMMANDS=()
FAILED_TEST_COMMANDS=()

# Helper function to track test results
track_test_result() {
    local test_name="$1"
    local command="$2"
    local success="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$success" = "true" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        PASSED_TEST_NAMES+=("$test_name")
        PASSED_TEST_COMMANDS+=("$command")
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
        FAILED_TEST_COMMANDS+=("$command")
    fi
}

echo "🔧 Testing CLI Commands Against All Daemons"
echo "==========================================="

# Try to source environment variables from the file created by main.rs
if [ -f "/tmp/aranya-env-vars.sh" ]; then
    echo "📁 Found environment variables file, sourcing..."
    source "/tmp/aranya-env-vars.sh"
    echo "✅ Environment variables loaded from /tmp/aranya-env-vars.sh"
else
    echo "⚠️  No environment variables file found at /tmp/aranya-env-vars.sh"
    echo "   Run the Rust example first to generate it"
fi

# Check if environment variables are set
if [ -z "$OWNER_UDS" ] || [ -z "$ADMIN_UDS" ] || [ -z "$OPERATOR_UDS" ] || [ -z "$MEMBERA_UDS" ] || [ -z "$MEMBERB_UDS" ]; then
    echo "❌ Error: UDS environment variables not set!"
    echo "Run: ./cli-testing-daemons.sh --test first"
    exit 1
fi

# Array of daemon names and their UDS paths
DAEMON_NAMES=("Owner" "Admin" "Operator" "MemberA" "MemberB")
DAEMON_PATHS=("$OWNER_UDS" "$ADMIN_UDS" "$OPERATOR_UDS" "$MEMBERA_UDS" "$MEMBERB_UDS")

# Test function for each daemon
test_daemon() {
    local name=$1
    local uds_path=$2
    
    echo ""
    echo "🧪 Testing $name daemon at: $uds_path"
    echo "----------------------------------------"
    
    # Test 1: Get device ID
    local cmd="aranya --uds-path \"$uds_path\" get-device-id"
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds_path" get-device-id
    if [ $? -eq 0 ]; then
        echo "✅ $name: Device ID retrieved successfully"
        track_test_result "Get Device ID for $name" "$cmd" "true"
    else
        echo "❌ $name: Failed to get device ID"
        track_test_result "Get Device ID for $name" "$cmd" "false"
    fi
    
    # Test 2: Get key bundle
    local cmd="aranya --uds-path \"$uds_path\" get-key-bundle"
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds_path" get-key-bundle
    if [ $? -eq 0 ]; then
        echo "✅ $name: Key bundle retrieved successfully"
        track_test_result "Get Key Bundle for $name" "$cmd" "true"
    else
        echo "❌ $name: Failed to get key bundle"
        track_test_result "Get Key Bundle for $name" "$cmd" "false"
    fi
    
    # Test 3: Query devices on team (using actual team ID)
    local cmd="aranya --uds-path \"$uds_path\" query-devices-on-team \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds_path" query-devices-on-team "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ $name: Devices on team queried successfully"
        track_test_result "Query Devices on Team for $name" "$cmd" "true"
    else
        echo "❌ $name: Failed to query devices on team"
        track_test_result "Query Devices on Team for $name" "$cmd" "false"
    fi
    
    # Test 4: Get device info
    local cmd="aranya --uds-path \"$uds_path\" device-info \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds_path" device-info "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ $name: Device info retrieved successfully"
        track_test_result "Get Device Info for $name" "$cmd" "true"
    else
        echo "❌ $name: Failed to get device info"
        track_test_result "Get Device Info for $name" "$cmd" "false"
    fi
    
    echo "✅ $name daemon tests completed"
}

# Test function for advanced CLI commands
test_advanced_commands() {
    echo ""
    echo "🧪 Testing Advanced CLI Commands"
    echo "================================="
    
    # Test 1: Assign role to device
    local cmd="aranya --uds-path \"$OPERATOR_UDS\" assign-role \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\" \"Member\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$OPERATOR_UDS" assign-role "$TEAM_ID" "$MEMBERA_DEVICE_ID" "Member"
    if [ $? -eq 0 ]; then
        echo "✅ assign-role succeeded"
        track_test_result "Assign Role for Operator" "$cmd" "true"
    else
        echo "❌ assign-role failed"
        track_test_result "Assign Role for Operator" "$cmd" "false"
    fi
    
    # Test 2: Query device role
    local cmd="aranya --uds-path \"$MEMBERA_UDS\" query-device-role \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$MEMBERA_UDS" query-device-role "$TEAM_ID" "$MEMBERA_DEVICE_ID"
    if [ $? -eq 0 ]; then
        echo "✅ query-device-role succeeded"
        track_test_result "Query Device Role for MemberA" "$cmd" "true"
    else
        echo "❌ query-device-role failed"
        track_test_result "Query Device Role for MemberA" "$cmd" "false"
    fi
    
    # Test 3: Query device keybundle
    local cmd="aranya --uds-path \"$MEMBERA_UDS\" query-device-keybundle \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$MEMBERA_UDS" query-device-keybundle "$TEAM_ID" "$MEMBERA_DEVICE_ID"
    if [ $? -eq 0 ]; then
        echo "✅ query-device-keybundle succeeded"
        track_test_result "Query Device Keybundle for MemberA" "$cmd" "true"
    else
        echo "❌ query-device-keybundle failed"
        track_test_result "Query Device Keybundle for MemberA" "$cmd" "false"
    fi
    
    # Test 4: Assign AQC network ID
    local cmd="aranya --uds-path \"$OPERATOR_UDS\" assign-aqc-net-id \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\" \"$MEMBERA_AQC_NET_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$OPERATOR_UDS" assign-aqc-net-id "$TEAM_ID" "$MEMBERA_DEVICE_ID" "$MEMBERA_AQC_NET_ID"
    if [ $? -eq 0 ]; then
        echo "✅ assign-aqc-net-id succeeded"
        track_test_result "Assign AQC Network ID for Operator" "$cmd" "true"
    else
        echo "❌ assign-aqc-net-id failed"
        track_test_result "Assign AQC Network ID for Operator" "$cmd" "false"
    fi
    
    # Test 5: Query AQC network identifier
    local cmd="aranya --uds-path \"$MEMBERA_UDS\" query-aqc-net-identifier \"$TEAM_ID\" \"$MEMBERA_DEVICE_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$MEMBERA_UDS" query-aqc-net-identifier "$TEAM_ID" "$MEMBERA_DEVICE_ID"
    if [ $? -eq 0 ]; then
        echo "✅ query-aqc-net-identifier succeeded"
        track_test_result "Query AQC Network Identifier for MemberA" "$cmd" "true"
    else
        echo "❌ query-aqc-net-identifier failed"
        track_test_result "Query AQC Network Identifier for MemberA" "$cmd" "false"
    fi
    
    # Test 6: List AQC assignments
    local cmd="aranya --uds-path \"$OPERATOR_UDS\" list-aqc-assignments \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$OPERATOR_UDS" list-aqc-assignments "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ list-aqc-assignments succeeded"
        track_test_result "List AQC Assignments for Operator" "$cmd" "true"
    else
        echo "❌ list-aqc-assignments failed"
        track_test_result "List AQC Assignments for Operator" "$cmd" "false"
    fi
    
    # Test 7: Add sync peer
    local cmd="aranya --uds-path \"$OWNER_UDS\" add-sync-peer \"$TEAM_ID\" \"$ADMIN_SYNC_ADDR\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$OWNER_UDS" add-sync-peer "$TEAM_ID" "$ADMIN_SYNC_ADDR"
    if [ $? -eq 0 ]; then
        echo "✅ add-sync-peer succeeded"
        track_test_result "Add Sync Peer for Owner" "$cmd" "true"
    else
        echo "❌ add-sync-peer failed"
        track_test_result "Add Sync Peer for Owner" "$cmd" "false"
    fi
    
    # Test 8: Sync now
    local cmd="aranya --uds-path \"$ADMIN_UDS\" sync-now \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$ADMIN_UDS" sync-now "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ sync-now succeeded"
        track_test_result "Sync Now for Admin" "$cmd" "true"
    else
        echo "❌ sync-now failed"
        track_test_result "Sync Now for Admin" "$cmd" "false"
    fi
    
    # Test 9: Create label
    local cmd="aranya --uds-path \"$OPERATOR_UDS\" create-label \"$TEAM_ID\" \"test_label\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$OPERATOR_UDS" create-label "$TEAM_ID" "test_label"
    if [ $? -eq 0 ]; then
        echo "✅ create-label succeeded"
        track_test_result "Create Label for Operator" "$cmd" "true"
    else
        echo "❌ create-label failed"
        track_test_result "Create Label for Operator" "$cmd" "false"
    fi
    
    # Test 10: List label assignments
    local cmd="aranya --uds-path \"$OPERATOR_UDS\" list-label-assignments \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$OPERATOR_UDS" list-label-assignments "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ list-label-assignments succeeded"
        track_test_result "List Label Assignments for Operator" "$cmd" "true"
    else
        echo "❌ list-label-assignments failed"
        track_test_result "List Label Assignments for Operator" "$cmd" "false"
    fi
    
    # Test 11: Show channels
    local cmd="aranya --uds-path \"$MEMBERA_UDS\" show-channels"
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$MEMBERA_UDS" show-channels
    if [ $? -eq 0 ]; then
        echo "✅ show-channels succeeded"
        track_test_result "Show Channels for MemberA" "$cmd" "true"
    else
        echo "❌ show-channels failed"
        track_test_result "Show Channels for MemberA" "$cmd" "false"
    fi
    
    # Test 12: List active channels
    local cmd="aranya --uds-path \"$MEMBERA_UDS\" list-active-channels"
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$MEMBERA_UDS" list-active-channels
    if [ $? -eq 0 ]; then
        echo "✅ list-active-channels succeeded"
        track_test_result "List Active Channels for MemberA" "$cmd" "true"
    else
        echo "❌ list-active-channels failed"
        track_test_result "List Active Channels for MemberA" "$cmd" "false"
    fi
}

# Test team commands with Owner daemon
test_team_commands() {
    echo ""
    echo "🔍 Testing team commands with Owner daemon"
    echo "========================================="

    local uds="$OWNER_UDS"
    echo "Using OWNER_UDS: $uds"

    # Test 1: Query devices on team (using known team ID)
    local cmd="aranya --uds-path \"$uds\" query-devices-on-team \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds" query-devices-on-team "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ query-devices-on-team succeeded"
        track_test_result "Query Devices on Team with Owner" "$cmd" "true"
    else
        echo "❌ query-devices-on-team failed"
        track_test_result "Query Devices on Team with Owner" "$cmd" "false"
    fi

    # Test 2: List devices on team
    local cmd="aranya --uds-path \"$uds\" list-devices \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds" list-devices "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ list-devices succeeded"
        track_test_result "List Devices with Owner" "$cmd" "true"
    else
        echo "❌ list-devices failed"
        track_test_result "List Devices with Owner" "$cmd" "false"
    fi

    # Test 3: Get device ID
    local cmd="aranya --uds-path \"$uds\" get-device-id"
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds" get-device-id
    if [ $? -eq 0 ]; then
        echo "✅ get-device-id succeeded"
        track_test_result "Get Device ID with Owner" "$cmd" "true"
    else
        echo "❌ get-device-id failed"
        track_test_result "Get Device ID with Owner" "$cmd" "false"
    fi

    # Test 4: Device info without device ID (current device)
    local cmd="aranya --uds-path \"$uds\" device-info \"$TEAM_ID\""
    echo -e "\n========== CLI TEST: $cmd =========="
    aranya --uds-path "$uds" device-info "$TEAM_ID"
    if [ $? -eq 0 ]; then
        echo "✅ device-info <team-id> succeeded"
        track_test_result "Get Device Info with Owner" "$cmd" "true"
    else
        echo "❌ device-info <team-id> failed"
        track_test_result "Get Device Info with Owner" "$cmd" "false"
    fi

    echo "✅ Team commands tests completed"
}

# Run tests for all daemons
echo "🚀 Starting CLI command tests for all daemons..."
for i in "${!DAEMON_NAMES[@]}"; do
    name="${DAEMON_NAMES[$i]}"
    uds_path="${DAEMON_PATHS[$i]}"
    test_daemon "$name" "$uds_path"
done

# Run team commands test with Owner daemon
test_team_commands

# Test advanced commands
test_advanced_commands

echo ""
echo "🎉 All CLI command tests completed!"
echo "📊 Summary:"
echo "  - Tested 5 daemons (Owner, Admin, Operator, MemberA, MemberB)"
echo "  - Each daemon tested: device-id, key-bundle, query-devices-on-team, device-info"
echo "  - Team commands tested with Owner daemon: query-devices-on-team, list-devices, device-info"
echo ""
echo "💡 Next steps:"
echo "  - Use the UDS paths for manual CLI testing"
echo "  - Test more complex scenarios with the CLI commands"

# At the end, print the env vars for manual CLI testing
echo -e "\n\n================= ENV VARS FOR MANUAL CLI TESTING ================="
echo "🔌 UDS Daemon Paths:"
echo "  OWNER_UDS:    $OWNER_UDS"
echo "  ADMIN_UDS:    $ADMIN_UDS"
echo "  OPERATOR_UDS: $OPERATOR_UDS"
echo "  MEMBERA_UDS:  $MEMBERA_UDS"
echo "  MEMBERB_UDS:  $MEMBERB_UDS"
echo ""
echo "🆔 Device IDs:"
echo "  OWNER_DEVICE_ID:    $OWNER_DEVICE_ID"
echo "  ADMIN_DEVICE_ID:    $ADMIN_DEVICE_ID"
echo "  OPERATOR_DEVICE_ID: $OPERATOR_DEVICE_ID"
echo "  MEMBERA_DEVICE_ID:  $MEMBERA_DEVICE_ID"
echo "  MEMBERB_DEVICE_ID:  $MEMBERB_DEVICE_ID"
echo ""
echo "🌐 Sync Addresses:"
echo "  OWNER_SYNC_ADDR:    $OWNER_SYNC_ADDR"
echo "  ADMIN_SYNC_ADDR:    $ADMIN_SYNC_ADDR"
echo "  OPERATOR_SYNC_ADDR: $OPERATOR_SYNC_ADDR"
echo "  MEMBERA_SYNC_ADDR:  $MEMBERA_SYNC_ADDR"
echo "  MEMBERB_SYNC_ADDR:  $MEMBERB_SYNC_ADDR"
echo ""
echo "🔗 AQC Network IDs:"
echo "  MEMBERA_AQC_NET_ID: $MEMBERA_AQC_NET_ID"
echo "  MEMBERB_AQC_NET_ID: $MEMBERB_AQC_NET_ID"
echo ""
echo "🏷️  Labels:"
echo "  LABEL_ID:           $LABEL_ID"
echo ""
echo "📊 Team Info:"
echo "  TEAM_ID:            $TEAM_ID"
echo "  SEED_IKM_HEX:       $SEED_IKM_HEX"
echo ""
echo "💡 Example Advanced Commands:"
echo "  aranya --uds-path \$OPERATOR_UDS assign-role \$TEAM_ID \$MEMBERA_DEVICE_ID 'Member'"
echo "  aranya --uds-path \$MEMBERA_UDS query-device-role \$TEAM_ID \$MEMBERA_DEVICE_ID"
echo "  aranya --uds-path \$OPERATOR_UDS assign-aqc-net-id \$TEAM_ID \$MEMBERA_DEVICE_ID \$MEMBERA_AQC_NET_ID"
echo "  aranya --uds-path \$OWNER_UDS add-sync-peer \$TEAM_ID \$ADMIN_SYNC_ADDR"
echo "  aranya --uds-path \$OPERATOR_UDS create-label \$TEAM_ID 'my_label'"
echo "  aranya --uds-path \$MEMBERA_UDS show-channels"
echo "  aranya --uds-path \$MEMBERA_UDS query-device-keybundle \$TEAM_ID \$MEMBERA_DEVICE_ID"
echo "  aranya --uds-path \$MEMBERA_UDS query-aqc-net-identifier \$TEAM_ID \$MEMBERA_DEVICE_ID"
echo "  aranya --uds-path \$OPERATOR_UDS list-aqc-assignments \$TEAM_ID"
echo "  aranya --uds-path \$ADMIN_UDS sync-now \$TEAM_ID"
echo "  aranya --uds-path \$OPERATOR_UDS list-label-assignments \$TEAM_ID"
echo "  aranya --uds-path \$MEMBERA_UDS list-active-channels"
echo "==============================================================="

# Print test summary
echo ""
echo "📊 TEST SUMMARY"
echo "==============="
echo "Total Tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
echo "Success Rate: $((PASSED_TESTS * 100 / TOTAL_TESTS))%"
echo ""

if [ ${#PASSED_TEST_NAMES[@]} -gt 0 ]; then
    echo "✅ PASSED TESTS:"
    echo "================"
    for i in "${!PASSED_TEST_NAMES[@]}"; do
        echo "  ✓ ${PASSED_TEST_NAMES[$i]}"
        echo "     Command: ${PASSED_TEST_COMMANDS[$i]}"
        echo ""
    done
fi

if [ ${#FAILED_TEST_NAMES[@]} -gt 0 ]; then
    echo "❌ FAILED TESTS:"
    echo "================"
    for i in "${!FAILED_TEST_NAMES[@]}"; do
        echo "  ✗ ${FAILED_TEST_NAMES[$i]}"
        echo "     Command: ${FAILED_TEST_COMMANDS[$i]}"
        echo ""
    done
fi

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED!"
else
    echo "⚠️  $FAILED_TESTS test(s) failed. Check the output above for details."
fi
