#!/bin/bash

# Create directories for all daemons
for i in {1..5}; do
    mkdir -p /tmp/aranya$i/{run,state,cache,logs,config}
done

echo "=== Creating teams on each daemon ==="

# Array to store team info for each daemon
declare -a TEAM_IDS
declare -a DEVICE_IDS
declare -a IDENTITY_KEYS
declare -a SIGNING_KEYS
declare -a ENCODING_KEYS

# Create team on each daemon
for i in {1..5}; do
    echo "Creating team on daemon $i..."
    
    # Create team
    TEAM_OUTPUT=$(aranya --uds-path /tmp/aranya$i/run/uds.sock -v create-team)
    TEAM_ID=$(echo "$TEAM_OUTPUT" | grep "Team ID:" | cut -d' ' -f3)
    
    echo "Daemon $i - Team ID: $TEAM_ID"
    TEAM_IDS[$i]=$TEAM_ID
    
    # Get device info
    DEVICE_OUTPUT=$(aranya --uds-path /tmp/aranya$i/run/uds.sock -v device-info $TEAM_ID)
    DEVICE_ID=$(echo "$DEVICE_OUTPUT" | grep "Device ID:" | cut -d' ' -f3)
    IDENTITY_KEY=$(echo "$DEVICE_OUTPUT" | grep "Identity:" | sed 's/.*Identity: *//')
    SIGNING_KEY=$(echo "$DEVICE_OUTPUT" | grep "Signing:" | sed 's/.*Signing: *//')
    ENCODING_KEY=$(echo "$DEVICE_OUTPUT" | grep "Encoding:" | sed 's/.*Encoding: *//')
    
    echo "Daemon $i - Device ID: $DEVICE_ID"
    DEVICE_IDS[$i]=$DEVICE_ID
    IDENTITY_KEYS[$i]=$IDENTITY_KEY
    SIGNING_KEYS[$i]=$SIGNING_KEY
    ENCODING_KEYS[$i]=$ENCODING_KEY
    
    echo ""
done

echo "=== Adding devices 2-5 to team 1 ==="

# Use team 1 as the main team
MAIN_TEAM_ID=${TEAM_IDS[1]}
echo "Main team ID (from daemon 1): $MAIN_TEAM_ID"

# Add device 2 and assign admin role
echo "Adding device 2 to team 1..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    add-device $MAIN_TEAM_ID ${IDENTITY_KEYS[2]} ${SIGNING_KEYS[2]} ${ENCODING_KEYS[2]}

echo "Assigning admin role to device 2..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    assign-role $MAIN_TEAM_ID ${DEVICE_IDS[2]} Admin

# Add device 3 and assign operator role
echo "Adding device 3 to team 1..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    add-device $MAIN_TEAM_ID ${IDENTITY_KEYS[3]} ${SIGNING_KEYS[3]} ${ENCODING_KEYS[3]}

echo "Assigning operator role to device 3..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    assign-role $MAIN_TEAM_ID ${DEVICE_IDS[3]} Operator

# Add device 4 and assign member role
echo "Adding device 4 to team 1..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    add-device $MAIN_TEAM_ID ${IDENTITY_KEYS[4]} ${SIGNING_KEYS[4]} ${ENCODING_KEYS[4]}

echo "Assigning member role to device 4..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    assign-role $MAIN_TEAM_ID ${DEVICE_IDS[4]} Member

# Add device 5 and assign member role
echo "Adding device 5 to team 1..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    add-device $MAIN_TEAM_ID ${IDENTITY_KEYS[5]} ${SIGNING_KEYS[5]} ${ENCODING_KEYS[5]}

echo "Assigning member role to device 5..."
aranya --uds-path /tmp/aranya1/run/uds.sock \
    assign-role $MAIN_TEAM_ID ${DEVICE_IDS[5]} Member

echo ""
echo "=== Listing all devices in team 1 ==="
aranya --uds-path /tmp/aranya1/run/uds.sock -v list-devices $MAIN_TEAM_ID

echo ""
echo "=== Setting up sync peers ==="

# Add sync peers for team 1 to sync with other daemons
for i in {2..5}; do
    echo "Adding sync peer from daemon 1 to daemon $i..."
    aranya --uds-path /tmp/aranya1/run/uds.sock \
        add-sync-peer --interval-secs 1 $MAIN_TEAM_ID 127.0.0.1:505$((4+i))
done

echo ""
echo "=== Summary ==="
echo "Main team ID: $MAIN_TEAM_ID"
echo "Device 1 (owner): ${DEVICE_IDS[1]} - role: owner"
echo "Device 2 (admin): ${DEVICE_IDS[2]} - role: admin"
echo "Device 3 (operator): ${DEVICE_IDS[3]} - role: operator"
echo "Device 4 (member): ${DEVICE_IDS[4]} - role: member"
echo "Device 5 (member): ${DEVICE_IDS[5]} - role: member"

echo ""
echo "=== Device Public Keys on Team 1 ==="
echo "Getting detailed device information with public keys..."

# Get the list of device IDs from team 1
DEVICE_LIST=$(aranya --uds-path /tmp/aranya1/run/uds.sock list-devices $MAIN_TEAM_ID)
echo "$DEVICE_LIST"

echo ""
echo "=== Individual Device Details ==="

# Get device info for each device in the team
echo "$DEVICE_LIST" | grep -E "^[A-Za-z0-9]{32,}" | while read device_id role; do
    echo "--- Device: $device_id (Role: $role) ---"
    aranya --uds-path /tmp/aranya1/run/uds.sock -v device-info $MAIN_TEAM_ID $device_id
    echo ""
done

echo ""
echo "=== Removing Device 4 from Team 1 ==="

# Get device 4's actual device ID from the team list
DEVICE_4_ID=$(aranya --uds-path /tmp/aranya1/run/uds.sock list-devices $MAIN_TEAM_ID | grep -E "^[A-Za-z0-9]{32,}" | sed -n '4p' | awk '{print $1}')
echo "Device 4 ID to remove: $DEVICE_4_ID"

# Remove device 4 from team 1
aranya --uds-path /tmp/aranya1/run/uds.sock remove-device $MAIN_TEAM_ID $DEVICE_4_ID

echo ""
echo "=== Updated Device List After Removal ==="

# Get the updated list of device IDs from team 1
UPDATED_DEVICE_LIST=$(aranya --uds-path /tmp/aranya1/run/uds.sock list-devices $MAIN_TEAM_ID)
echo "$UPDATED_DEVICE_LIST"

echo ""
echo "=== Updated Individual Device Details ==="

# Get device info for each remaining device in the team
echo "$UPDATED_DEVICE_LIST" | grep -E "^[A-Za-z0-9]{32,}" | while read device_id role; do
    echo "--- Device: $device_id (Role: $role) ---"
    aranya --uds-path /tmp/aranya1/run/uds.sock -v device-info $MAIN_TEAM_ID $device_id
    echo ""
done


