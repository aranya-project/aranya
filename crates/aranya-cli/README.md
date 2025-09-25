

# Aranya CLI Testing and Usage Guide

This `aranya-cli` crate contains a CLI tool for interacting with Aranya. The CLI provides a complete interface for managing Aranya teams, devices, labels, and secure communication channels. The CLI tool connects to the Aranya deamon via the encrypted USD IPC API. Comprehensive testing and example scripts are located in the `testing` subdirectory.
AQC operations are not currently supported with this tool. An issue has been opened here to provided better support for the CLI tool in Aranya:
https://github.com/aranya-project/aranya/issues/409

## Overview

The Aranya CLI (`aranya`) is a powerful command-line tool that interfaces with Aranya daemons to manage:
- **Team Management**: Create teams, add/remove devices, assign roles
- **Device Management**: Query device information, manage key bundles
- **Label System**: Create and assign labels for secure communication channels
- **Sync Configuration**: Manage peer synchronization for team state updates
- **AQC (in-testing)**: Manage peer synchronization for team state updates


## CLI Commands Reference

### Basic Device Commands

#### `get-device-id`
Retrieves the current device's unique identifier.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock get-device-id
```

#### `get-key-bundle`
Displays the device's cryptographic key bundle (identity, signing, and encoding keys).

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock get-key-bundle
```

#### `create-client`
Creates a client/device identity and outputs device information in JSON or text format.

```bash
# Text format (default)
aranya --uds-path /tmp/aranya1/run/uds.sock create-client

# JSON format
aranya --uds-path /tmp/aranya1/run/uds.sock create-client --format json
```

### Team Management Commands

#### `create-team`
Creates a new team with optional seed IKM (Input Keying Material) for deterministic key generation.

```bash
# Create team with random seed IKM
aranya --uds-path /tmp/aranya1/run/uds.sock create-team

# Create team with specific seed IKM (32-byte hex)
aranya --uds-path /tmp/aranya1/run/uds.sock create-team --seed-ikm a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

#### `create-team-with-config`
Creates a team with custom configuration including sync intervals.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock create-team-with-config \
  --seed-ikm a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456 \
  --sync-interval-secs 5
```

#### `add-team`
Adds an existing team to the current device using team ID and seed IKM.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock add-team \
  "team_abc123" \
  "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
```

#### `remove-team`
Removes a team from the current device.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock remove-team "team_abc123"
```

### Device Management Commands

#### `add-device`
Adds a device to a team using its public keys.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock add-device \
  "team_abc123" \
  "identity_key_hex_here" \
  "signing_key_hex_here" \
  "encoding_key_hex_here"
```

#### `remove-device`
Removes a device from a team.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock remove-device \
  "team_abc123" \
  "device_xyz789"
```

#### `assign-role`
Assigns a role to a device on a team. Available roles: Owner, Admin, Operator, Member.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock assign-role \
  "team_abc123" \
  "device_xyz789" \
  "Admin"
```

#### `list-devices`
Lists all devices on a team with their roles.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock list-devices "team_abc123"
```

#### `device-info`
Displays comprehensive information about a device including role, keys, labels, and AQC network ID.

```bash
# Show current device info
aranya --uds-path /tmp/aranya1/run/uds.sock device-info "team_abc123"

# Show specific device info
aranya --uds-path /tmp/aranya1/run/uds.sock device-info "team_abc123" "device_xyz789"
```

### Query Commands

#### `query-devices-on-team`
Lists all devices on a team with count.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock query-devices-on-team "team_abc123"
```

#### `query-device-role`
Queries the role of a specific device on a team.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock query-device-role \
  "team_abc123" \
  "device_xyz789"
```

#### `query-device-keybundle`
Retrieves the key bundle of a specific device.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock query-device-keybundle \
  "team_abc123" \
  "device_xyz789"
```

#### `query-aqc-net-identifier`
Queries the AQC network identifier assigned to a device.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock query-aqc-net-identifier \
  "team_abc123" \
  "device_xyz789"
```

### Sync Configuration Commands

#### `add-sync-peer`
Adds a sync peer for automatic team state synchronization.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock add-sync-peer \
  "team_abc123" \
  "192.168.1.100:7812" \
  --interval-secs 5
```

#### `sync-now`
Performs immediate synchronization with a peer.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock sync-now \
  "team_abc123" \
  "192.168.1.100:7812"
```

#### `set-sync-config`
Updates sync configuration for a team.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock set-sync-config \
  "team_abc123" \
  10
```

### Label Management Commands

#### `create-label`
Creates a new label for secure communication channels.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock create-label \
  "team_abc123" \
  "secure_channel_label"
```

#### `assign-label`
Assigns a label to a device with specific channel operations (SendOnly, RecvOnly, SendRecv).

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock assign-label \
  "team_abc123" \
  "device_xyz789" \
  "label_id_hex_here" \
  "SendRecv"
```

#### `list-label-assignments`
Lists all label assignments for a specific device.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock list-label-assignments \
  "team_abc123" \
  "device_xyz789"
```

#### `revoke-label`
Revokes a label assignment from a device.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock revoke-label \
  "team_abc123" \
  "device_xyz789" \
  "label_id_hex_here"
```

#### `delete-label`
Deletes a label entirely from a team (Admin only).

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock delete-label \
  "team_abc123" \
  "label_id_hex_here"
```

#### `get-label-id-base58`
Converts a hex label ID to base58 format.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock get-label-id-base58 \
  "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
```

### AQC Network Commands

#### `assign-aqc-net-id`
Assigns an AQC network identifier to a device for secure communication.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock assign-aqc-net-id \
  "team_abc123" \
  "device_xyz789" \
  "192.168.1.100:5050"
```

#### `list-aqc-assignments`
Lists all AQC network assignments for devices on a team.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock list-aqc-assignments "team_abc123"
```

### Advanced AQC Communication Commands

#### `send-data`
Sends data to a device using a label with PSK rotation (creates fresh channel for each send).

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock send-data \
  "team_abc123" \
  "device_xyz789" \
  "label_id_hex_here" \
  "Hello, secure message!"
```

#### `listen-data`
Listens for data from a device using a label with PSK rotation.

```bash
# Listen with 30-second timeout (default)
aranya --uds-path /tmp/aranya1/run/uds.sock listen-data \
  "team_abc123" \
  "device_xyz789" \
  "label_id_hex_here"

# Listen with custom timeout
aranya --uds-path /tmp/aranya1/run/uds.sock listen-data \
  "team_abc123" \
  "device_xyz789" \
  "label_id_hex_here" \
  --timeout 60
```

#### `create-bidi-channel`
Creates a bidirectional AQC channel for secure communication.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock create-bidi-channel \
  "team_abc123" \
  "192.168.1.100:5050" \
  "label_id_hex_here"
```

#### `receive-channel`
Receives an incoming AQC channel.

```bash
# Receive with 30-second timeout (default)
aranya --uds-path /tmp/aranya1/run/uds.sock receive-channel

# Receive with custom timeout
aranya --uds-path /tmp/aranya1/run/uds.sock receive-channel --timeout 60
```

#### `create-bidi-stream`
Creates a bidirectional stream on an existing channel.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock create-bidi-stream "channel_uuid_here"
```

#### `receive-stream`
Receives a stream from an existing channel.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock receive-stream \
  "channel_uuid_here" \
  --timeout 30
```

#### `send-stream-data`
Sends data on a bidirectional stream.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock send-stream-data \
  "stream_uuid_here" \
  "Hello from stream!"
```

#### `receive-stream-data`
Receives data from a stream.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock receive-stream-data \
  "stream_uuid_here" \
  --timeout 30
```

### Channel Management Commands

#### `show-channels`
Shows information about AQC channels (note: channels are ephemeral for PSK rotation).

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock show-channels "team_abc123"
```

#### `list-active-channels`
Lists all active channels and streams in the CLI session.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock list-active-channels
```

#### `close-channel`
Closes a specific channel.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock close-channel "channel_uuid_here"
```

#### `close-stream`
Closes a specific stream.

```bash
aranya --uds-path /tmp/aranya1/run/uds.sock close-stream "stream_uuid_here"
```

## Testing with run-and-test.sh

The `run-and-test.sh` script provides a comprehensive testing environment for the Aranya CLI. It sets up multiple daemons with different roles and provides environment variables for testing all CLI commands.

### How to Run Tests

1. **Build and run the test environment:**
   ```bash
   cd examples/rust/cli
   ./run-and-test.sh --test
   ```

2. **Manual testing mode:**
   ```bash
   ./run-and-test.sh
   # Then source the environment variables and test manually
   source /tmp/aranya-env-vars.sh
   ```

### What the Test Script Does

The `run-and-test.sh` script:

1. **Builds the daemon and example** from the Rust workspace
2. **Starts 5 daemons** with different roles (Owner, Admin, Operator, MemberA, MemberB)
3. **Creates a team** with all devices and assigns appropriate roles
4. **Sets up sync peers** for automatic state synchronization
5. **Creates labels** and assigns them to devices for AQC communication
6. **Exports environment variables** for easy CLI testing
7. **Runs automated CLI tests** (in test mode) or provides manual testing environment

### Environment Variables Provided

The script exports these environment variables for testing:

- **UDS Paths**: `OWNER_UDS`, `ADMIN_UDS`, `OPERATOR_UDS`, `MEMBERA_UDS`, `MEMBERB_UDS`
- **Team Info**: `TEAM_ID`, `SEED_IKM_HEX`
- **Device IDs**: `OWNER_DEVICE_ID`, `ADMIN_DEVICE_ID`, `OPERATOR_DEVICE_ID`, `MEMBERA_DEVICE_ID`, `MEMBERB_DEVICE_ID`
- **Sync Addresses**: `OWNER_SYNC_ADDR`, `ADMIN_SYNC_ADDR`, `OPERATOR_SYNC_ADDR`, `MEMBERA_SYNC_ADDR`, `MEMBERB_SYNC_ADDR`
- **AQC Network IDs**: `MEMBERA_AQC_NET_ID`, `MEMBERB_AQC_NET_ID`
- **Label ID**: `LABEL_ID`

### Relationship to main.rs

The `main.rs` file in `crates/aranya-cli/src/main.rs` implements all the CLI commands described above. It provides:

- **Command-line argument parsing** using `clap`
- **Daemon connection management** via Unix Domain Sockets
- **Team and device management** operations
- **AQC channel and stream management** with PSK rotation
- **Global channel registry** for managing active connections
- **Error handling and user-friendly output**

The testing scripts use the same CLI interface that `main.rs` provides, ensuring that all commands work correctly in real-world scenarios with multiple daemons and complex team configurations.

### Example Test Commands

After running the test script, you can test various CLI commands:

```bash
# Basic device operations
aranya --uds-path "$OWNER_UDS" get-device-id
aranya --uds-path "$OWNER_UDS" get-key-bundle

# Team management
aranya --uds-path "$OWNER_UDS" query-devices-on-team "$TEAM_ID"
aranya --uds-path "$ADMIN_UDS" device-info "$TEAM_ID"

# Role management
aranya --uds-path "$OPERATOR_UDS" assign-role "$TEAM_ID" "$MEMBERA_DEVICE_ID" "Member"
aranya --uds-path "$MEMBERA_UDS" query-device-role "$TEAM_ID" "$MEMBERA_DEVICE_ID"

# AQC communication
aranya --uds-path "$MEMBERA_UDS" send-data "$TEAM_ID" "$MEMBERB_DEVICE_ID" "$LABEL_ID" "Hello!"
aranya --uds-path "$MEMBERB_UDS" listen-data "$TEAM_ID" "$MEMBERA_DEVICE_ID" "$LABEL_ID"
```

## Issues and Solutions

### Port Conflict Issue with --aqc-addr Flag

**Problem**: When running multiple Aranya daemons and using the CLI with `--aqc-addr` flags, we encount
ered "Address already in use" errors.

**Root Cause**: The CLI tries to start its own AQC (Aranya Query Client) server when the `--aqc-addr` parameter is provided, but this conflicts with the daemon's existing AQC server running on the same port.

**Error Message**:
```
Error: Failed to connect to daemon after 5 attempts: AQC error: Server start error: Address already in use (os error 48)
```

**Solution**: Remove all `--aqc-addr` parameters from CLI commands when using Unix Domain Socket (UDS) connections. The UDS connection works perfectly without specifying an AQC address.

**Working Command**:
```bash
# ✅ Works - UDS only
aranya --uds-path /tmp/aranya1/run/uds.sock create-team

# ❌ Fails - UDS + AQC address causes port conflict
aranya --uds-path /tmp/aranya1/run/uds.sock --aqc-addr 127.0.0.1:5055 create-team
```

**Impact**: This allows multiple daemons to run simultaneously on different ports (5055-5059) while CLI commands connect via their respective UDS sockets without port conflicts.

**Files Affected**:
- `build-teams.sh` - Removed all `--aqc-addr` parameters
- `start-daemons.sh` - Updated to use separate aranya directories and correct UDS paths

