# Aranya CLI Testing Infrastructure

This directory contains the core testing infrastructure for the Aranya CLI tool, including the main testing application and supporting documentation.

## Overview

The testing infrastructure provides a comprehensive framework for validating Aranya CLI functionality through automated multi-daemon scenarios, environment setup, and integration testing.

## `main.rs` - Multi-Daemon Testing Application

### Purpose

The `main.rs` file implements a sophisticated multi-daemon testing application that serves as the foundation for CLI testing. It creates a realistic Aranya deployment scenario with multiple devices, teams, and communication channels to validate CLI functionality in a production-like environment.

### Key Functionality

#### **Multi-Daemon Orchestration**
- **Daemon Management**: Spawns and manages multiple Aranya daemon instances with isolated working directories
- **Process Lifecycle**: Handles daemon startup, configuration, and graceful shutdown
- **Resource Isolation**: Each daemon operates in its own `/tmp/aranya-{user}-{timestamp}` directory
- **Configuration Generation**: Dynamically creates daemon configuration files with proper directory structure

#### **Team and Device Setup**
- **Device Hierarchy**: Creates a complete team structure with Owner, Admin, Operator, and Member roles
- **Role Assignment**: Demonstrates proper role-based access control (RBAC) enforcement
- **Device Onboarding**: Shows the complete device addition and team joining process
- **Sync Configuration**: Establishes peer-to-peer synchronization between all devices

#### **AQC (Aranya QUIC Channels) Testing**
- **Channel Creation**: Demonstrates bidirectional AQC channel establishment
- **Stream Management**: Tests data stream creation and management within channels
- **Secure Communication**: Validates encrypted data transmission between devices
- **Label System**: Tests label creation, assignment, and revocation for access control

#### **Environment Export**
- **Variable Generation**: Exports all necessary environment variables for CLI testing
- **File Output**: Writes environment variables to `/tmp/aranya-env-vars.sh` for easy sourcing
- **Path Management**: Provides UDS socket paths, device IDs, team IDs, and network addresses
- **Integration Support**: Enables seamless integration with CLI testing scripts

### Architecture

#### **Core Components**

```rust
struct Daemon {
    _proc: Child,           // Daemon process handle
    _work_dir: PathBuf,     // Isolated working directory
}

struct ClientCtx {
    client: Client,         // Aranya client instance
    aqc_addr: SocketAddr,   // AQC server address
    pk: KeyBundle,          // Cryptographic key bundle
    id: DeviceId,           // Device identifier
    _work_dir: PathBuf,     // Working directory
    _daemon: Daemon,        // Associated daemon
}
```

#### **Testing Flow**

1. **Initialization**
   - Parse command-line arguments for daemon executable path
   - Set up logging and tracing infrastructure
   - Configure retry mechanisms for client connections

2. **Daemon Spawning**
   - Create isolated working directories for each device
   - Generate daemon configuration files with proper directory structure
   - Spawn daemon processes with appropriate configuration

3. **Team Creation**
   - Generate cryptographic seed material for deterministic key generation
   - Create team with QUIC sync configuration
   - Add all devices to the team with proper role assignments

4. **Sync Configuration**
   - Establish peer-to-peer synchronization between all devices
   - Configure sync intervals and retry mechanisms
   - Validate state synchronization across the network

5. **AQC Testing**
   - Create labels for secure communication channels
   - Establish bidirectional AQC channels between devices
   - Test data transmission and stream management
   - Validate label assignment and revocation

6. **Environment Export**
   - Export all environment variables needed for CLI testing
   - Write variables to file for easy sourcing by test scripts
   - Provide comprehensive debugging information

### Environment Variables Generated

The application exports the following environment variables for CLI testing:

```bash
# Daemon UDS Socket Paths
export OWNER_UDS="/tmp/aranya-owner-{timestamp}/daemon/run/uds.sock"
export ADMIN_UDS="/tmp/aranya-admin-{timestamp}/daemon/run/uds.sock"
export OPERATOR_UDS="/tmp/aranya-operator-{timestamp}/daemon/run/uds.sock"
export MEMBERA_UDS="/tmp/aranya-member_a-{timestamp}/daemon/run/uds.sock"
export MEMBERB_UDS="/tmp/aranya-member_b-{timestamp}/daemon/run/uds.sock"

# Cryptographic Material
export SEED_IKM_HEX="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"

# Team and Device Identifiers
export TEAM_ID="team_abc123"
export OWNER_DEVICE_ID="device_owner_xyz"
export ADMIN_DEVICE_ID="device_admin_xyz"
export OPERATOR_DEVICE_ID="device_operator_xyz"
export MEMBERA_DEVICE_ID="device_membera_xyz"
export MEMBERB_DEVICE_ID="device_memberb_xyz"

# Network Addresses
export OWNER_SYNC_ADDR="127.0.0.1:7812"
export ADMIN_SYNC_ADDR="127.0.0.1:7813"
export OPERATOR_SYNC_ADDR="127.0.0.1:7814"
export MEMBERA_SYNC_ADDR="127.0.0.1:7815"
export MEMBERB_SYNC_ADDR="127.0.0.1:7816"

# AQC Network Identifiers
export MEMBERA_AQC_NET_ID="127.0.0.1:5050"
export MEMBERB_AQC_NET_ID="127.0.0.1:5051"

# Label Identifiers
export LABEL_ID="label_xyz789"
```

### Integration with CLI Testing

The `main.rs` application integrates seamlessly with the CLI testing infrastructure:

1. **Automated Testing**: The `run-and-test.sh` script executes this application to set up the testing environment
2. **Manual Testing**: Provides environment variables for interactive CLI testing
3. **Validation**: Demonstrates proper Aranya functionality that CLI commands should replicate
4. **Debugging**: Offers comprehensive logging and state inspection capabilities

### Usage

The correct workflow for CLI testing uses the following scripts in order:

#### **1. Generate Daemon Configs (`generate_configs.sh`)**

```bash
./generate_configs.sh
```
- Creates necessary runtime/config directories for each daemon
- Generates `config_daemon{i}.json` files for each daemon with appropriate sync addresses

#### **2. Setup and Run Daemons (`cli-testing-daemons.sh`)**

```bash
./cli-testing-daemons.sh
```
- Builds the CLI tool and daemon in release mode
- Spawns multiple daemon instances with isolated working directories and generated configs
- Runs the multi-daemon testing application (`main.rs`)
- Exports environment variables for CLI testing

#### **3. Run Example and Test (`run-and-test.sh`)**

```bash
./run-and-test.sh
```
- Runs the example application and sources environment variables
- Optionally runs CLI tests if invoked with `--test`
- Provides environment variables for manual CLI testing

#### **Cleanup (`cleanup.sh`)**

```bash
./cleanup.sh
# Or for full cleanup including build artifacts:
./cleanup.sh --clean-build
```
- Stops all Aranya daemon and CLI processes
- Removes temporary directories and keystores
- Optionally removes build artifacts for a complete reset

#### **Complete Testing Workflow**

```bash
# 1. Generate configs for all daemons
./generate_configs.sh

# 2. Setup and run daemons
./cli-testing-daemons.sh

# 3. Run the example and test
./run-and-test.sh



aranya --uds-path "$OWNER_UDS" query-devices-on-team "$TEAM_ID"

# 5. Cleanup when done
./cleanup.sh
```

#### **Environment Variables for Manual Testing**

After running the setup scripts, the following environment variables are available:

```bash
# Daemon UDS Socket Paths
export OWNER_UDS="/tmp/aranya-owner-{timestamp}/daemon/run/uds.sock"
export ADMIN_UDS="/tmp/aranya-admin-{timestamp}/daemon/run/uds.sock"
export OPERATOR_UDS="/tmp/aranya-operator-{timestamp}/daemon/run/uds.sock"
export MEMBERA_UDS="/tmp/aranya-member_a-{timestamp}/daemon/run/uds.sock"
export MEMBERB_UDS="/tmp/aranya-member_b-{timestamp}/daemon/run/uds.sock"

# Team and Device Information
export TEAM_ID="team_abc123"
export OWNER_DEVICE_ID="device_owner_xyz"
export ADMIN_DEVICE_ID="device_admin_xyz"
export OPERATOR_DEVICE_ID="device_operator_xyz"
export MEMBERA_DEVICE_ID="device_membera_xyz"
export MEMBERB_DEVICE_ID="device_memberb_xyz"

# Network Addresses and Labels
export SEED_IKM_HEX="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
export LABEL_ID="label_xyz789"
```

### Key Benefits

- **Realistic Testing**: Provides a production-like environment for CLI validation
- **Comprehensive Coverage**: Tests all major Aranya functionality including teams, devices, sync, and AQC
- **Easy Integration**: Exports all necessary variables for seamless CLI testing
- **Debugging Support**: Offers detailed logging and state inspection
- **Isolation**: Each test run operates in isolated directories to prevent interference

This testing infrastructure ensures that the Aranya CLI tool works correctly with real Aranya deployments and provides a solid foundation for both automated and manual testing scenarios.
