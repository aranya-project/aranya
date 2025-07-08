# Aranya Chunk Sender Example

A demonstration of secure file transfer using Aranya's peer-to-peer communication framework. This example showcases chunked file transmission with metadata handling, optimal chunk sizing, and secure team-based access control.

## Overview

This example implements a complete file transfer system that:

- **Creates a secure team** with role-based access control (Owner, Admin, Operator, Sender, Receiver)
- **Establishes encrypted channels** using Aranya's AQC (Authenticated Quantum Communication) protocol
- **Transfers files in chunks** with metadata for reliable reassembly
- **Optimizes chunk sizes** based on file size and system resources
- **Handles concurrent streams** for efficient data transfer
- **Provides progress tracking** and error handling throughout the transfer

## Features

- 🔐 **Secure Communication**: Uses Aranya's authenticated quantum communication
- 📦 **Chunked Transfer**: Breaks large files into optimal-sized chunks
- 🏷️ **Metadata Handling**: Includes filename, chunk indices, and file size information
- ⚡ **Concurrent Streams**: Multiple parallel streams for faster transfer
- 🛡️ **Role-Based Access**: Team creation with Owner/Admin/Operator/Sender/Receiver roles
- 📊 **Progress Tracking**: Real-time transfer progress and status updates
- 🔄 **Reliable Reassembly**: Ensures complete file reconstruction on receiver side

## Prerequisites

- Rust toolchain (1.85+)
- Aranya daemon executable
- A file to transfer

## Usage

### Building

```bash
cargo build --release
```

### Running

```bash
./target/release/sender <daemon_path> <file_path>
```

**Parameters:**
- `daemon_path`: Path to the Aranya daemon executable
- `file_path`: Path to the file you want to transfer

### Example

```bash
# Build the example
cargo build --release

# Run with a test file
./target/release/sender ../../../../target/release/aranya-daemon data/test.yaml
```

## How It Works

### 1. Team Setup
The example creates a team with 5 devices:
- **Owner**: Creates the team and manages initial setup
- **Admin**: Has administrative privileges
- **Operator**: Manages file transfer operations
- **Sender**: Initiates file transfer
- **Receiver**: Receives and reassembles the file

### 2. Channel Establishment
- Creates an AQC bidirectional channel between sender and receiver
- Assigns a "file_transfer" label for secure communication
- Establishes multiple parallel streams for data transfer

### 3. File Transfer Process
1. **Chunking**: File is split into optimal-sized chunks (8KB minimum, up to ~68MB)
2. **Metadata**: Each chunk includes filename, index, size, and total chunk count
3. **Serialization**: Chunks are serialized using CBOR format
4. **Streaming**: Multiple concurrent streams send chunks with metadata
5. **Reassembly**: Receiver reconstructs file from chunks in correct order

### 4. Output
The received file is saved as `received_<filename>` in the current directory.

## Configuration

### Chunk Size Optimization

The example automatically calculates optimal chunk sizes:
- **Minimum**: 16KB (ensures reasonable transfer efficiency)
- **Maximum**: ~68MB (prevents memory issues)
- **Adaptive**: Scales based on file size and system resources
- **Minimum Chunks**: Ensures at least 4 chunks for parallel processing

### Memory Management

- Uses buffered I/O for efficient file reading
- Streams data directly without loading entire file into memory
- Implements timeout handling for network operations
- Provides graceful error recovery

## Error Handling

The example includes comprehensive error handling:
- Network timeouts and retries
- File I/O error recovery
- Stream connection failures
- Metadata validation
- Chunk reassembly verification

## Logging

Enable detailed logging by setting the environment variable:
```bash
export ARANYA_EXAMPLE=debug
./target/release/sender <daemon_path> <file_path>
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│     Sender      │    │    Receiver     │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ File Reader │ │    │ │File Writer  │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Chunker    │ │    │ │Reassembler  │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Streams    │◄─────►│  Streams    │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
```

## Security Features

- **Authenticated Channels**: All communication is cryptographically verified
- **Role-Based Access**: Fine-grained permissions control
- **Label-Based Security**: Communication restricted to specific labels
- **Quantum-Resistant**: Uses post-quantum cryptography
- **Zero-Trust**: No implicit trust between devices

## Performance Considerations

- **Parallel Streams**: Multiple concurrent streams for bandwidth utilization
- **Adaptive Chunking**: Optimizes for file size and system resources
- **Buffered I/O**: Efficient file reading and writing
- **Memory Efficient**: Streaming approach prevents large memory usage
- **Network Resilient**: Timeout handling and retry logic

## Troubleshooting

### Common Issues

1. **Daemon not found**: Ensure the daemon path is correct and executable
2. **File not found**: Verify the file path exists and is readable
3. **Permission errors**: Check file and directory permissions
4. **Network timeouts**: Increase timeout values for slow networks
5. **Memory issues**: Reduce chunk size for very large files

### Debug Mode

For detailed debugging, run with debug logging:
```bash
ARANYA_EXAMPLE=debug ./target/release/sender <daemon_path> <file_path>
```

## Related Examples

- [Basic Sender](../sender/): Simple file transfer example
- [C Examples](../../c/): C language bindings and examples
- [Rust Examples](../): Other Rust integration examples
