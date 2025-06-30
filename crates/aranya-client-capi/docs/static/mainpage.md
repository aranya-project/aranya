# Aranya C API

The Aranya C API allows a C application to interface directly with the
Aranya client using a library and header file.

Before attempting to use this API, verify that you are using a matching version of the C library, Aranya client header file, Rust example application, getting started documentation, and API documentation.

1. Navigate to the [Aranya releases](https://github.com/aranya-project/aranya/releases) page.
2. Identify the [Aranya release](https://github.com/aranya-project/aranya/releases) matching this version of the C API documentation.
3. Checkout the [aranya](https://github.com/aranya-project/aranya/tree/main) repository at the commit matching that release or download the source code from the release and extract it onto your machine.
4. Refer to the top-level [README.md](https://github.com/aranya-project/aranya/blob/main/README.md) for instructions on running the [C example](https://github.com/aranya-project/aranya/blob/main/examples/c/README.md).

# Function Cheat Sheet

- `aranya_create_team()` - Create an Aranya team
- `aranya_add_team()` - Add an Aranya team to a device
- `aranya_add_device_to_team()` - Add a device to the Aranya team
- `aranya_add_sync_peer()` - Add peer to sync with
- `aranya_aqc_assign_net_identifier()` - Assign an AQC network identifier to a device
- `aranya_create_label()` - Create a new AQC label
- `aranya_assign_label()` - Assign an AQC label to a device
- `aranya_aqc_create_bidi_channel()` - Create a bidirectional AQC channel
- `aranya_aqc_receive_channel()` - Receive an AQC channel
- `aranya_aqc_bidi_create_bidi_stream()` - Create a bidirectional AQC stream
- `aranya_aqc_bidi_stream_send()` - Send data via bidirectional stream
- `aranya_aqc_bidi_stream_try_recv()` - Try to receive data via a bidirectional stream

# Object Cheat Sheet

Objects for creating an Aranya client and Aranya team:
- `AranyaClient`
- `AranyaClientConfig`
- `AranyaTeamConfig`
- `AranyaTeamConfigBuilder`
- `AranyaQuicSyncConfig`
- `AranyaQuicSyncConfigBuilder`
- `AranyaSyncPeerConfig`
- `AranyaSyncPeerConfigBuilder`

Objects for creating AQC (Aranya QUIC) channels and sending/receiving data:
- `AranyaAqcConfig`
- `AranyaAqcPeerChannel`
- `AranyaAqcBidiChannel`
- `AranyaAqcBidiStream`
