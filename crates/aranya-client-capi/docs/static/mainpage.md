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
- `aranya_create_label()` - Create a new label
- `aranya_assign_label()` - Assign a label to a device
- `aranya_afc_create_channel()` - Create a send-only AFC channel
- `aranya_afc_accept_channel()` - Accept a receive-only AFC channel from a peer
- `aranya_afc_channel_seal()` - Seal data with AFC channel
- `aranya_afc_channel_open()` - Open data with AFC channel

# Object Cheat Sheet

Objects for creating an Aranya client and Aranya team:
- `AranyaClient`
- `AranyaClientConfig`
- `AranyaCreateTeamConfig`
- `AranyaCreateTeamConfigBuilder`
- `AranyaCreateTeamQuicSyncConfig`
- `AranyaCreateTeamQuicSyncConfigBuilder`
- `AranyaAddTeamConfig`
- `AranyaAddTeamConfigBuilder`
- `AranyaAddTeamQuicSyncConfig`
- `AranyaAddTeamQuicSyncConfigBuilder`
- `AranyaSyncPeerConfig`
- `AranyaSyncPeerConfigBuilder`

AFC related types:
- `AranyaAfcSendChannel`
- `AranyaAfcReceiveChannel`
- `AranyaAfcCtrlMsg`
- `AranyaAfcSeq`

# Extended‐error (_ext) Variants
Functions suffixed with `_ext` accept an extra `struct AranyaExtError *ext_err` parameter for extended error information.
- `ext_err` must be a valid, non-NULL pointer.
- If the call returns anything other than `ARANYA_ERROR_SUCCESS`,
  `*ext_err` is populated with additional error details.
- On success, the content of `ext_err` is unchanged.
- To extract a human-readable message:
      \code{.c}
      AranyaError aranya_ext_error_msg(
          const struct AranyaExtError *err,
          char *msg,
          size_t *msg_len
      );
      \endcode

 Example:
    \code{.c}
     struct AranyaExtError ext_err;
     AranyaError rc = aranya_get_device_id_ext(client, &id, &ext_err);
     if (rc != ARANYA_ERROR_SUCCESS) {
         size_t len = 0;
         aranya_ext_error_msg(&ext_err, NULL, &len);
         char *buf = malloc(len);
         aranya_ext_error_msg(&ext_err, buf, &len);
         // `buf` now holds the detailed error message
     }
     \endcode
