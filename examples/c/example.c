/*
 * Copyright (c) SpiderOak, Inc. All rights reserved.
 */
/**
 * @file example.c
 * @brief Example C application using the Aranya client library.
 */

// Note: this file is formatted with `clang-format`.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aranya-client.h"

// Macro for printing AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define EXPECT(C, M)                                                           \
    do {                                                                       \
        AranyaError error = (C);                                               \
        if (error != ARANYA_ERROR_SUCCESS) {                                   \
            fprintf(stderr, "%s: %s\r\n", (M), aranya_error_to_str(error));    \
            return error;                                                      \
        }                                                                      \
    } while (0)

// Macro for printing client AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define CLIENT_EXPECT(C, M, N)                                                 \
    do {                                                                       \
        AranyaError error = (C);                                               \
        if (error != ARANYA_ERROR_SUCCESS) {                                   \
            fprintf(stderr, "%s %s: %s\r\n", (M), (N),                         \
                    aranya_error_to_str(error));                               \
            return error;                                                      \
        }                                                                      \
    } while (0)

// Default size of allocated data buffers.
#define BUFFER_LEN 256

// Number of clients on an Aranya team.
#define NUM_CLIENTS 5

// Enum containing all team members, for better indexing into arrays.
typedef enum {
    OWNER,
    ADMIN,
    OPERATOR,
    MEMBERA,
    MEMBERB,
} Members;

// List of Unix Domain Socket paths for the Aranya clients.
const char *daemon_socks[] = {"out/owner/uds.sock", "out/admin/uds.sock",
                              "out/operator/uds.sock", "out/membera/uds.sock",
                              "out/memberb/uds.sock"};

// List of names for the Aranya clients.
const char *client_names[] = {"owner", "admin", "operator", "membera",
                              "memberb"};

// List of sync addresses.
const AranyaAddr sync_addrs[] = {"127.0.0.1:10001", "127.0.0.1:10002",
                                 "127.0.0.1:10003", "127.0.0.1:10004",
                                 "127.0.0.1:10005"};

// List of AQC addresses.
const char *aqc_addrs[] = {"127.0.0.1:11001", "127.0.0.1:11002",
                           "127.0.0.1:11003", "127.0.0.1:11004",
                           "127.0.0.1:11005"};

// Container for handling Aranya Client state.
typedef struct {
    // Name of the client.
    const char *name;
    // Pointer to the internal Aranya Client.
    AranyaClient client;
    // Pointer to the serialized public key bundle.
    uint8_t *pk;
    // Length of the serialized public key bundle.
    size_t pk_len;
    // The Device ID corresponding to the current Client.
    AranyaDeviceId id;
} Client;

// Container for keeping track of all members on a Team.
//
// Contains the Team ID and all Aranya Clients for the devices on this team.
typedef struct {
    AranyaTeamId id;
    union {
        struct {
            // Team Owner.
            Client owner;
            // Team Admin.
            Client admin;
            // Team Operator.
            Client operator;
            // Team Member A.
            Client membera;
            // Team Member B.
            Client memberb;
        } clients;
        Client clients_arr[NUM_CLIENTS];
    };
} Team;

// Forward Declarations
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *aqc_addr);
AranyaError init_team(Team *t);
AranyaError add_sync_peers(Team *t, AranyaSyncPeerConfig *cfg);
AranyaError run(Team *t);
AranyaError run_aqc_example(Team *t);
AranyaError cleanup_team(Team *t);

// Initialize an Aranya `Client` with the given name and addresses.
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *aqc_addr) {
    AranyaError err;
    c->name = name;

    struct AranyaClientConfigBuilder cli_build;
    struct AranyaClientConfig cli_cfg;
    EXPECT(aranya_client_config_builder_init(&cli_build),
           "error initializing `ClientConfigBuilder`");
    EXPECT(
        aranya_client_config_builder_set_daemon_addr(&cli_build, daemon_addr),
        "unable to set daemon address on `ClientConfigBuilder`");

    struct AranyaAqcConfigBuilder aqc_build;
    struct AranyaAqcConfig aqc_cfg;
    EXPECT(aranya_aqc_config_builder_init(&aqc_build),
           "error initializing `AqcConfigBuilder`");
    EXPECT(aranya_aqc_config_builder_set_address(&aqc_build, aqc_addr),
           "unable to set AQC address on `AqcConfigBuilder`");
    EXPECT(aranya_aqc_config_build(&aqc_build, &aqc_cfg),
           "error building `AqcConfig`");
    EXPECT(aranya_aqc_config_builder_cleanup(&aqc_build),
           "error cleaning up the `AqcConfigBuilder");

    EXPECT(aranya_client_config_builder_set_aqc_config(&cli_build, &aqc_cfg),
           "unable to set `AqcConfig` parameter on `ClientConfigBuilder`");
    EXPECT(aranya_client_config_build(&cli_build, &cli_cfg),
           "error building `ClientConfig`");
    EXPECT(aranya_client_config_builder_cleanup(&cli_build),
           "error cleaning up the `ClientConfigBuilder`");

    err = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr,
                "error initializing client %s (daemon_addr: %s): %s\r\n",
                c->name, daemon_addr, aranya_error_to_str(err));
        return err;
    }
    CLIENT_EXPECT(aranya_get_device_id(&c->client, &c->id),
                  "error getting `DeviceId`", c->name);

    c->pk_len = 8; // intentionally set to small size to show reallocation
    c->pk     = malloc(c->pk_len);
    err       = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("reallocating key bundle buffer\r\n");
        c->pk = realloc(c->pk, c->pk_len);
        err   = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    }
    CLIENT_EXPECT(err, "error getting key bundle", c->name);

    return ARANYA_ERROR_SUCCESS;
}

// Initializes an Aranya `Team`, initializing each client and creating the team.
AranyaError init_team(Team *t) {
    AranyaError err;

    // initialize team clients.
    for (int i = 0; i < NUM_CLIENTS; i++) {
        printf("initializing client: %s\r\n", client_names[i]);
        EXPECT(init_client(&t->clients_arr[i], client_names[i], daemon_socks[i],
                           aqc_addrs[i]),
               "error initializing `Client`");
    }

    // Have the owner call `aranya_create_team`, which creates a new graph for
    // the team to use.
    AranyaTeamConfigBuilder team_build;
    AranyaTeamConfig team_cfg;
    EXPECT(aranya_team_config_build(&team_build, &team_cfg),
           "error building `TeamConfig`");
    EXPECT(aranya_create_team(&t->clients.owner.client, &team_cfg, &t->id),
           "error creating aranya team");

    // Test ID serialization and deserialization
    size_t team_id_str_len = ARANYA_ID_STR_LEN;
    char *team_id_str      = malloc(team_id_str_len);
    EXPECT(aranya_id_to_str(&t->id.id, team_id_str, &team_id_str_len),
           "error converting ID to string");
    printf("Team ID: %s \r\n", team_id_str);

    AranyaId decodedId;
    EXPECT(aranya_id_from_str(team_id_str, &decodedId),
           "error decoding string into an ID");

    free(team_id_str);

    if (!(memcmp(decodedId.bytes, t->id.id.bytes, ARANYA_ID_LEN) == 0)) {
        fprintf(stderr, "application failed: Decoded ID doesn't match\r\n");
        return EXIT_FAILURE;
    }

    return ARANYA_ERROR_SUCCESS;
}

// Cleans up an Aranya `Team`, freeing any memory and closing connections where
// necessary.
AranyaError cleanup_team(Team *t) {
    AranyaError err;
    AranyaError retErr = ARANYA_ERROR_SUCCESS;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        free(t->clients_arr[i].pk);
        err = aranya_client_cleanup(&t->clients_arr[i].client);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "error cleaning up %s: %s\r\n",
                    t->clients_arr[i].name, aranya_error_to_str(err));
            retErr = err;
        }
    }
    return retErr;
}

// Add sync peers.
// This creates a complete graph where each Aranya client can sync with all
// the other Aranya client peers on the network.
AranyaError add_sync_peers(Team *t, AranyaSyncPeerConfig *cfg) {
    AranyaError err;

    // TODO(nikki): refactor to use half the operations and connect sync peers
    // both ways
    for (int i = 0; i < NUM_CLIENTS; i++) {
        for (int j = 0; j < NUM_CLIENTS; j++) {
            if (i == j) {
                continue; // don't add self as a sync peer.
            }
            printf("adding sync peer %s to %s\r\n", t->clients_arr[j].name,
                   t->clients_arr[i].name);
            err = aranya_add_sync_peer(&t->clients_arr[i].client, &t->id,
                                       sync_addrs[j], cfg);
            if (err != ARANYA_ERROR_SUCCESS) {
                fprintf(stderr, "error adding sync peer %s to %s: %s\r\n",
                        t->clients_arr[j].name, t->clients_arr[i].name,
                        aranya_error_to_str(err));
                return err;
            }
        }
    }

    return ARANYA_ERROR_SUCCESS;
}

// Runs the C example program.
AranyaError run(Team *t) {
    AranyaError err;

    // initialize logging.
    printf("initializing logging\r\n");
    EXPECT(aranya_init_logging(), "error initializing logging");

    // initialize the Aranya team.
    printf("initializing team\r\n");
    EXPECT(init_team(t), "error initializing team");

    Client *owner = &t->clients.owner;
    Client *admin = &t->clients.admin;
    Client *operator= & t->clients.operator;
    Client *membera = &t->clients.membera;
    Client *memberb = &t->clients.memberb;

    // add admin to team.
    EXPECT(aranya_add_device_to_team(&owner->client, &t->id, admin->pk,
                                     admin->pk_len),
           "error adding admin to team");

    // add operator to team.
    EXPECT(aranya_add_device_to_team(&owner->client,
                                     &t->id, operator->pk, operator->pk_len),
           "error adding operator to team");

    // upgrade role to admin.
    EXPECT(aranya_assign_role(&owner->client, &t->id, &admin->id,
                              ARANYA_ROLE_ADMIN),
           "error assigning admin role");

    // upgrade role to operator. this includes testing that sync_now works.
    err = aranya_assign_role(&admin->client, &t->id, &operator->id,
                             ARANYA_ROLE_OPERATOR);
    if (err == ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: expected role assignment to fail");
        return EXIT_FAILURE;
    }

    EXPECT(aranya_sync_now(&admin->client, &t->id, sync_addrs[OWNER], NULL),
           "error calling `sync_now` to sync with peer");

    sleep(1);

    EXPECT(aranya_assign_role(&admin->client, &t->id, &operator->id,
                              ARANYA_ROLE_OPERATOR),
           "error assigning operator role");

    // Initialize the builder
    struct AranyaSyncPeerConfigBuilder builder;
    EXPECT(aranya_sync_peer_config_builder_init(&builder),
           "error initializing `SyncPeerConfigBuilder`");

    // Set duration on the config builder
    AranyaDuration interval = ARANYA_DURATION_MILLISECONDS * 100;
    EXPECT(aranya_sync_peer_config_builder_set_interval(&builder, interval),
           "unable to set duration on `SyncPeerConfigBuilder`");

    // Set syncing to happen immediately on the config builder
    EXPECT(aranya_sync_peer_config_builder_set_sync_now(&builder),
           "unable to set sync_now parameter on `SyncPeerConfigBuilder`");

    // Build the sync config
    struct AranyaSyncPeerConfig cfg;
    EXPECT(aranya_sync_peer_config_build(&builder, &cfg),
           "error building `SyncPeerConfig`");

    EXPECT(aranya_sync_peer_config_builder_cleanup(&builder),
           "error cleaning up the `SyncPeerConfigBuilder`");

    // add sync peers.
    printf("adding sync peers\r\n");
    EXPECT(add_sync_peers(t, &cfg), "error adding sync peers");

    // Team members are added to the team by first calling
    // `aranya_add_device_to_team`, passing in the submitter's client, the
    // team ID and the public key of the device to be added. In a real world
    // scenario, the keys would be exchanged outside of Aranya using
    // something like `scp`.

    // add membera to team.
    EXPECT(aranya_add_device_to_team(&owner->client, &t->id, membera->pk,
                                     membera->pk_len),
           "error adding membera to team");

    // add memberb to team.
    EXPECT(aranya_add_device_to_team(&owner->client, &t->id, memberb->pk,
                                     memberb->pk_len),
           "error adding memberb to team");

    sleep(1);

    // assign AQC network addresses.
    EXPECT(aranya_aqc_assign_net_identifier(&operator->client, &t->id,
                                            &membera->id, aqc_addrs[MEMBERA]),
           "error assigning AQC `NetIdentifier` to membera");

    EXPECT(aranya_aqc_assign_net_identifier(&operator->client, &t->id,
                                            &memberb->id, aqc_addrs[MEMBERB]),
           "error assigning AQC `NetIdentifier` to memberb");

    sleep(1);

    // Queries
    printf("running factdb queries\r\n");

    size_t devices_len      = BUFFER_LEN;
    AranyaDeviceId *devices = malloc(devices_len * sizeof(AranyaDeviceId));
    EXPECT(aranya_query_devices_on_team(&operator->client, &t->id, devices,
                                        &devices_len),
           "unable to query devices on team");

    if (devices == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < devices_len; i++) {
        AranyaDeviceId device_result = devices[i];

        size_t device_str_len = ARANYA_ID_STR_LEN;
        char *device_str      = malloc(ARANYA_ID_STR_LEN);
        EXPECT(aranya_id_to_str(&device_result.id, device_str, &device_str_len),
               "error converting ID to string");
        printf("device_id: %s at index: %zu/%zu \r\n", device_str, i,
               devices_len);

        AranyaId decodedId;
        EXPECT(aranya_id_from_str(device_str, &decodedId),
               "error decoding string into an ID");

        free(device_str);

        if (!(memcmp(decodedId.bytes, device_result.id.bytes, ARANYA_ID_LEN) ==
              0)) {
            fprintf(stderr, "application failed: Decoded ID doesn't match\r\n");
            return EXIT_FAILURE;
        }
    }
    free(devices);

    size_t memberb_keybundle_len = 255;
    uint8_t *memberb_keybundle   = malloc(memberb_keybundle_len);
    EXPECT(aranya_query_device_keybundle(&operator->client, &t->id,
                                         &memberb->id, memberb_keybundle,
                                         &memberb_keybundle_len),
           "unable to query for memberb's key bundle");
    printf(
        "%s key bundle len: %zu"
        "\r\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle_len);

    size_t memberb_aqc_net_identifier_len = BUFFER_LEN;
    char *memberb_aqc_net_identifier      = malloc(BUFFER_LEN);
    bool aqc_net_identifier_exists        = false;
    EXPECT(
        aranya_query_aqc_net_identifier(
            &operator->client, &t->id, &memberb->id, memberb_aqc_net_identifier,
            &memberb_aqc_net_identifier_len, &aqc_net_identifier_exists),
        "unable to query for memberb's AQC `NetIdentifier`");
    if (!aqc_net_identifier_exists) {
        fprintf(stderr, "expected AQC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s aqc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);

    EXPECT(aranya_aqc_remove_net_identifier(&operator->client, &t->id,
                                            &memberb->id, aqc_addrs[MEMBERB]),
           "error removing memberb's AQC `NetIdentifier`");
    printf("%s removed aqc net identifier: %s \r\n",
           t->clients_arr[MEMBERB].name, memberb_aqc_net_identifier);

    memberb_aqc_net_identifier_len = BUFFER_LEN;
    EXPECT(aranya_query_aqc_net_identifier(
               &operator->client, &t->id, &memberb->id,
               memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
               &aqc_net_identifier_exists) == ARANYA_ERROR_SUCCESS
               ? ARANYA_ERROR_BUG
               : ARANYA_ERROR_SUCCESS,
           "able to query for memberb's AQC `NetIdentifier` despite being "
           "removed");
    printf("%s aqc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);
    free(memberb_aqc_net_identifier);

    EXPECT(run_aqc_example(t), "error running aqc example");

    return ARANYA_ERROR_SUCCESS;
}

// Run the AQC example.
AranyaError run_aqc_example(Team *t) {
    AranyaError err;

    printf("running AQC demo\r\n");

    Client *owner = &t->clients.owner;
    Client *admin = &t->clients.admin;
    Client *operator= & t->clients.operator;
    Client *membera = &t->clients.membera;
    Client *memberb = &t->clients.memberb;

    // Create label and assign it to members
    printf("creating multiple labels\r\n");
    const char *label1_name = "label1";
    AranyaLabelId label1_id;
    EXPECT(
        aranya_create_label(&operator->client, &t->id, label1_name, &label1_id),
        "error creating label1");

    const char *label2_name = "label2";
    AranyaLabelId label2_id;
    EXPECT(
        aranya_create_label(&operator->client, &t->id, label2_name, &label2_id),
        "error creating label2");

    printf("assigning a label to members\r\n");
    AranyaChanOp op = ARANYA_CHAN_OP_SEND_RECV;
    EXPECT(aranya_assign_label(&operator->client, &t->id, &membera->id,
                               &label1_id, op),
           "error assigning label to membera");
    EXPECT(aranya_assign_label(&operator->client, &t->id, &memberb->id,
                               &label1_id, op),
           "error assigning label to memberb");
    sleep(1);

    // Queries
    printf("querying if label exists on team\r\n");
    bool exists = false;
    EXPECT(aranya_query_label_exists(&membera->client, &t->id, &label1_id,
                                     &exists),
           "unable to query if label exists");
    printf("%s label exists: %s \r\n", t->clients_arr[MEMBERA].name,
           exists ? "true" : "false");
    EXPECT(aranya_query_label_exists(&memberb->client, &t->id, &label1_id,
                                     &exists),
           "unable to query if label exists");
    printf("%s label exists: %s \r\n", t->clients_arr[MEMBERB].name,
           exists ? "true" : "false");

    size_t device_str_len = ARANYA_ID_STR_LEN;
    char *device_str      = malloc(ARANYA_ID_STR_LEN);
    EXPECT(aranya_id_to_str(&memberb->id.id, device_str, &device_str_len),
           "error converting ID to string");

    printf("querying labels assigned to device: %s\r\n", device_str);
    // Intentionally set `labels_len`to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    size_t labels_len     = 1;
    AranyaLabelId *labels = malloc(labels_len * sizeof(AranyaLabelId));
    err                   = aranya_query_device_label_assignments(
        &operator->client, &t->id, &memberb->id, labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\r\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err =
            aranya_query_labels(&operator->client, &t->id, labels, &labels_len);
    }
    EXPECT(err, "error querying labels assigned to device");

    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabelId label_result = labels[i];
        size_t label_str_len       = ARANYA_ID_STR_LEN;
        char *label_str            = malloc(ARANYA_ID_STR_LEN);
        EXPECT(aranya_id_to_str(&label_result.id, label_str, &label_str_len),
               "error converting ID to string");
        printf("label_id: %s at index: %zu/%zu \r\n", label_str, i, labels_len);
        free(label_str);
    }
    free(device_str);

    size_t team_str_len = ARANYA_ID_STR_LEN;
    char *team_str      = malloc(ARANYA_ID_STR_LEN);
    EXPECT(aranya_id_to_str(&t->id.id, team_str, &team_str_len),
           "error converting ID to string");
    printf("querying labels on team: %s\r\n", team_str);

    // Intentionally set `labels_len` to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    labels_len = 1;
    err = aranya_query_labels(&operator->client, &t->id, labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\r\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err =
            aranya_query_labels(&operator->client, &t->id, labels, &labels_len);
    }
    EXPECT(err, "error querying labels on team");
    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabelId label_result = labels[i];
        size_t label_str_len       = ARANYA_ID_STR_LEN;
        char *label_str            = malloc(ARANYA_ID_STR_LEN);
        EXPECT(aranya_id_to_str(&label_result.id, label_str, &label_str_len),
               "error converting ID to string");
        printf("label_id: %s at index: %zu/%zu \r\n", label_str, i, labels_len);
        free(label_str);
    }
    free(labels);
    free(team_str);

    // Create channel using Member A's client
    printf("creating a bidirectional AQC channel\r\n");
    AranyaAqcBidiChannelId chan_id;
    EXPECT(
        aranya_aqc_create_bidi_channel(
            &membera->client, &t->id, aqc_addrs[MEMBERB], &label1_id, &chan_id),
        "error creating bidirectional AQC channel");

    // TODO: send AQC data

    // Revoke label using the Operator
    printf("revoking labels\r\n");
    EXPECT(aranya_revoke_label(&operator->client, &t->id, &membera->id,
                               &label1_id),
           "error revoking label from membera");
    EXPECT(aranya_revoke_label(&operator->client, &t->id, &memberb->id,
                               &label1_id),
           "error revoking label from memberb");

    return err;
}

int main(void) {
    Team team;
    AranyaError err;
    int retErr = EXIT_SUCCESS;

    // TODO: take work_dirs, shm_paths, daemon_socks, IP addresses as input?

    // run the example.
    err = run(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: %s\r\n", aranya_error_to_str(err));
        retErr = EXIT_FAILURE;
    }

    // cleanup team.
    printf("cleaning up the Aranya team \r\n");
    err = cleanup_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        retErr = EXIT_FAILURE;
    }

    return retErr;
}
