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
#define EXPECT(M, E)                                                           \
    do {                                                                       \
        AranyaError error = (E);                                               \
        if (err != ARANYA_ERROR_SUCCESS) {                                     \
            fprintf(stderr, "%s: %s\r\n", (M), aranya_error_to_str(error));    \
            return error;                                                      \
        }                                                                      \
    } while (0)

// Macro for printing client AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define CLIENT_EXPECT(M, N, E)                                                 \
    do {                                                                       \
        AranyaError error = (E);                                               \
        if (error != ARANYA_ERROR_SUCCESS) {                                   \
            fprintf(stderr, "%s %s: %s\r\n", (M), (N),                         \
                    aranya_error_to_str(error));                               \
            return error;                                                      \
        }                                                                      \
    } while (0)

// Size of data buffer.
#define BUF_LEN 256

// Maximum number of AFC channels supported by shared memory.
// This number must be configured the same for both the read and write
// sides.
#define MAX_CHANS 256

// Number of clients on Aranya team.
#define NUM_CLIENTS 5

// Team members enum. Can index into team member arrays.
typedef enum {
    OWNER,
    ADMIN,
    OPERATOR,
    MEMBERA,
    MEMBERB,
} Members;

// List of shared memory paths for the Aranya clients.
const char *afc_shm_paths[] = {"/afc_owner", "/afc_admin", "/afc_operator",
                               "/afc_membera", "/afc_memberb"};

// List of Unix domain socket paths for the Aranya clients.
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

// List of AFC addresses.
const char *afc_addrs[] = {"127.0.0.1:11001", "127.0.0.1:11002",
                           "127.0.0.1:11003", "127.0.0.1:11004",
                           "127.0.0.1:11005"};

#if defined(ENABLE_AFC)
// List of AFC addresses.
const char *afc_addrs[] = {"127.0.0.1:11001", "127.0.0.1:11002",
                           "127.0.0.1:11003", "127.0.0.1:11004",
                           "127.0.0.1:11005"};
#endif

// Aranya client.
typedef struct {
    // Name of Aranya client.
    const char *name;
    // Pointer to Aranya client.
    AranyaClient client;
    // Aranya client's serialized public key bundle.
    uint8_t *pk;
    // Aranya client's serialized public key bundle length.
    size_t pk_len;
    // Aranya client's public id.
    AranyaDeviceId id;
} Client;

// Aranya team.
//
// Contains the team ID and all Aranya clients for the devices on this example's
// team.
typedef struct {
    AranyaTeamId id;
    union {
        struct {
            // Team owner.
            Client owner;
            // Team admin.
            Client admin;
            // Team operator.
            Client operator;
            // Team member a.
            Client membera;
            // Team member b.
            Client memberb;
        } clients;
        Client clients_arr[NUM_CLIENTS];
    };
} Team;

#if defined(ENABLE_AFC)
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *shm_path, const char *afc_addr,
                        const char *aqc_addr);
#else
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *shm_path, const char *aqc_addr);
#endif
AranyaError init_team(Team *t);
AranyaError add_sync_peers(Team *t, AranyaSyncPeerConfig *cfg);
AranyaError run(Team *t);
AranyaError run_aqc_example(Team *t);
AranyaError cleanup_team(Team *t);

// Initialize an Aranya client.
#if defined(ENABLE_AFC)
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *shm_path, const char *afc_addr,
                        const char *aqc_addr) {
#else
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *shm_path, const char *aqc_addr) {
#endif
    AranyaError err;
    c->name = name;

    struct AranyaClientConfigBuilder cli_build;
    struct AranyaClientConfig cli_cfg;
    err = aranya_client_config_builder_init(&cli_build);
    EXPECT("error initializing client config builder", err);
    aranya_client_config_builder_set_daemon_addr(&cli_build, daemon_addr);
#if defined(ENABLE_AFC)
    struct AranyaAfcConfigBuilder afc_build;
    struct AranyaAfcConfig afc_cfg;
    aranya_afc_config_builder_set_shm_path(&afc_build, shm_path);
    aranya_afc_config_builder_set_max_channels(&afc_build, MAX_CHANS);
    aranya_afc_config_builder_set_address(&afc_build, afc_addr);
    err = aranya_afc_config_builder_build(&afc_build, &afc_cfg);

    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing afc config: %s\r\n",
                aranya_error_to_str(err));
        return err;
    }

    aranya_client_config_builder_set_afc_config(&cli_build, &afc_cfg);
#endif
    struct AranyaAqcConfigBuilder aqc_build;
    struct AranyaAqcConfig aqc_cfg;
    err = aranya_aqc_config_builder_init(&aqc_build);
    EXPECT("error initializing client config builder", err);
    aranya_aqc_config_builder_set_address(&aqc_build, aqc_addr);
    err = aranya_aqc_config_builder_build(&aqc_build, &aqc_cfg);

    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing afc config: %s\r\n",
                aranya_error_to_str(err));
        return err;
    }
    err = aranya_aqc_config_builder_cleanup(&aqc_build);
    EXPECT("error running the cleanup routine for the aqc config builder", err);

    aranya_client_config_builder_set_aqc_config(&cli_build, &aqc_cfg);

    err = aranya_client_config_builder_build(&cli_build, &cli_cfg);

    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing client config: %s\r\n",
                aranya_error_to_str(err));
        return err;
    }

    err = aranya_client_config_builder_cleanup(&cli_build);
    EXPECT("error running the cleanup routine for the client config builder",
           err);

    err = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
#if defined(ENABLE_AFC)
        fprintf(stderr,
                "error initializing client %s (daemon_addr: %s, shm_path: %s, "
                "afc_addr: %s): %s\r\n",
                c->name, daemon_addr, shm_path, afc_addr,
                aranya_error_to_str(err));
#else
        fprintf(stderr,
                "error initializing client %s (daemon_addr: %s, shm_path: %s): "
                "%s\r\n",
                c->name, daemon_addr, shm_path, aranya_error_to_str(err));
#endif
        return err;
    }
    err = aranya_get_device_id(&c->client, &c->id);
    CLIENT_EXPECT("error getting device id", c->name, err);

    c->pk_len = 8; // intentionally set to small size to show reallocation
    c->pk     = malloc(c->pk_len);
    err       = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("reallocating key bundle buffer\r\n");
        c->pk = realloc(c->pk, c->pk_len);
        err   = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    }
    CLIENT_EXPECT("error getting key bundle", c->name, err);

    return ARANYA_ERROR_SUCCESS;
}

// Initialize the Aranya `Team` by first initializing the team's clients and
// then creates the team.
AranyaError init_team(Team *t) {
    AranyaError err;

    // initialize team clients.
    for (int i = 0; i < NUM_CLIENTS; i++) {
#if defined(ENABLE_AFC)
        printf("initializing client: %s\r\n", client_names[i]);
        err = init_client(&t->clients_arr[i], client_names[i], daemon_socks[i],
                          afc_shm_paths[i], afc_addrs[i], afc_addrs[i]);
#else
        printf("initializing client: %s\r\n", client_names[i]);
        err = init_client(&t->clients_arr[i], client_names[i], daemon_socks[i],
                          afc_shm_paths[i], afc_addrs[i]);
#endif
        EXPECT("error initializing team", err);
    }

    // have owner create the team.
    // The `aranya_create_team` method is used to create a new graph for the
    // team to operate on.
    err = aranya_create_team(&t->clients.owner.client, &t->id);
    EXPECT("error creating team", err);

    // Test ID serialization and deserialization
    size_t team_id_str_len = ARANYA_ID_STR_LEN;
    char *team_id_str      = malloc(team_id_str_len);
    aranya_id_to_str(&t->id.id, team_id_str, &team_id_str_len);
    printf("Team ID: %s \r\n", team_id_str);

    AranyaId decodedId;
    err = aranya_id_from_str(team_id_str, &decodedId);
    EXPECT("error decoding string into an ID", err);

    free(team_id_str);

    if (!(memcmp(decodedId.bytes, t->id.id.bytes, ARANYA_ID_LEN) == 0)) {
        fprintf(stderr, "application failed: Decoded ID doesn't match\r\n");
        return EXIT_FAILURE;
    }

    return ARANYA_ERROR_SUCCESS;
}

// Cleanup Aranya `Team`.
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

// Run the example.
AranyaError run(Team *t) {
    AranyaError err;

    // initialize logging.
    printf("initializing logging\r\n");
    err = aranya_init_logging();
    EXPECT("error initializing logging", err);

    // initialize the Aranya team.
    printf("initializing team\r\n");
    err = init_team(t);
    EXPECT("error initializing team", err);

    // add admin to team.
    err =
        aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                  t->clients.admin.pk, t->clients.admin.pk_len);
    EXPECT("error adding admin to team", err);

    // add operator to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    t->clients.operator.pk,
                                    t->clients.operator.pk_len);
    EXPECT("error adding operator to team", err);

    // upgrade role to admin.
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.admin.id, ARANYA_ROLE_ADMIN);
    EXPECT("error assigning admin role", err);

    // upgrade role to operator.
    err = aranya_assign_role(&t->clients.admin.client, &t->id,
                             &t->clients.operator.id, ARANYA_ROLE_OPERATOR);

    if (err == ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: expected role assignment to fail");
        return EXIT_FAILURE;
    }

    err = aranya_sync_now(&t->clients.admin.client, &t->id, sync_addrs[OWNER],
                          NULL);
    EXPECT("error calling `sync_now` to sync with peer", err);

    sleep(1);
    err = aranya_assign_role(&t->clients.admin.client, &t->id,
                             &t->clients.operator.id, ARANYA_ROLE_OPERATOR);
    EXPECT("error assigning operator role", err);

    // Initialize the builder
    struct AranyaSyncPeerConfigBuilder builder;
    err = aranya_sync_peer_config_builder_init(&builder);
    EXPECT("error initializing sync peer config builder", err);

    // Set duration on the config builder
    AranyaDuration interval = ARANYA_DURATION_MILLISECONDS * 100;
    err = aranya_sync_peer_config_builder_set_interval(&builder, interval);
    EXPECT("error setting duration on config builder", err);

    // Set syncing to happen immediately on the config builder
    err = aranya_sync_peer_config_builder_set_sync_now(&builder);
    EXPECT("error setting `sync_now` on config builder", err);

    // Build the sync config
    struct AranyaSyncPeerConfig cfg;
    err = aranya_sync_peer_config_builder_build(&builder, &cfg);
    EXPECT("error building the sync peer config", err);

    err = aranya_sync_peer_config_builder_cleanup(&builder);
    EXPECT("error running the cleanup routine for the config builder", err);

    // add sync peers.
    printf("adding sync peers\r\n");
    err = add_sync_peers(t, &cfg);
    EXPECT("error adding sync peers", err);

    // Team members are added to the team by first calling
    // `aranya_add_device_to_team`, passing in the submitter's client, the
    // team ID and the public key of the device to be added. In a real world
    // scenario, the keys would be exchanged outside of Aranya using
    // something like `scp`.

    // add membera to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    t->clients.membera.pk,
                                    t->clients.membera.pk_len);
    EXPECT("error adding membera to team", err);

    // add memberb to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    t->clients.memberb.pk,
                                    t->clients.memberb.pk_len);
    EXPECT("error adding memberb to team", err);

    sleep(1);

#if defined(ENABLE_AFC)
    // Once all team members are added and the appropriate roles have been
    // assigned, the team works together to send data using Aranya Fast
    // Channels.
    // First, a label must be created to associate a channel to its
    // permitted devices using the `aranya_create_label` function.

    // operator creates AFC labels and assigns them to team members.
    AranyaLabel label1 = 42;
    err = aranya_create_afc_label(&t->clients.operator.client, &t->id, label);
    EXPECT("error creating afc label", err);

    // Then, the label is assigned to the `Member`s on the team, membera and
    // memberb using `aranya_assign_label`.

    err = aranya_assign_afc_label(&t->clients.operator.client, &t->id,
                                  &t->clients.membera.id, label);
    EXPECT("error assigning afc label to membera", err);

    err = aranya_assign_afc_label(&t->clients.operator.client, &t->id,
                                  &t->clients.memberb.id, label);
    EXPECT("error assigning afc label to memberb", err);

    // Once the label is created and assigned, the devices that will
    // communicate via Aranya Fast Channels must be assigned a network
    // identifier. This is used by Fast Channels to properly translate
    // between network names and devices. Network identifiers are assigned
    // using the `aranya_afc_assign_net_identifiers` function.

    // assign AFC network addresses.
    err = aranya_afc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.membera.id,
                                           afc_addrs[MEMBERA]);
    EXPECT("error assigning afc net name to membera", err);

    err = aranya_afc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error assigning afc net name to memberb", err);
#endif

    // assign AQC network addresses.
    err = aranya_aqc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.membera.id,
                                           afc_addrs[MEMBERA]);
    EXPECT("error assigning aqc net name to membera", err);

    err = aranya_aqc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error assigning aqc net name to memberb", err);

    sleep(1);

    // Queries
    printf("running factdb queries\r\n");
    size_t devices_len      = BUF_LEN;
    AranyaDeviceId *devices = malloc(devices_len * sizeof(AranyaDeviceId));
    err = aranya_query_devices_on_team(&t->clients.operator.client, &t->id,
                                       devices, &devices_len);
    EXPECT("error querying devices on team", err);
    if (devices == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < devices_len; i++) {
        AranyaDeviceId device_result = devices[i];
        size_t device_str_len        = ARANYA_ID_STR_LEN;
        char *device_str             = malloc(ARANYA_ID_STR_LEN);
        aranya_id_to_str(&device_result.id, device_str, &device_str_len);
        printf("device_id: %s at index: %zu/%zu \r\n", device_str, i,
               devices_len);

        AranyaId decodedId;
        err = aranya_id_from_str(device_str, &decodedId);
        EXPECT("error decoding string into an ID", err);

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
    err                          = aranya_query_device_keybundle(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_keybundle, &memberb_keybundle_len);
    EXPECT("error querying memberb key bundle", err);
    printf(
        "%s key bundle len: %zu"
        "\r\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle_len);

#if defined(ENABLE_AFC)
    size_t labels_len   = BUF_LEN;
    AranyaLabel *labels = malloc(labels_len * sizeof(AranyaLabel));
    err                 = aranya_query_device_afc_label_assignments(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id, labels,
        &labels_len);
    EXPECT("error querying labels assigned to device", err);
    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabel label_result = labels[i];
        printf("label: %u at index: %zu/%zu \r\n", label_result, i, labels_len);
    }

    AranyaKeyBundle memberb_keybundle;
    err = aranya_query_device_keybundle(&t->clients.operator.client, &t->id,
                                        &t->clients.memberb.id,
                                        &memberb_keybundle);
    EXPECT("error querying memberb key bundle", err);
    printf(
        "%s key bundle enc_key_len %lu, sign_key_len %lu, ident_key_len "
        "%lu "
        "\r\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle.enc_key_len,
        memberb_keybundle.sign_key_len, memberb_keybundle.ident_key_len);

    size_t memberb_afc_net_identifier_len = BUF_LEN;
    char *memberb_afc_net_identifier      = malloc(BUF_LEN);
    bool afc_net_identifier_exists        = false;
    err                                   = aranya_query_afc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_afc_net_identifier, &memberb_afc_net_identifier_len,
        &afc_net_identifier_exists);
    EXPECT("error querying memberb afc net identifier", err);
    if (!afc_net_identifier_exists) {
        fprintf(stderr, "expected AFC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s afc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_afc_net_identifier);

    err = aranya_afc_remove_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error removing memberb afc net identifier", err);
    printf("%s removed afc net identifier: %s \r\n",
           t->clients_arr[MEMBERB].name, memberb_afc_net_identifier);
    memberb_afc_net_identifier_len = BUF_LEN;
    err                            = aranya_query_afc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_afc_net_identifier, &memberb_afc_net_identifier_len,
        &afc_net_identifier_exists);
    EXPECT("error querying memberb afc net identifier", err);
    if (afc_net_identifier_exists) {
        fprintf(stderr, "did not expect AFC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s afc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_afc_net_identifier);
    free(memberb_afc_net_identifier);
#endif

    size_t memberb_aqc_net_identifier_len = BUF_LEN;
    char *memberb_aqc_net_identifier      = malloc(BUF_LEN);
    bool aqc_net_identifier_exists        = false;
    err                                   = aranya_query_aqc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
        &aqc_net_identifier_exists);
    EXPECT("error querying memberb aqc net identifier", err);
    if (!aqc_net_identifier_exists) {
        fprintf(stderr, "expected AQC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s aqc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);

    err = aranya_aqc_remove_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error removing memberb aqc net identifier", err);
    printf("%s removed aqc net identifier: %s \r\n",
           t->clients_arr[MEMBERB].name, memberb_aqc_net_identifier);
    memberb_aqc_net_identifier_len = BUF_LEN;
    err                            = aranya_query_aqc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
        &aqc_net_identifier_exists);
    EXPECT("error querying memberb aqc net identifier", err);
    if (aqc_net_identifier_exists) {
        fprintf(stderr, "did not expect AQC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s aqc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);
    free(memberb_aqc_net_identifier);

#if defined(ENABLE_AFC)
    bool exists = false;
    err = aranya_query_afc_label_exists(&t->clients.membera.client, &t->id,
                                        &label, &exists);
    EXPECT("error querying label exists", err);
    printf("%s label exists: %s \r\n", t->clients_arr[MEMBERB].name,
           exists ? "true" : "false");

    // Once membera and memberb have been assigned the label and their network
    // identifiers, a Fast Channel can be created. In this example, membera
    // will create the channel using `aranya_afc_create_bidi_channel`. This will
    // create a bidirectional Aranya Fast Channel.

    // create AFC channel between membera and memberb.
    AranyaChannelId chan_id;
    err = aranya_afc_create_bidi_channel(&t->clients.membera.client, &t->id,
                                         afc_addrs[MEMBERB], label, &chan_id);
    EXPECT("error creating afc channel", err);
    AranyaDuration timeout = ARANYA_DURATION_SECONDS * 1;
    // TODO: poll in separate task.
    // poll for ctrl message.
    while (true) {
        AranyaError err1, err2;

        printf("polling for ctrl\r\n");
        err1 = aranya_afc_poll_data(&t->clients.membera.client, timeout);
        err2 = aranya_afc_poll_data(&t->clients.memberb.client, timeout);
        if (err1 == ARANYA_ERROR_TIMEOUT && err2 == ARANYA_ERROR_TIMEOUT) {
            printf("polling timed out\r\n");
            break;
        }
    }

    // Once created, membera can send a message over the channel using
    // `aranya_afc_send_data`.

    // send AFC data.
    printf("sending afc data\r\n");
    const char *send = "hello world";
    err              = aranya_afc_send_data(&t->clients.membera.client, chan_id,
                                            (const uint8_t *)send, (int)strlen(send));
    EXPECT("error sending data", err);
    printf("%s sent afc message: len: %d \r\n", t->clients_arr[MEMBERA].name,
           (int)strlen(send));

    // poll for data message.
    while (true) {
        AranyaError err1, err2;

        printf("polling for data\r\n");
        err1 = aranya_afc_poll_data(&t->clients.membera.client, timeout);
        err2 = aranya_afc_poll_data(&t->clients.memberb.client, timeout);
        if (err1 == ARANYA_ERROR_TIMEOUT && err2 == ARANYA_ERROR_TIMEOUT) {
            printf("polling timed out\r\n");
            break;
        }
    }

    // Memberb uses `aranya_afc_recv_data` to receive the incoming message.

    // receive AFC data.
    AranyaAfcMsgInfo info;
    uint8_t buf[BUF_LEN];
    size_t len = BUF_LEN;
    bool ok    = false;
    err =
        aranya_afc_recv_data(&t->clients.memberb.client, buf, &len, &info, &ok);
    EXPECT("error receiving data", err);
    if (!ok) {
        fprintf(stderr, "`aranya_afc_recv_data` returned `false`\n");
        return ARANYA_ERROR_AFC;
    }
    printf("%s received afc message from %s: len: %zu, label: %d \r\n",
           t->clients_arr[MEMBERB].name, t->clients_arr[MEMBERA].name, len,
           info.label);
#endif

    err = run_aqc_example(t);
    EXPECT("error running aqc example", err);

    return ARANYA_ERROR_SUCCESS;
}

// Run the AQC example.
AranyaError run_aqc_example(Team *t) {
    AranyaError err;

    printf("running AQC demo \r\n");

    // Create label and assign it to members
    printf("creating label \r\n");
    const char *label1_name = "label1";
    AranyaLabelId label1_id;
    err = aranya_create_label(&t->clients.operator.client, &t->id, label1_name,
                              &label1_id);
    EXPECT("error creating label1", err);
    const char *label2_name = "label2";
    AranyaLabelId label2_id;
    err = aranya_create_label(&t->clients.operator.client, &t->id, label2_name,
                              &label2_id);
    EXPECT("error creating label2", err);
    printf("assigning label to members \r\n");
    AranyaChanOp op = ARANYA_CHAN_OP_SEND_RECV;
    err             = aranya_assign_label(&t->clients.operator.client, &t->id,
                                          &t->clients.membera.id, &label1_id, op);
    EXPECT("error assigning label1 to membera", err);
    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, &label1_id, op);
    EXPECT("error assigning label2 to memberb", err);
    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.membera.id, &label2_id, op);
    EXPECT("error assigning label2 to membera", err);
    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, &label2_id, op);
    EXPECT("error assigning label2 to memberb", err);
    sleep(1);

    // Queries
    printf("query if label exists on team \r\n");
    bool exists = false;
    err         = aranya_query_label_exists(&t->clients.membera.client, &t->id,
                                            &label1_id, &exists);
    EXPECT("error querying label exists", err);
    printf("%s label exists: %s \r\n", t->clients_arr[MEMBERB].name,
           exists ? "true" : "false");

    size_t device_str_len = ARANYA_ID_STR_LEN;
    char *device_str      = malloc(ARANYA_ID_STR_LEN);
    aranya_id_to_str(&t->clients.memberb.id.id, device_str, &device_str_len);
    printf("query labels assigned to device: %s\r\n", device_str);
    // `labels_len` is intentionally set to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    size_t labels_len     = 1;
    AranyaLabelId *labels = malloc(labels_len * sizeof(AranyaLabelId));
    err = aranya_query_device_label_assignments(&t->clients.operator.client,
                                                &t->id, &t->clients.memberb.id,
                                                labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\r\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_query_labels(&t->clients.operator.client, &t->id, labels,
                                  &labels_len);
    }
    EXPECT("error querying labels assigned to device", err);
    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabelId label_result = labels[i];
        size_t label_str_len       = ARANYA_ID_STR_LEN;
        char *label_str            = malloc(ARANYA_ID_STR_LEN);
        aranya_id_to_str(&label_result.id, label_str, &label_str_len);
        printf("label_id: %s at index: %zu/%zu \r\n", label_str, i, labels_len);
        free(label_str);
    }
    free(device_str);

    size_t team_str_len = ARANYA_ID_STR_LEN;
    char *team_str      = malloc(ARANYA_ID_STR_LEN);
    aranya_id_to_str(&t->id.id, team_str, &team_str_len);
    printf("query labels on team: %s\r\n", team_str);
    // `labels_len` is intentionally set to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    labels_len = 1;
    err = aranya_query_labels(&t->clients.operator.client, &t->id, labels,
                              &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\r\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_query_labels(&t->clients.operator.client, &t->id, labels,
                                  &labels_len);
    }
    EXPECT("error querying labels on team", err);
    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabelId label_result = labels[i];
        size_t label_str_len       = ARANYA_ID_STR_LEN;
        char *label_str            = malloc(ARANYA_ID_STR_LEN);
        aranya_id_to_str(&label_result.id, label_str, &label_str_len);
        printf("label_id: %s at index: %zu/%zu \r\n", label_str, i, labels_len);
        free(label_str);
    }
    free(labels);
    free(team_str);

    // Create channel using Member A's client
    printf("creating AQC channel \r\n");
    AranyaAqcBidiChannelId chan_id;
    err = aranya_aqc_create_bidi_channel(&t->clients.membera.client, &t->id,
                                         afc_addrs[MEMBERB], &label1_id,
                                         &chan_id);
    EXPECT("error creating aqc bidi channel", err);

    // TODO: send AQC data

    // Revoke/delete label using the Operator
    printf("revoke/delete label \r\n");
    err = aranya_revoke_label(&t->clients.operator.client, &t->id,
                              &t->clients.membera.id, &label1_id);
    EXPECT("error revoking label from membera", err);
    err = aranya_revoke_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, &label1_id);
    EXPECT("error revoking label from memberb", err);
    err = aranya_delete_label(&t->clients.admin.client, &t->id, &label1_id);
    EXPECT("error deleting label", err);

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
